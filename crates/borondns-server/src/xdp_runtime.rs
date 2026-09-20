//! Opt-in queue-local runtimes. Each adapter keeps sole ownership of its rings
//! and UMEM; only the execution/reactor placement differs from the shared runtime.
use rustix::thread::{CpuSet, sched_getaffinity, sched_setaffinity};
use std::{
    io,
    os::fd::AsRawFd,
    sync::mpsc,
    time::{Duration, Instant},
};
use tokio::{
    io::unix::AsyncFd,
    runtime::{Handle, Runtime},
};

const START_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct QueueRuntimes {
    runtimes: Vec<Runtime>,
    queue_count: usize,
    queues_per_group: usize,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn masks(groups: &[Vec<usize>], queues: usize, allowed: &CpuSet) -> io::Result<Vec<CpuSet>> {
    if groups.is_empty() || queues == 0 || !queues.is_multiple_of(groups.len()) {
        return Err(invalid(
            "xdp.worker_cpu_groups requires equal nonempty queue partitions",
        ));
    }
    let mut seen = CpuSet::new();
    groups
        .iter()
        .map(|cpus| {
            if cpus.is_empty() {
                return Err(invalid("xdp.worker_cpu_groups contains an empty CPU set"));
            }
            let mut mask = CpuSet::new();
            for &cpu in cpus {
                if cpu >= CpuSet::MAX_CPU || !allowed.is_set(cpu) || seen.is_set(cpu) {
                    return Err(invalid(
                        "xdp.worker_cpu_groups CPU is unavailable or duplicated",
                    ));
                }
                seen.set(cpu);
                mask.set(cpu);
            }
            Ok(mask)
        })
        .collect()
}

fn pin_worker(mask: &CpuSet) -> io::Result<()> {
    sched_setaffinity(None, mask)?;
    if sched_getaffinity(None)? != *mask {
        return Err(invalid(
            "xdp.worker_cpu_groups effective CPU affinity differs from configured mask",
        ));
    }
    Ok(())
}

impl QueueRuntimes {
    pub(crate) fn new(groups: &[Vec<usize>], queues: usize) -> io::Result<Option<Self>> {
        if groups.is_empty() {
            return Ok(None);
        }
        Self::build(groups, queues, pin_worker).map(Some)
    }

    fn build<F>(groups: &[Vec<usize>], queues: usize, initialize: F) -> io::Result<Self>
    where
        F: Fn(&CpuSet) -> io::Result<()> + Clone + Send + Sync + 'static,
    {
        let masks = masks(groups, queues, &sched_getaffinity(None)?)?;
        let mut owner = Self {
            runtimes: Vec::new(),
            queue_count: queues,
            queues_per_group: queues / groups.len(),
        };
        let deadline = Instant::now() + START_TIMEOUT;
        for (number, mask) in masks.into_iter().enumerate() {
            let (tx, rx) = mpsc::channel();
            let initialize = initialize.clone();
            let workers = groups[number].len();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .max_blocking_threads(1)
                .thread_name(format!("xdp-group-{number}"))
                .on_thread_start(move || {
                    let _ = tx.send(initialize(&mask));
                })
                .enable_all()
                .build()?;
            // Own it before the fallible handshake. Dropping Runtime directly
            // from the startup async task would block/panic on an error path.
            owner.runtimes.push(runtime);
            for _ in 0..workers {
                rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "AF_XDP worker startup timed out")
                    })??;
            }
        }
        tracing::info!(worker_cpu_groups = ?groups, queues, "AF_XDP queue runtimes ready");
        Ok(owner)
    }

    pub(crate) fn handle(&self, worker: usize) -> io::Result<&Handle> {
        if worker >= self.queue_count {
            return Err(invalid(
                "AF_XDP worker is outside configured queue partitions",
            ));
        }
        Ok(self.runtimes[worker / self.queues_per_group].handle())
    }
}

impl Drop for QueueRuntimes {
    fn drop(&mut self) {
        // Normal shutdown drains the server's JoinSet first. On startup failure
        // or cancellation, shutdown_background cancels tasks without blocking an
        // async caller. Serving tasks never use the blocking pool.
        for runtime in self.runtimes.drain(..) {
            runtime.shutdown_background();
        }
    }
}

pub(crate) fn reregister<T: AsRawFd>(socket: AsyncFd<T>) -> io::Result<AsyncFd<T>> {
    AsyncFd::new(socket.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };

    fn one_cpu() -> usize {
        let allowed = sched_getaffinity(None).unwrap();
        (0..CpuSet::MAX_CPU)
            .find(|&cpu| allowed.is_set(cpu))
            .unwrap()
    }

    #[test]
    fn xdp_runtime_masks_validate_bounds_disjointness_and_partition() {
        let mut allowed = CpuSet::new();
        for cpu in [1, 2, 3, 4] {
            allowed.set(cpu);
        }
        assert_eq!(
            masks(&[vec![1, 2], vec![3, 4]], 4, &allowed).unwrap().len(),
            2
        );
        for (groups, queues) in [
            (vec![], 4),
            (vec![vec![]], 4),
            (vec![vec![1, 1]], 4),
            (vec![vec![1], vec![1]], 4),
            (vec![vec![1]], 0),
            (vec![vec![1], vec![2]], 3),
            (vec![vec![0]], 4),
            (vec![vec![CpuSet::MAX_CPU]], 4),
        ] {
            assert!(masks(&groups, queues, &allowed).is_err());
        }
        assert!(QueueRuntimes::new(&[], 0).unwrap().is_none());
    }

    #[test]
    fn xdp_runtime_reactor_migration_and_affinity() {
        let cpu = one_cpu();
        let groups = QueueRuntimes::new(&[vec![cpu]], 2).unwrap().unwrap();
        assert!(groups.handle(2).is_err());
        let old = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (read, mut write) = UnixStream::pair().unwrap();
        read.set_nonblocking(true).unwrap();
        let fd = {
            let _entered = old.enter();
            AsyncFd::new(read).unwrap()
        };
        let (registered_tx, registered_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        groups.handle(1).unwrap().spawn(async move {
            let fd = reregister(fd).unwrap();
            registered_tx.send(()).unwrap();
            let mut byte = [0];
            loop {
                let mut ready = fd.readable().await.unwrap();
                if let Ok(result) = ready.try_io(|fd| fd.get_ref().read(&mut byte)) {
                    assert_eq!(result.unwrap(), 1);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
            done_tx.send((byte[0], sched_getcpu_for_test())).unwrap();
        });
        registered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        drop(old);
        write.write_all(&[42]).unwrap();
        assert_eq!(
            done_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            (42, cpu)
        );
    }

    fn sched_getcpu_for_test() -> usize {
        rustix::thread::sched_getcpu()
    }

    #[test]
    fn xdp_runtime_failed_reregistration_closes_owned_socket() {
        let old = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (read, mut peer) = UnixStream::pair().unwrap();
        read.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let fd = {
            let _entered = old.enter();
            AsyncFd::new(read).unwrap()
        };
        let dead = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handle = dead.handle().clone();
        drop(dead);
        let _entered = handle.enter();
        assert!(reregister(fd).is_err());
        assert_eq!(
            peer.read(&mut [0]).unwrap(),
            0,
            "peer must see EOF, not a leaked descriptor"
        );
    }

    #[test]
    fn xdp_runtime_initialization_failure_unwinds_inside_async_context() {
        let outer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = outer.block_on(async {
            QueueRuntimes::build(&[vec![one_cpu()]], 1, |_| {
                Err(io::ErrorKind::PermissionDenied.into())
            })
            .err()
            .unwrap()
        });
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn xdp_runtime_drop_cancels_tasks_without_blocking_async_caller() {
        struct Dropped(mpsc::Sender<()>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let groups = QueueRuntimes::new(&[vec![one_cpu()]], 1).unwrap().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (dropped_tx, dropped_rx) = mpsc::channel();
        groups.handle(0).unwrap().spawn(async move {
            let _guard = Dropped(dropped_tx);
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let outer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        outer.block_on(async {
            drop(groups);
        });
        dropped_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    }
}
