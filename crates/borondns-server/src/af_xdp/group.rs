//! Nonblocking queue progress for a single owner of a configured queue group.
//! No await or cross-queue frame sharing occurs here. The owner retains unsent
//! replies and retry state between turns; no active queue waits for its sibling.
use super::*;
use crate::udp::{UdpServerSettings, prepare_group_udp_batch};
use borondns_core::zone::ZoneStore;
use std::{sync::atomic::AtomicBool, time::Instant};

#[derive(Default)]
struct KickRetry {
    attempts: u64,
    due: Option<Instant>,
    delivery_error: Option<io::Error>,
}

enum KickStep {
    Complete(Option<io::Error>),
    Retry,
    Failed(io::Error),
}

impl KickRetry {
    fn ready(&self, now: Instant) -> bool {
        self.due.is_none_or(|due| now >= due)
    }

    fn observe(&mut self, now: Instant, result: io::Result<()>, lossy: bool) -> KickStep {
        self.attempts += 1;
        match result {
            Ok(()) => {
                let delivery = self.delivery_error.take();
                *self = Self::default();
                return KickStep::Complete(delivery);
            }
            Err(error) => {
                if lossy {
                    if self.delivery_error.is_none() {
                        self.delivery_error = Some(error);
                    }
                } else if !is_transient_ring_kick_error(&error) {
                    // A terminal error for this attempt can still be
                    // retryable to the UDP owner (for example EHOSTUNREACH).
                    // Retain pending ring ownership, but never let a busy
                    // sibling turn this into one failed syscall per round.
                    self.attempts = 0;
                    self.due = Some(now + RING_KICK_RETRY_DELAY);
                    return KickStep::Failed(error);
                } else if self.attempts >= RING_KICK_MAX_RECOVERY_ATTEMPTS {
                    let error = self.delivery_error.take().unwrap_or(error);
                    self.attempts = 0;
                    self.due = Some(now + RING_KICK_RETRY_DELAY);
                    return KickStep::Failed(error);
                }
            }
        }
        self.due = Some(now + RING_KICK_RETRY_DELAY);
        if self.attempts >= RING_KICK_MAX_RECOVERY_ATTEMPTS {
            self.attempts = 0;
            KickStep::Failed(self.delivery_error.take().expect("bounded delivery retry"))
        } else {
            KickStep::Retry
        }
    }
}

pub(crate) struct Queue {
    pub(crate) io: AfXdpPacketIo,
    pub(crate) worker: usize,
    outbound: Vec<UdpOutbound>,
    pending: VecDeque<(usize, Option<Instant>)>,
    admitted: Option<usize>,
    tx_retry: KickRetry,
    fill_retry: KickRetry,
    metrics: RuntimeMetrics,
    backoff: Option<Instant>,
    error_is_send: bool,
}

impl Queue {
    pub(crate) fn new(io: AfXdpPacketIo, worker: usize, metrics: RuntimeMetrics) -> Self {
        let capacity = io.batch_size;
        Self {
            io,
            worker,
            outbound: Vec::with_capacity(capacity),
            pending: VecDeque::with_capacity(capacity),
            admitted: None,
            tx_retry: KickRetry::default(),
            fill_retry: KickRetry::default(),
            metrics,
            backoff: None,
            error_is_send: true,
        }
    }

    fn finish_batch(&mut self) {
        if let Some(admitted) = self.admitted.take() {
            self.metrics.record_udp_send_batch(admitted);
            self.metrics
                .record_af_xdp_worker_send_batch(self.worker, admitted);
        }
    }

    pub(crate) fn drained(&self) -> bool {
        self.admitted.is_none() && self.io.tx_slab.is_empty() && !self.io.tx_kick_pending
    }

    fn kick(&mut self, now: Instant, kind: RingKickKind) -> io::Result<bool> {
        let (pending, retry) = match kind {
            RingKickKind::Tx => (&mut self.io.tx_kick_pending, &mut self.tx_retry),
            RingKickKind::Fill => (&mut self.io.fill_kick_pending, &mut self.fill_retry),
        };
        if !*pending {
            return Ok(true);
        }
        if !retry.ready(now) {
            return Ok(false);
        }
        let result = kick_af_xdp_ring(self.io.socket.get_ref().as_raw_fd(), kind);
        let transient = result.as_ref().is_err_and(is_transient_ring_kick_error);
        let lossy =
            matches!(kind, RingKickKind::Tx) && result.as_ref().is_err_and(is_lossy_tx_kick_error);
        if matches!(kind, RingKickKind::Tx) {
            self.metrics
                .record_af_xdp_tx_kick_observation(result.is_ok(), transient, lossy);
        }
        let outcome = retry.observe(now, result, lossy);
        if matches!(outcome, KickStep::Complete(_)) {
            *pending = false;
        }
        if transient || lossy {
            self.io.drain_completions();
        }
        match outcome {
            KickStep::Complete(None) => Ok(true),
            KickStep::Complete(Some(error)) | KickStep::Failed(error) => Err(error),
            KickStep::Retry => Ok(false),
        }
    }

    fn refill(&mut self, now: Instant) -> io::Result<bool> {
        if !self.kick(now, RingKickKind::Fill)? {
            return Ok(false);
        }
        // Use the existing safe adapter boundary for frame ownership transfer.
        let queued = super::group_fill_once(&mut self.io)?;
        #[cfg(not(feature = "experimental-xdp-conditional-wakeup"))]
        mark_ring_kick_pending(&mut self.io.fill_kick_pending, queued);
        #[cfg(feature = "experimental-xdp-conditional-wakeup")]
        mark_conditional_fill_kick(&mut self.io.fill_kick_pending, queued, || {
            self.io.fill_wakeup_flags.needs_wakeup()
        });
        self.kick(now, RingKickKind::Fill)
    }

    fn publish(&mut self, now: Instant) -> io::Result<bool> {
        let (admitted, result) = group_publish_once(&mut self.io);
        *self
            .admitted
            .as_mut()
            .expect("TX batch owns admission counter") += admitted;
        record_admitted_send_metrics(&mut self.pending, &self.outbound, admitted, &self.metrics);
        if result.is_err() {
            mark_ring_kick_pending(&mut self.io.tx_kick_pending, admitted);
        } else {
            self.io.mark_successful_tx_publication(admitted);
        }
        if self.io.tx_slab.is_empty() {
            debug_assert!(self.pending.is_empty());
            self.finish_batch();
            self.outbound.clear();
        }
        // Admission accounting precedes all recoverable failures and group yields.
        self.io.flush_pending_stats(&self.metrics);
        result?;
        let _ = self.kick(now, RingKickKind::Tx)?;
        Ok(admitted > 0)
    }

    /// At most one nonempty RX dequeue and TX publication per turn. An empty
    /// attempt may recheck under a readiness token before clearing its edge.
    /// A retained RX
    /// tail is consumed before newer packets, including after an invalid storm.
    pub(crate) fn turn(
        &mut self,
        zones: &ZoneStore,
        settings: &UdpServerSettings,
        admission: &AtomicBool,
        now: Instant,
    ) -> io::Result<bool> {
        if self.backoff.is_some_and(|until| now < until) {
            return Ok(false);
        }
        self.backoff = None;
        let result = self.turn_inner(zones, settings, admission, now);
        self.io.flush_pending_stats(&self.metrics);
        result
    }

    fn turn_inner(
        &mut self,
        zones: &ZoneStore,
        settings: &UdpServerSettings,
        admission: &AtomicBool,
        now: Instant,
    ) -> io::Result<bool> {
        self.io.drain_completions();
        self.error_is_send = true;
        if !self.kick(now, RingKickKind::Tx)? {
            return Ok(false);
        }
        if !self.io.tx_slab.is_empty() {
            return self.publish(now);
        }
        if !admission.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(false);
        }
        self.error_is_send = false;
        if !self.refill(now)? {
            return Ok(false);
        }
        self.io.release_unsent_frames();
        self.io.active_inbound = 0;
        self.io.reply_epoch = self
            .io
            .reply_epoch
            .checked_add(1)
            .expect("AF_XDP reply epoch exhausted");
        let mut received = self.io.recv_slab.len();
        if received == 0 {
            received = group_receive_once(&mut self.io)?;
            if received == 0 {
                return Ok(false);
            }
        }
        if ensure_udp_admission_open(admission).is_err() {
            self.io.recycle_received_packets(received);
            return Ok(false);
        }
        self.io.consume_received_packets(received);
        if self.io.active_inbound == 0 {
            return Ok(true);
        }
        prepare_group_udp_batch(
            &mut self.io,
            zones,
            settings,
            self.worker,
            &mut self.outbound,
        )?;
        self.error_is_send = true;
        self.admitted = Some(0);
        let umem = &mut self.io.umem;
        if let Err(error) = prepare_tx_frames(
            &mut self.io.frames,
            &mut self.io.tx_slab,
            &mut self.pending,
            &self.outbound,
            &self.metrics,
            |packet| umem.free_packet(packet),
        ) {
            self.finish_batch();
            self.outbound.clear();
            return Err(error);
        }
        if self.io.tx_slab.is_empty() {
            self.finish_batch();
            self.outbound.clear();
            return Ok(true);
        }
        self.publish(now)
    }

    fn recover(&mut self, error: io::Error) -> io::Result<()> {
        use crate::udp::{UdpIoErrorAction, classify_udp_recv_error, classify_udp_send_error};
        let action = if self.error_is_send {
            self.metrics.record_udp_send_error();
            classify_udp_send_error(&error)
        } else {
            self.metrics.record_udp_receive_error();
            classify_udp_recv_error(&error)
        };
        match action {
            UdpIoErrorAction::Continue => Ok(()),
            UdpIoErrorAction::Backoff(duration) => {
                self.backoff = Some(Instant::now() + duration);
                Ok(())
            }
            UdpIoErrorAction::Fatal => Err(error),
        }
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
        admission: &AtomicBool,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::Poll;
        // Explicit timed kicks preserve errno visibility; polling a pending
        // kick can itself drive TX while discarding the driver's error.
        if self.backoff.is_some() || self.io.tx_kick_pending || self.io.fill_kick_pending {
            return Poll::Pending;
        }
        let result = if !self.io.tx_slab.is_empty() {
            self.io.socket.poll_write_ready(cx)
        } else if admission.load(std::sync::atomic::Ordering::Acquire) {
            self.io.socket.poll_read_ready(cx)
        } else {
            return Poll::Pending;
        };
        result.map(|ready| ready.map(drop))
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        // Only still-local frames may be recycled. Already admitted descriptors
        // remain kernel-owned until CQ/socket teardown, even after a failed kick.
        self.finish_batch();
        self.io.drain_tx_slab_to_umem();
        self.io.release_unsent_frames();
        self.io.flush_pending_stats(&self.metrics);
    }
}

fn round<T>(
    queues: &mut [T],
    mut visit: impl FnMut(&mut T) -> io::Result<bool>,
) -> io::Result<bool> {
    let mut progress = false;
    for queue in queues {
        // Do not short-circuit on a busy or blocked sibling.
        progress |= visit(queue)?;
    }
    Ok(progress)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_until<S>(
    adapters: Vec<AfXdpPacketIo>,
    first_worker: usize,
    worker_count: usize,
    zones: ZoneStore,
    settings: UdpServerSettings,
    admission: Arc<AtomicBool>,
    shutdown: S,
) -> Result<(), crate::RuntimeError>
where
    S: std::future::Future<Output = tokio::time::Instant>,
{
    let mut queues: Vec<_> = adapters
        .into_iter()
        .enumerate()
        .map(|(offset, io)| Queue::new(io, first_worker + offset, settings.metrics.clone()))
        .collect();
    tracing::info!(
        first_worker,
        worker_count,
        queues = queues.len(),
        "AF_XDP queue-group owner ready"
    );
    tokio::pin!(shutdown);
    let mut deadline = None;
    loop {
        if (deadline.is_some() || !admission.load(std::sync::atomic::Ordering::Acquire))
            && queues.iter().all(Queue::drained)
        {
            return Ok(());
        }
        // Shutdown also closes admission before entering the bounded work loop.
        let work = async {
            let mut progress = false;
            for _ in 0..8 {
                let did_work = round(&mut queues, |queue| {
                    match queue.turn(&zones, &settings, &admission, Instant::now()) {
                        Ok(progress) => Ok(progress),
                        Err(error) => queue.recover(error).map(|()| false),
                    }
                })?;
                progress |= did_work;
                if !did_work {
                    break;
                }
            }
            if progress {
                tokio::task::yield_now().await;
            } else {
                // The timer also guarantees isolated pending-kick progress.
                // Socket readiness wakes sparse traffic immediately; idle
                // groups do not spin or block a Tokio worker thread.
                tokio::select! {
                    _ = tokio::time::sleep(RING_KICK_RETRY_DELAY) => {},
                    result = std::future::poll_fn(|cx| {
                        for queue in &mut queues {
                            if let std::task::Poll::Ready(result) = queue.poll_ready(cx, &admission) {
                                return std::task::Poll::Ready(result);
                            }
                        }
                        std::task::Poll::Pending
                    }) => result?,
                }
            }
            Ok::<(), io::Error>(())
        };
        if let Some(until) = deadline {
            match tokio::time::timeout_at(until, work).await {
                Ok(result) => result.map_err(crate::RuntimeError::Udp)?,
                Err(_) => return Ok(()),
            }
        } else {
            tokio::select! {
                biased;
                until = &mut shutdown => {
                    admission.store(false, std::sync::atomic::Ordering::Release);
                    deadline = Some(until);
                },
                result = work => result.map_err(crate::RuntimeError::Udp)?,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn group_readiness_positive_progress_never_rechecks() {
        let (reader, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let reader = AsyncFd::new(reader).unwrap();
        let mut calls = 0;
        assert_eq!(
            group_ring_io(&reader, Interest::READABLE, || {
                calls += 1;
                Ok(64)
            })
            .unwrap(),
            64
        );
        assert_eq!(calls, 1);
    }

    #[tokio::test]
    async fn group_readiness_second_empty_clears_and_rearms() {
        use std::io::{Read, Write};
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let reader = AsyncFd::new(reader).unwrap();
        writer.write_all(&[1]).unwrap();
        drop(reader.readable().await.unwrap());
        reader.get_ref().read_exact(&mut [0]).unwrap();
        let mut calls = 0;
        assert_eq!(
            group_ring_io(&reader, Interest::READABLE, || {
                calls += 1;
                match reader.get_ref().read(&mut [0]) {
                    Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(0),
                    result => result,
                }
            })
            .unwrap(),
            0
        );
        assert_eq!(calls, 2);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reader.readable())
                .await
                .is_err()
        );
        writer.write_all(&[2]).unwrap();
        drop(
            tokio::time::timeout(Duration::from_secs(1), reader.readable())
                .await
                .unwrap()
                .unwrap(),
        );
    }

    #[tokio::test]
    async fn group_readiness_recheck_preserves_real_errors_and_admission() {
        use std::io::Write;
        for errno in [libc::EAGAIN, libc::EINVAL, libc::EHOSTUNREACH] {
            let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
            reader.set_nonblocking(true).unwrap();
            let reader = AsyncFd::new(reader).unwrap();
            writer.write_all(&[1]).unwrap();
            drop(reader.readable().await.unwrap());
            let mut calls = 0;
            let mut remaining = 5;
            let error = group_ring_io(&reader, Interest::READABLE, || {
                calls += 1;
                if calls == 1 {
                    return Ok(0);
                }
                // Model a publication error after transferring a prefix.
                // The helper may not turn the error into a success or replay it.
                remaining -= 2;
                Err(io::Error::from_raw_os_error(errno))
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
            assert_eq!(calls, 2);
            assert_eq!(remaining, 3);
        }
    }

    #[tokio::test]
    async fn group_readiness_rechecks_arrival_after_empty_ring() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let (reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let reader = AsyncFd::new(reader).unwrap();
        writer.write_all(&[1]).unwrap();
        drop(reader.readable().await.unwrap());
        let mut byte = [0];
        reader.get_ref().read_exact(&mut byte).unwrap();
        let mut calls = 0;
        let count = group_ring_io(&reader, Interest::READABLE, || {
            calls += 1;
            match reader.get_ref().read(&mut byte) {
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    // Ring was empty, but a packet arrives before readiness
                    // clearing. Rechecking under the current token must find it.
                    writer.write_all(&[2]).unwrap();
                    Ok(0)
                }
                result => result,
            }
        })
        .unwrap();
        assert_eq!(
            count, 1,
            "arrival after empty observation must be rechecked"
        );
        assert_eq!(calls, 2);
        assert_eq!(byte, [2]);
    }

    #[test]
    fn group_kick_retryable_delivery_errno_obeys_deadline() {
        // These errors end an individual kick attempt, but the outer UDP
        // owner keeps the queue alive. A hot sibling must not cause retries
        // on every round without observing the retry delay.
        for errno in [
            libc::ECONNREFUSED,
            libc::EHOSTUNREACH,
            libc::ENETUNREACH,
            libc::EMSGSIZE,
            libc::EPERM,
        ] {
            let now = Instant::now();
            let mut retry = KickRetry::default();
            for turn in 0..3 {
                let at = now + RING_KICK_RETRY_DELAY * turn;
                assert!(retry.ready(at));
                let KickStep::Failed(error) =
                    retry.observe(at, Err(io::Error::from_raw_os_error(errno)), false)
                else {
                    panic!("error must remain visible to the UDP owner");
                };
                assert_eq!(error.raw_os_error(), Some(errno));
                assert!(matches!(
                    crate::udp::classify_udp_send_error(&error),
                    crate::udp::UdpIoErrorAction::Continue
                ));
                assert!(!retry.ready(at), "errno {errno} retries immediately");
                assert_eq!(retry.attempts, 0);
            }
            assert!(matches!(
                retry.observe(now + RING_KICK_RETRY_DELAY * 3, Ok(()), false),
                KickStep::Complete(None)
            ));
            assert!(retry.ready(now + RING_KICK_RETRY_DELAY * 3));
        }
    }

    #[test]
    fn group_round_services_hot_and_blocked_siblings_without_short_circuit() {
        let mut queues = [0, 1, 2];
        let mut seen = Vec::new();
        for _ in 0..100 {
            assert!(
                round(&mut queues, |queue| {
                    seen.push(*queue);
                    Ok(*queue == 1)
                })
                .unwrap()
            );
        }
        assert_eq!(seen, [0, 1, 2].repeat(100));
        assert!(!round(&mut queues, |_| Ok(false)).unwrap());
    }

    #[test]
    fn group_kick_backoff_and_delivery_error_survive_across_turns() {
        let now = Instant::now();
        let mut retry = KickRetry::default();
        assert!(retry.ready(now));
        assert!(matches!(
            retry.observe(now, Err(io::Error::from(ErrorKind::PermissionDenied)), true),
            KickStep::Retry
        ));
        assert!(!retry.ready(now));
        assert!(retry.ready(now + RING_KICK_RETRY_DELAY));
        assert!(matches!(
            retry.observe(now, Err(io::ErrorKind::WouldBlock.into()), false),
            KickStep::Retry
        ));
        let KickStep::Complete(Some(error)) = retry.observe(now, Ok(()), false) else {
            panic!("delivery error was lost")
        };
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(retry.attempts, 0);
        assert!(retry.ready(now));
    }

    #[test]
    fn group_kick_retry_budget_is_bounded_without_clearing_pending_ownership() {
        for lossy in [false, true] {
            let mut retry = KickRetry::default();
            for attempt in 1..=RING_KICK_MAX_RECOVERY_ATTEMPTS {
                let step = retry.observe(
                    Instant::now(),
                    Err(io::Error::from(if lossy {
                        ErrorKind::PermissionDenied
                    } else {
                        ErrorKind::WouldBlock
                    })),
                    lossy,
                );
                assert_eq!(
                    matches!(step, KickStep::Failed(_)),
                    attempt == RING_KICK_MAX_RECOVERY_ATTEMPTS
                );
            }
            assert_eq!(retry.attempts, 0);
            assert!(retry.due.is_some());
        }
    }
}
