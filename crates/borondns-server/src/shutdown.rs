#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::RuntimeError;

#[cfg(unix)]
pub(crate) async fn wait_for_shutdown_signal() -> Result<&'static str, std::io::Error> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok("SIGINT")
        }
        _ = terminate.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
pub(crate) async fn wait_for_shutdown_signal() -> Result<&'static str, std::io::Error> {
    tokio::signal::ctrl_c().await?;
    Ok("SIGINT")
}

pub(crate) fn handle_runtime_task_result(
    task_set: &'static str,
    result: Option<Result<Result<(), RuntimeError>, tokio::task::JoinError>>,
) -> Result<(), RuntimeError> {
    match result {
        Some(Ok(Ok(()))) | None => Ok(()),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => Err(RuntimeError::RuntimeTask {
            task_set,
            message: error.to_string(),
        }),
    }
}

pub(crate) async fn abort_task_set_until(
    tasks: &mut JoinSet<Result<(), RuntimeError>>,
    deadline: tokio::time::Instant,
    task_set: &'static str,
) -> bool {
    tasks.abort_all();
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let reaped = tokio::time::timeout(remaining, async {
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    warn!(%error, task_set, "runtime task returned error during shutdown");
                }
                Err(error) if error.is_cancelled() => {
                    debug!(task_set, "runtime task cancelled during shutdown");
                }
                Err(error) => {
                    warn!(%error, task_set, "runtime task failed during shutdown");
                }
            }
        }
    })
    .await;
    if reaped.is_err() {
        warn!(
            task_set,
            "shutdown deadline elapsed while reaping aborted tasks"
        );
        return false;
    }
    true
}

#[cfg(test)]
pub(crate) async fn drain_task_set(
    tasks: &mut JoinSet<Result<(), RuntimeError>>,
    grace: Duration,
    task_set: &'static str,
) -> bool {
    let now = tokio::time::Instant::now();
    let deadline = now.checked_add(grace).unwrap_or(now);
    drain_task_set_until(tasks, deadline, task_set).await
}

pub(crate) async fn drain_task_set_until(
    tasks: &mut JoinSet<Result<(), RuntimeError>>,
    deadline: tokio::time::Instant,
    task_set: &'static str,
) -> bool {
    if tasks.is_empty() {
        return true;
    }

    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let drained = tokio::time::timeout(remaining, async {
        let mut clean = true;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    clean = false;
                    warn!(%error, task_set, "runtime task returned error while draining");
                }
                Err(error) => {
                    clean = false;
                    warn!(%error, task_set, "runtime task failed while draining");
                }
            }
        }
        clean
    })
    .await;

    match drained {
        Ok(clean) => clean,
        Err(_) => {
            tasks.abort_all();
            false
        }
    }
}

#[cfg(test)]
pub(crate) async fn drain_tcp_connections(
    active_connections: Arc<AtomicUsize>,
    grace: Duration,
    poll_interval: Duration,
) -> bool {
    let now = tokio::time::Instant::now();
    let deadline = now.checked_add(grace).unwrap_or(now);
    loop {
        if active_connections.load(Ordering::Acquire) == 0 {
            return true;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::time::sleep(poll_interval.min(remaining)).await;
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_reap_does_not_wait_past_deadline_for_noncooperative_task() {
        let mut tasks = JoinSet::new();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let _ = started_tx.send(());
            tokio::task::block_in_place(|| std::thread::sleep(Duration::from_secs(1)));
            Ok(())
        });
        started_rx.await.expect("blocking task started");

        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_millis(20);
        assert!(!abort_task_set_until(&mut tasks, deadline, "test").await);
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
