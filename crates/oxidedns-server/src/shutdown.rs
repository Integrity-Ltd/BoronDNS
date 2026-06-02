use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
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
        Some(Err(error)) => {
            warn!(%error, task_set, "runtime task failed");
            Ok(())
        }
    }
}

pub(crate) async fn abort_task_set(
    tasks: &mut JoinSet<Result<(), RuntimeError>>,
    task_set: &'static str,
) {
    tasks.abort_all();
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
}

pub(crate) async fn drain_task_set(
    tasks: &mut JoinSet<Result<(), RuntimeError>>,
    grace: Duration,
    task_set: &'static str,
) -> bool {
    if tasks.is_empty() {
        return true;
    }

    let drained = tokio::time::timeout(grace, async {
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
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        warn!(%error, task_set, "runtime task returned error after drain timeout");
                    }
                    Err(error) if error.is_cancelled() => {
                        debug!(task_set, "runtime task cancelled after drain timeout");
                    }
                    Err(error) => {
                        warn!(%error, task_set, "runtime task failed after drain timeout");
                    }
                }
            }
            false
        }
    }
}

pub(crate) async fn drain_tcp_connections(
    active_connections: Arc<AtomicUsize>,
    grace: Duration,
    poll_interval: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + grace;
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
