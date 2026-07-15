use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

const RUNTIME_STATUS_RUNNING: u8 = 0;
const RUNTIME_STATUS_DRAINING: u8 = 1;
const RUNTIME_STATUS_UNHEALTHY: u8 = 2;

#[derive(Clone, Debug)]
pub(super) struct RuntimeStatus {
    value: Arc<AtomicU8>,
    draining_since: Arc<Mutex<Option<Instant>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeStatusValue {
    Running,
    Draining,
    Unhealthy,
}

impl RuntimeStatus {
    pub(super) fn new() -> Self {
        Self {
            value: Arc::new(AtomicU8::new(RUNTIME_STATUS_RUNNING)),
            draining_since: Arc::new(Mutex::new(None)),
        }
    }

    pub(super) fn mark_draining(&self) {
        *self
            .draining_since
            .lock()
            .expect("runtime status lock poisoned") = Some(Instant::now());
        self.value.store(RUNTIME_STATUS_DRAINING, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn mark_unhealthy(&self) {
        self.value
            .store(RUNTIME_STATUS_UNHEALTHY, Ordering::Release);
    }

    pub(super) fn status(&self) -> RuntimeStatusValue {
        match self.value.load(Ordering::Acquire) {
            RUNTIME_STATUS_RUNNING => RuntimeStatusValue::Running,
            RUNTIME_STATUS_DRAINING => RuntimeStatusValue::Draining,
            RUNTIME_STATUS_UNHEALTHY => RuntimeStatusValue::Unhealthy,
            _ => RuntimeStatusValue::Unhealthy,
        }
    }

    pub(super) fn draining_elapsed(&self) -> Option<Duration> {
        self.draining_since
            .lock()
            .expect("runtime status lock poisoned")
            .as_ref()
            .map(Instant::elapsed)
    }
}
