use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use borondns_core::{
    config::{CookieConfig, CookiePolicyConfig},
    dns::{DnsCookieContext, DnsCookiePolicy},
};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::IpPrefix;

pub(crate) fn dns_cookie_secret() -> Result<[u8; 16], getrandom::Error> {
    let mut secret = [0u8; 16];
    getrandom::fill(&mut secret)?;
    Ok(secret)
}

pub(crate) fn dns_cookie_secret_fingerprint(secret: &[u8; 16]) -> String {
    let digest = Sha256::digest(secret);
    lower_hex(&digest[..8])
}

#[derive(Clone)]
pub(crate) struct DnsCookieSecretStore {
    inner: Arc<DnsCookieSecretStoreInner>,
    rotation_interval: Option<Duration>,
}

struct DnsCookieSecretStoreInner {
    state: ArcSwap<DnsCookieSecretState>,
    rotation: Mutex<()>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DnsCookieSecrets {
    pub(crate) current: Zeroizing<[u8; 16]>,
    pub(crate) previous: Option<Zeroizing<[u8; 16]>>,
}

#[derive(Clone)]
struct DnsCookieSecretState {
    current: Zeroizing<[u8; 16]>,
    previous: Option<Zeroizing<[u8; 16]>>,
    generated_at: Instant,
}

impl DnsCookieSecretStore {
    pub(crate) fn new(current: [u8; 16], rotation_interval: Option<Duration>) -> Self {
        Self::new_at(current, None, rotation_interval, Instant::now())
    }

    pub(crate) fn configured(current: [u8; 16], previous: Option<[u8; 16]>) -> Self {
        Self::new_at(current, previous, None, Instant::now())
    }

    pub(crate) fn new_at(
        current: [u8; 16],
        previous: Option<[u8; 16]>,
        rotation_interval: Option<Duration>,
        generated_at: Instant,
    ) -> Self {
        Self {
            inner: Arc::new(DnsCookieSecretStoreInner {
                state: ArcSwap::from_pointee(DnsCookieSecretState {
                    current: Zeroizing::new(current),
                    previous: previous.map(Zeroizing::new),
                    generated_at,
                }),
                rotation: Mutex::new(()),
            }),
            rotation_interval,
        }
    }

    pub(crate) fn current(&self) -> DnsCookieSecrets {
        self.current_with_generator(dns_cookie_secret)
    }

    pub(crate) fn current_with_generator(
        &self,
        generate_secret: impl FnOnce() -> Result<[u8; 16], getrandom::Error>,
    ) -> DnsCookieSecrets {
        // Immutable snapshots keep ordinary readers off a shared reader-count
        // cache line. Publish the current/previous pair and deadline together;
        // the writer mutex only serializes due rotations (including RNG retry).
        {
            let state = self.inner.state.load();
            if !self
                .rotation_interval
                .is_some_and(|interval| state.generated_at.elapsed() >= interval)
            {
                return DnsCookieSecrets {
                    current: state.current.clone(),
                    previous: state.previous.clone(),
                };
            }
        }
        let _rotation = self
            .inner
            .rotation
            .lock()
            .expect("DNS Cookie secret store lock poisoned");
        // Another reader may have rotated while we acquired the writer lock.
        let snapshot = self.inner.state.load();
        let mut state = (**snapshot).clone();
        if self
            .rotation_interval
            .is_some_and(|interval| state.generated_at.elapsed() >= interval)
        {
            match generate_secret() {
                Ok(secret) => {
                    let previous = std::mem::replace(&mut state.current, Zeroizing::new(secret));
                    state.previous = Some(previous);
                    state.generated_at = Instant::now();
                    info!(
                        category = "cookie",
                        secret_fingerprint = %dns_cookie_secret_fingerprint(&state.current),
                        "DNS Cookie server secret rotated"
                    );
                }
                Err(error) => {
                    state.generated_at = Instant::now();
                    warn!(
                        category = "cookie",
                        %error,
                        "DNS Cookie server secret rotation failed; retaining previous secret"
                    );
                }
            }
            self.inner.state.store(Arc::new(state.clone()));
        }
        DnsCookieSecrets {
            current: state.current.clone(),
            previous: state.previous.clone(),
        }
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn ordinary_secret_reads_do_not_wait_for_rotation_lock() {
        let store = DnsCookieSecretStore::configured([3; 16], Some([2; 16]));
        let held = store.inner.rotation.lock().unwrap();
        let reader = store.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let pair = reader.current_with_generator(|| panic!("configured keys do not rotate"));
            tx.send(pair).unwrap();
        });
        let result = rx.recv_timeout(Duration::from_secs(2));
        drop(held);
        worker.join().unwrap();
        let pair = result.expect("a concurrent reader must not need exclusive access");
        assert_eq!(*pair.current, [3; 16]);
        assert_eq!(pair.previous.as_deref(), Some(&[2; 16]));
    }

    #[test]
    fn concurrent_due_readers_rotate_only_once_and_observe_a_coherent_pair() {
        let store = DnsCookieSecretStore::new_at(
            [1; 16],
            None,
            Some(Duration::from_secs(60)),
            Instant::now() - Duration::from_secs(120),
        );
        let barrier = Barrier::new(16);
        let generations = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    barrier.wait();
                    let secrets = store.current_with_generator(|| {
                        generations.fetch_add(1, Ordering::Relaxed);
                        Ok([2; 16])
                    });
                    assert_eq!(*secrets.current, [2; 16]);
                    assert_eq!(secrets.previous.as_deref(), Some(&[1; 16]));
                });
            }
        });
        assert_eq!(generations.load(Ordering::Relaxed), 1);
    }
}

fn current_unix_time_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as u32)
        .unwrap_or_default()
}

#[derive(Clone, Copy)]
pub(crate) struct DnsCookieRuntimeSettings {
    pub(crate) policy: Option<DnsCookiePolicy>,
    pub(crate) past_window_secs: u32,
    pub(crate) future_window_secs: u32,
    pub(crate) secret_rotation_interval: Option<Duration>,
}

#[derive(Clone, Copy)]
pub(crate) struct CookiePrefixMetricSettings {
    pub(crate) ipv4_prefix_len: u8,
    pub(crate) ipv6_prefix_len: u8,
}

pub(crate) fn dns_cookie_settings(config: &CookieConfig) -> DnsCookieRuntimeSettings {
    let policy = match config.policy {
        CookiePolicyConfig::Disabled => None,
        CookiePolicyConfig::Lenient => Some(DnsCookiePolicy::Lenient),
        CookiePolicyConfig::Strict => Some(DnsCookiePolicy::Strict),
    };
    DnsCookieRuntimeSettings {
        policy,
        past_window_secs: config.timestamp_past_tolerance_seconds,
        future_window_secs: config.timestamp_future_tolerance_seconds,
        secret_rotation_interval: (config.secret_rotation_interval_secs > 0)
            .then(|| Duration::from_secs(config.secret_rotation_interval_secs)),
    }
}

pub(crate) fn dns_cookie_context<'a>(
    peer_ip: IpAddr,
    secrets: &'a DnsCookieSecrets,
    settings: DnsCookieRuntimeSettings,
) -> Option<DnsCookieContext<'a>> {
    let mut context = DnsCookieContext::new(peer_ip, &secrets.current, current_unix_time_secs());
    context.previous_server_secret = secrets.previous.as_deref();
    context.policy = settings.policy?;
    context.past_window_secs = settings.past_window_secs;
    context.future_window_secs = settings.future_window_secs;
    Some(context)
}

pub(crate) fn cookie_metric_prefix(
    source: IpAddr,
    settings: CookiePrefixMetricSettings,
) -> IpPrefix {
    let prefix_len = match source {
        IpAddr::V4(_) => settings.ipv4_prefix_len,
        IpAddr::V6(_) => settings.ipv6_prefix_len,
    };
    IpPrefix::new(source, prefix_len)
}
