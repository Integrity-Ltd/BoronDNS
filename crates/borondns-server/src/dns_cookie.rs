use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

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
    inner: Arc<Mutex<DnsCookieSecretState>>,
    rotation_interval: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DnsCookieSecrets {
    pub(crate) current: Zeroizing<[u8; 16]>,
    pub(crate) previous: Option<Zeroizing<[u8; 16]>>,
}

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
            inner: Arc::new(Mutex::new(DnsCookieSecretState {
                current: Zeroizing::new(current),
                previous: previous.map(Zeroizing::new),
                generated_at,
            })),
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
        let mut state = self
            .inner
            .lock()
            .expect("DNS Cookie secret store lock poisoned");
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
