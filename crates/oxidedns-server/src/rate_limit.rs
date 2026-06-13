use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use oxidedns_core::{
    config::RrlConfig,
    dns::{DomainName, Header, Opcode, RecordType},
    tsig::TsigError,
};
use tracing::{info, warn};

use crate::{
    RuntimeError, RuntimeMetrics, RuntimeMetricsSnapshot, response_rcode, skip_response_record,
};

pub(crate) async fn serve_rrl_summary_logs(
    rrl: RrlLimiter,
    metrics: RuntimeMetrics,
    interval: Duration,
) -> Result<(), RuntimeError> {
    let mut previous = metrics.snapshot();
    loop {
        tokio::time::sleep(interval).await;
        let current = metrics.snapshot();
        let summary = RrlSummary::from_snapshots(previous, current, rrl.rate_limited_key_count());
        log_rrl_summary(summary, interval);
        previous = current;
    }
}

pub(crate) async fn serve_notify_log_summaries(
    limiter: NotifyLogLimiter,
    interval: Duration,
) -> Result<(), RuntimeError> {
    loop {
        tokio::time::sleep(interval).await;
        let summary = limiter.take_summary();
        if summary.total_suppressed > 0 {
            log_notify_log_summary(summary, interval);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RrlSummary {
    pub(crate) dropped_responses: u64,
    pub(crate) truncated_responses: u64,
    pub(crate) rate_limited_keys: u64,
    pub(crate) total_dropped_responses: u64,
    pub(crate) total_truncated_responses: u64,
}

impl RrlSummary {
    pub(crate) fn from_snapshots(
        previous: RuntimeMetricsSnapshot,
        current: RuntimeMetricsSnapshot,
        rate_limited_keys: u64,
    ) -> Self {
        Self {
            dropped_responses: current.rrl_dropped.saturating_sub(previous.rrl_dropped),
            truncated_responses: current.rrl_truncated.saturating_sub(previous.rrl_truncated),
            rate_limited_keys,
            total_dropped_responses: current.rrl_dropped,
            total_truncated_responses: current.rrl_truncated,
        }
    }
}

pub(crate) fn log_rrl_summary(summary: RrlSummary, interval: Duration) {
    info!(
        category = "rrl",
        event = "rrl_periodic_summary",
        interval_secs = interval.as_secs(),
        dropped_responses = summary.dropped_responses,
        truncated_responses = summary.truncated_responses,
        rate_limited_keys = summary.rate_limited_keys,
        total_dropped_responses = summary.total_dropped_responses,
        total_truncated_responses = summary.total_truncated_responses,
        "RRL periodic summary"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotifyLogSummary {
    pub(crate) suppressed_unauthorized: u64,
    pub(crate) suppressed_tsig_failures: u64,
    pub(crate) distinct_source_prefixes: u64,
    pub(crate) total_suppressed: u64,
}

pub(crate) fn log_notify_log_summary(summary: NotifyLogSummary, interval: Duration) {
    info!(
        category = "notify",
        event = "notify_log_rate_limit_summary",
        interval_secs = interval.as_secs(),
        suppressed_unauthorized = summary.suppressed_unauthorized,
        suppressed_tsig_failures = summary.suppressed_tsig_failures,
        distinct_source_prefixes = summary.distinct_source_prefixes,
        total_suppressed = summary.total_suppressed,
        "NOTIFY log rate-limit summary"
    );
}

#[derive(Clone, Debug)]
pub(crate) struct RrlLimiter {
    enabled: bool,
    inner: Arc<Mutex<RrlState>>,
    metrics: RuntimeMetrics,
}

impl RrlLimiter {
    pub(crate) fn from_config(config: &RrlConfig, metrics: RuntimeMetrics) -> Self {
        Self {
            enabled: config.enabled,
            inner: Arc::new(Mutex::new(RrlState::from_config(config))),
            metrics,
        }
    }

    pub(crate) fn apply(&self, source: IpAddr, response: Vec<u8>) -> RrlDecision {
        if !self.enabled {
            return RrlDecision::Send(response);
        }
        let Some(category) = response_category(&response) else {
            return RrlDecision::Send(response);
        };
        let mut state = self.inner.lock().expect("RRL state lock poisoned");
        state.apply(source, category, response, &self.metrics)
    }

    pub(crate) fn rate_limited_key_count(&self) -> u64 {
        self.inner
            .lock()
            .expect("RRL state lock poisoned")
            .rate_limited_key_count()
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }
}

#[derive(Debug)]
pub(crate) enum RrlDecision {
    Send(Vec<u8>),
    Drop,
}

#[derive(Debug)]
struct RrlState {
    enabled: bool,
    ipv4_prefix_len: u8,
    ipv6_prefix_len: u8,
    rates: RrlRates,
    slip: u32,
    max_keys: usize,
    allowlist: Vec<IpPrefix>,
    buckets: HashMap<RrlKey, RrlBucket>,
    next_order: u128,
}

impl RrlState {
    fn from_config(config: &RrlConfig) -> Self {
        Self {
            enabled: config.enabled,
            ipv4_prefix_len: config.ipv4_prefix_len,
            ipv6_prefix_len: config.ipv6_prefix_len,
            rates: RrlRates {
                positive: config.positive_per_second,
                nxdomain: config.nxdomain_per_second,
                nodata: config.nodata_per_second,
                referral: config.referral_per_second,
                error: config.error_per_second,
            },
            slip: config.slip,
            max_keys: config.max_keys,
            allowlist: config
                .allowlist
                .iter()
                .map(|prefix| IpPrefix::parse(prefix).expect("validated RRL allowlist prefix"))
                .collect(),
            buckets: HashMap::new(),
            next_order: 0,
        }
    }

    fn apply(
        &mut self,
        source: IpAddr,
        category: RrlCategory,
        response: Vec<u8>,
        metrics: &RuntimeMetrics,
    ) -> RrlDecision {
        if !self.enabled || self.allowlist.iter().any(|prefix| prefix.contains(source)) {
            return RrlDecision::Send(response);
        }

        metrics.record_rrl_subject();
        let key = RrlKey::new(source, self.prefix_len(source), category);
        let rate = self.rates.for_category(category);
        if !self.buckets.contains_key(&key) {
            self.evict_one_if_needed(metrics);
            let order = self.allocate_order();
            self.buckets.insert(key, RrlBucket::new(rate, order));
            metrics.set_rrl_tracked_keys(self.tracked_keys());
        }

        let order = self.allocate_order();
        let Some(bucket) = self.buckets.get_mut(&key) else {
            return RrlDecision::Send(response);
        };
        bucket.touch(order);
        if bucket.take_token(rate) {
            return RrlDecision::Send(response);
        }

        if bucket.limited_count == 0 {
            warn!(
                ?key,
                rate,
                slip = self.slip,
                "RRL accounting key entered rate-limited state"
            );
        }
        bucket.limited_count = bucket.limited_count.saturating_add(1);
        if self.slip > 0 && bucket.limited_count.is_multiple_of(u64::from(self.slip)) {
            metrics.record_rrl_truncated();
            RrlDecision::Send(rrl_truncated_response(&response))
        } else {
            metrics.record_rrl_dropped();
            RrlDecision::Drop
        }
    }

    fn prefix_len(&self, source: IpAddr) -> u8 {
        match source {
            IpAddr::V4(_) => self.ipv4_prefix_len,
            IpAddr::V6(_) => self.ipv6_prefix_len,
        }
    }

    fn evict_one_if_needed(&mut self, metrics: &RuntimeMetrics) {
        if self.buckets.len() < self.max_keys {
            return;
        }
        let Some(oldest_key) = self
            .buckets
            .iter()
            .min_by_key(|(_, bucket)| bucket.order)
            .map(|(key, _)| *key)
        else {
            return;
        };
        if self.buckets.remove(&oldest_key).is_some() {
            metrics.record_rrl_key_evicted();
            metrics.set_rrl_tracked_keys(self.tracked_keys());
        }
    }

    fn allocate_order(&mut self) -> u128 {
        let order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        order
    }

    fn tracked_keys(&self) -> u64 {
        self.buckets.len() as u64
    }

    fn rate_limited_key_count(&self) -> u64 {
        let now = Instant::now();
        self.buckets
            .iter()
            .filter(|(key, bucket)| {
                bucket.limited_count > 0
                    && !bucket.would_have_token(self.rates.for_category(key.category), now)
            })
            .count() as u64
    }
}

#[derive(Debug, Clone, Copy)]
struct RrlRates {
    positive: u32,
    nxdomain: u32,
    nodata: u32,
    referral: u32,
    error: u32,
}

impl RrlRates {
    fn for_category(self, category: RrlCategory) -> u32 {
        match category {
            RrlCategory::Positive => self.positive,
            RrlCategory::NxDomain => self.nxdomain,
            RrlCategory::NoData => self.nodata,
            RrlCategory::Referral => self.referral,
            RrlCategory::Error => self.error,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RrlBucket {
    tokens: f64,
    last_refill: Instant,
    limited_count: u64,
    order: u128,
}

impl RrlBucket {
    fn new(rate: u32, order: u128) -> Self {
        Self {
            tokens: f64::from(rate),
            last_refill: Instant::now(),
            limited_count: 0,
            order,
        }
    }

    fn touch(&mut self, order: u128) {
        self.order = order;
    }

    fn take_token(&mut self, rate: u32) -> bool {
        if rate > 0 {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            self.tokens = (self.tokens + elapsed * f64::from(rate)).min(f64::from(rate));
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn would_have_token(self, rate: u32, now: Instant) -> bool {
        let tokens = if rate > 0 {
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            (self.tokens + elapsed * f64::from(rate)).min(f64::from(rate))
        } else {
            self.tokens
        };
        tokens >= 1.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RrlKey {
    prefix: IpPrefix,
    category: RrlCategory,
}

impl RrlKey {
    fn new(source: IpAddr, prefix_len: u8, category: RrlCategory) -> Self {
        Self {
            prefix: IpPrefix::new(source, prefix_len),
            category,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RrlCategory {
    Positive,
    NxDomain,
    NoData,
    Referral,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IpPrefix {
    V4 { network: u32, len: u8 },
    V6 { network: u128, len: u8 },
}

impl IpPrefix {
    fn parse(value: &str) -> Option<Self> {
        let (addr, len) = match value.split_once('/') {
            Some((addr, len)) => {
                let addr = addr.parse::<IpAddr>().ok()?;
                let len = len.parse::<u8>().ok()?;
                (addr, len)
            }
            None => {
                let addr = value.parse::<IpAddr>().ok()?;
                let len = match addr {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                (addr, len)
            }
        };
        Some(Self::new(addr, len))
    }

    pub(crate) fn new(addr: IpAddr, len: u8) -> Self {
        match addr {
            IpAddr::V4(addr) => {
                let len = len.min(32);
                let network = u32::from(addr) & prefix_mask_v4(len);
                Self::V4 { network, len }
            }
            IpAddr::V6(addr) => {
                let len = len.min(128);
                let network = u128::from(addr) & prefix_mask_v6(len);
                Self::V6 { network, len }
            }
        }
    }

    fn contains(self, addr: IpAddr) -> bool {
        match (self, addr) {
            (Self::V4 { network, len }, IpAddr::V4(addr)) => {
                u32::from(addr) & prefix_mask_v4(len) == network
            }
            (Self::V6 { network, len }, IpAddr::V6(addr)) => {
                u128::from(addr) & prefix_mask_v6(len) == network
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 { network, len } => {
                write!(formatter, "{}/{}", std::net::Ipv4Addr::from(*network), len)
            }
            Self::V6 { network, len } => {
                write!(formatter, "{}/{}", std::net::Ipv6Addr::from(*network), len)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NotifyLogLimiter {
    inner: Arc<Mutex<NotifyLogState>>,
}

impl NotifyLogLimiter {
    pub(crate) fn new(window: Duration, max_keys: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NotifyLogState::new(window, max_keys))),
        }
    }

    pub(crate) fn log_unauthorized(&self, source: IpAddr, zone: &DomainName) {
        self.log_event(NotifyLogCategory::Unauthorized, source, zone, None);
    }

    pub(crate) fn log_tsig_failure(&self, source: IpAddr, zone: &DomainName, error: &TsigError) {
        self.log_event(
            NotifyLogCategory::TsigFailure,
            source,
            zone,
            Some(error.to_string()),
        );
    }

    fn log_event(
        &self,
        category: NotifyLogCategory,
        source: IpAddr,
        zone: &DomainName,
        error: Option<String>,
    ) {
        let zone_key = zone.canonical_key();
        let decision = self
            .inner
            .lock()
            .expect("NOTIFY log limiter lock poisoned")
            .observe(category, source, zone_key);
        if decision == NotifyLogDecision::Suppress {
            return;
        }
        match category {
            NotifyLogCategory::Unauthorized => {
                warn!(
                    category = "notify",
                    event = "notify_unauthorized_discard",
                    peer_ip = %source,
                    source_prefix = %notify_log_prefix(source),
                    zone = %zone,
                    "unauthorized NOTIFY discarded"
                );
            }
            NotifyLogCategory::TsigFailure => {
                warn!(
                    category = "notify",
                    event = "notify_tsig_failure",
                    peer_ip = %source,
                    source_prefix = %notify_log_prefix(source),
                    zone = %zone,
                    error = %error.as_deref().unwrap_or("TSIG verification failed"),
                    "rejected NOTIFY with invalid TSIG"
                );
            }
        }
    }

    pub(crate) fn take_summary(&self) -> NotifyLogSummary {
        self.inner
            .lock()
            .expect("NOTIFY log limiter lock poisoned")
            .take_summary()
    }
}

#[derive(Debug)]
struct NotifyLogState {
    window: Duration,
    max_keys: usize,
    keys: HashMap<NotifyLogKey, Instant>,
    suppressed_unauthorized: u64,
    suppressed_tsig_failures: u64,
    suppressed_prefixes: HashSet<IpPrefix>,
}

impl NotifyLogState {
    fn new(window: Duration, max_keys: usize) -> Self {
        Self {
            window,
            max_keys: max_keys.max(1),
            keys: HashMap::new(),
            suppressed_unauthorized: 0,
            suppressed_tsig_failures: 0,
            suppressed_prefixes: HashSet::new(),
        }
    }

    fn observe(
        &mut self,
        category: NotifyLogCategory,
        source: IpAddr,
        zone: String,
    ) -> NotifyLogDecision {
        let now = Instant::now();
        self.expire_old_keys(now);
        let prefix = notify_log_prefix(source);
        let key = NotifyLogKey {
            prefix,
            zone,
            category,
        };
        let can_insert = self.keys.len() < self.max_keys;
        match self.keys.entry(key) {
            std::collections::hash_map::Entry::Occupied(_) => {}
            std::collections::hash_map::Entry::Vacant(entry) => {
                if can_insert {
                    entry.insert(now);
                    return NotifyLogDecision::Emit;
                }
            }
        }

        self.record_suppressed(category, prefix);
        NotifyLogDecision::Suppress
    }

    fn record_suppressed(&mut self, category: NotifyLogCategory, prefix: IpPrefix) {
        match category {
            NotifyLogCategory::Unauthorized => {
                self.suppressed_unauthorized = self.suppressed_unauthorized.saturating_add(1);
            }
            NotifyLogCategory::TsigFailure => {
                self.suppressed_tsig_failures = self.suppressed_tsig_failures.saturating_add(1);
            }
        }
        if self.suppressed_prefixes.len() < self.max_keys {
            self.suppressed_prefixes.insert(prefix);
        }
    }

    fn expire_old_keys(&mut self, now: Instant) {
        let window = self.window;
        self.keys
            .retain(|_, first_seen| now.duration_since(*first_seen) < window);
    }

    fn take_summary(&mut self) -> NotifyLogSummary {
        let summary = NotifyLogSummary {
            suppressed_unauthorized: self.suppressed_unauthorized,
            suppressed_tsig_failures: self.suppressed_tsig_failures,
            distinct_source_prefixes: self.suppressed_prefixes.len() as u64,
            total_suppressed: self
                .suppressed_unauthorized
                .saturating_add(self.suppressed_tsig_failures),
        };
        self.suppressed_unauthorized = 0;
        self.suppressed_tsig_failures = 0;
        self.suppressed_prefixes.clear();
        summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NotifyLogKey {
    prefix: IpPrefix,
    zone: String,
    category: NotifyLogCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NotifyLogCategory {
    Unauthorized,
    TsigFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyLogDecision {
    Emit,
    Suppress,
}

fn notify_log_prefix(source: IpAddr) -> IpPrefix {
    let prefix_len = match source {
        IpAddr::V4(_) => 24,
        IpAddr::V6(_) => 56,
    };
    IpPrefix::new(source, prefix_len)
}

fn prefix_mask_v4(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

fn prefix_mask_v6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    }
}

pub(crate) fn response_category(response: &[u8]) -> Option<RrlCategory> {
    let header = Header::parse(response).ok()?;
    if !header.is_response() || header.opcode() != Some(Opcode::Query) {
        return None;
    }
    let rcode = response_rcode(response, &header);
    match rcode {
        0 if header.ancount > 0 => Some(RrlCategory::Positive),
        0 if response_has_authority_ns(response, &header) => Some(RrlCategory::Referral),
        0 => Some(RrlCategory::NoData),
        3 => Some(RrlCategory::NxDomain),
        _ => Some(RrlCategory::Error),
    }
}

fn response_has_authority_ns(response: &[u8], header: &Header) -> bool {
    let Some(mut offset) = response_question_end(response, header) else {
        return false;
    };
    for _ in 0..header.ancount {
        let Some(next) = skip_response_record(response, offset) else {
            return false;
        };
        offset = next;
    }
    for _ in 0..header.nscount {
        let Some((rr_type, next)) = response_record_type(response, offset) else {
            return false;
        };
        if rr_type == RecordType::Ns as u16 {
            return true;
        }
        offset = next;
    }
    false
}

pub(crate) fn response_question_end(response: &[u8], header: &Header) -> Option<usize> {
    let mut offset = 12;
    for _ in 0..header.qdcount {
        let (_, consumed) = DomainName::parse(response, offset).ok()?;
        offset = offset.checked_add(consumed)?.checked_add(4)?;
        if offset > response.len() {
            return None;
        }
    }
    Some(offset)
}

pub(crate) fn response_record_type(response: &[u8], offset: usize) -> Option<(u16, usize)> {
    let (_, consumed) = DomainName::parse(response, offset).ok()?;
    let header_offset = offset.checked_add(consumed)?;
    if header_offset + 10 > response.len() {
        return None;
    }
    let rr_type = u16::from_be_bytes([response[header_offset], response[header_offset + 1]]);
    let rdlength =
        u16::from_be_bytes([response[header_offset + 8], response[header_offset + 9]]) as usize;
    let next = header_offset.checked_add(10)?.checked_add(rdlength)?;
    (next <= response.len()).then_some((rr_type, next))
}

pub(crate) fn rrl_truncated_response(response: &[u8]) -> Vec<u8> {
    let Ok(header) = Header::parse(response) else {
        return response.to_vec();
    };
    let question_end = response_question_end(response, &header).unwrap_or(12);
    let opt = response_opt_record(response, &header);
    let mut out = Vec::with_capacity(question_end + opt.map_or(0, |opt| opt.len()));
    out.extend_from_slice(&response[..2]);
    out.extend_from_slice(&(header.flags | 0x0200).to_be_bytes());
    out.extend_from_slice(&header.qdcount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(u16::from(opt.is_some())).to_be_bytes());
    if question_end > 12 && question_end <= response.len() {
        out.extend_from_slice(&response[12..question_end]);
    }
    if let Some(opt) = opt {
        out.extend_from_slice(opt);
    }
    out
}

pub(crate) fn response_opt_record<'a>(response: &'a [u8], header: &Header) -> Option<&'a [u8]> {
    let mut offset = response_question_end(response, header)?;
    for count in [header.ancount, header.nscount] {
        for _ in 0..count {
            offset = skip_response_record(response, offset)?;
        }
    }
    for _ in 0..header.arcount {
        let start = offset;
        let (rr_type, next) = response_record_type(response, offset)?;
        if rr_type == RecordType::Opt as u16 {
            return Some(&response[start..next]);
        }
        offset = next;
    }
    None
}
