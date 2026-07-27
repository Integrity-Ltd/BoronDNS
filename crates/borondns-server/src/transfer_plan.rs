use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::watch;

use borondns_core::{
    ServerConfig,
    catalog::{CatalogMemberTransfer, CatalogMemberTransport},
    config::{
        CatalogZoneConfig, TransferPrimaryConfig, TransferTransportConfig, ZoneConfig,
        is_legacy_private_primary,
    },
    dns::DomainName,
};

use crate::{RuntimeError, transfer::TransferIngestBudget};

#[derive(Debug, Clone)]
pub(crate) struct ZoneTransferPlan {
    pub(crate) origin: DomainName,
    pub(crate) qclass: u16,
    pub(crate) primaries: Vec<TransferPrimaryConfig>,
    pub(crate) tsig_key_name: Option<DomainName>,
    pub(crate) tsig_fudge_seconds: u16,
    pub(crate) max_transfer_ingest_bytes: u64,
    pub(crate) max_transfer_ingest_messages: u64,
    pub(crate) transfer_sources: Vec<SocketAddr>,
    generation: u64,
    cancellation: watch::Sender<bool>,
}

impl ZoneTransferPlan {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) async fn cancelled(&self) {
        let mut cancellation = self.cancellation.subscribe();
        loop {
            if *cancellation.borrow_and_update() {
                return;
            }
            if cancellation.changed().await.is_err() {
                return;
            }
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn is_cancelled(&self) -> bool {
        *self.cancellation.borrow()
    }

    fn cancel(&self) {
        self.cancellation.send_replace(true);
    }

    pub(crate) fn transfer_source_for(&self, primary: SocketAddr) -> Option<SocketAddr> {
        self.transfer_sources
            .iter()
            .copied()
            .find(|source| source.is_ipv4() == primary.is_ipv4())
    }

    pub(crate) fn for_member_origin(&self, origin: DomainName) -> Self {
        Self {
            origin,
            qclass: self.qclass,
            primaries: self.primaries.clone(),
            tsig_key_name: self.tsig_key_name.clone(),
            tsig_fudge_seconds: self.tsig_fudge_seconds,
            max_transfer_ingest_bytes: self.max_transfer_ingest_bytes,
            max_transfer_ingest_messages: self.max_transfer_ingest_messages,
            transfer_sources: self.transfer_sources.clone(),
            generation: 0,
            cancellation: fresh_cancellation(),
        }
    }

    fn same_transfer_shape(&self, other: &Self) -> bool {
        self.origin == other.origin
            && self.qclass == other.qclass
            && self.primaries == other.primaries
            && self.tsig_key_name == other.tsig_key_name
            && self.tsig_fudge_seconds == other.tsig_fudge_seconds
            && self.max_transfer_ingest_bytes == other.max_transfer_ingest_bytes
            && self.max_transfer_ingest_messages == other.max_transfer_ingest_messages
            && self.transfer_sources == other.transfer_sources
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransferPlan {
    zones_by_key: Arc<Mutex<HashMap<String, ZoneTransferPlan>>>,
    catalog_member_templates_by_key: Arc<HashMap<String, ZoneTransferPlan>>,
    next_generation: Arc<AtomicU64>,
    transfer_ingest_budget: TransferIngestBudget,
}

impl TransferPlan {
    pub(crate) fn from_config(config: &ServerConfig) -> Result<Self, RuntimeError> {
        Self::from_config_with_primary_start(config, random_primary_start_index)
    }

    pub(crate) fn from_config_with_primary_start(
        config: &ServerConfig,
        primary_start_index: impl Fn(usize) -> Result<usize, getrandom::Error>,
    ) -> Result<Self, RuntimeError> {
        let next_generation = Arc::new(AtomicU64::new(1));
        let mut zones_by_key = HashMap::new();
        let mut catalog_member_templates_by_key = HashMap::new();
        for zone in &config.zones {
            let mut plan = transfer_plan_from_zone_config(
                zone,
                config.tsig.fudge_seconds,
                config.limits.max_transfer_ingest_bytes,
                config.limits.max_transfer_ingest_messages,
                &config.interfaces.transfer,
                &primary_start_index,
            )?;
            assign_generation(&mut plan, &next_generation);
            zones_by_key.insert(plan.origin.canonical_key(), plan);
        }
        for catalog_zone in &config.catalog_zones {
            let mut plan = transfer_plan_from_catalog_zone_config(
                catalog_zone,
                config.tsig.fudge_seconds,
                config.limits.max_transfer_ingest_bytes,
                config.limits.max_transfer_ingest_messages,
                &config.interfaces.transfer,
                &primary_start_index,
            )?;
            assign_generation(&mut plan, &next_generation);
            let catalog_key = plan.origin.canonical_key();
            let member_template = transfer_plan_from_catalog_member_config(
                catalog_zone,
                config.tsig.fudge_seconds,
                config.limits.max_transfer_ingest_bytes,
                config.limits.max_transfer_ingest_messages,
                &config.interfaces.transfer,
                &primary_start_index,
            )?;
            zones_by_key.insert(catalog_key.clone(), plan);
            catalog_member_templates_by_key.insert(catalog_key, member_template);
        }

        Ok(Self {
            zones_by_key: Arc::new(Mutex::new(zones_by_key)),
            catalog_member_templates_by_key: Arc::new(catalog_member_templates_by_key),
            next_generation,
            // `max_transfer_ingest_bytes` is a per-session protocol limit. The
            // shared guard therefore reserves enough for every session admitted
            // by the transfer semaphore instead of making concurrent valid
            // sessions compete for one session's allowance.
            transfer_ingest_budget: TransferIngestBudget::for_concurrent_sessions(
                config.limits.max_transfer_ingest_bytes,
                config.limits.max_concurrent_transfers,
            ),
        })
    }

    pub(crate) fn ingest_budget(&self) -> TransferIngestBudget {
        self.transfer_ingest_budget.clone()
    }

    pub(crate) fn get(&self, origin: &DomainName) -> Option<ZoneTransferPlan> {
        self.zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .get(&origin.canonical_key())
            .cloned()
    }

    pub(crate) fn if_current_plan<R>(
        &self,
        plan: &ZoneTransferPlan,
        action: impl FnOnce() -> R,
    ) -> Option<R> {
        let zones_by_key = self
            .zones_by_key
            .lock()
            .expect("transfer plan lock poisoned");
        if zones_by_key
            .get(&plan.origin.canonical_key())
            .is_some_and(|current| current.generation == plan.generation)
        {
            Some(action())
        } else {
            None
        }
    }

    pub(crate) fn is_current_plan(&self, plan: &ZoneTransferPlan) -> bool {
        self.zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .get(&plan.origin.canonical_key())
            .is_some_and(|current| current.generation == plan.generation)
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn insert(&self, mut plan: ZoneTransferPlan) {
        assign_generation(&mut plan, &self.next_generation);
        if let Some(previous) = self
            .zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .insert(plan.origin.canonical_key(), plan)
        {
            previous.cancel();
        }
    }

    /// Inserts `plan`, preserving the generation when its transfer shape is unchanged.
    ///
    /// Returns `true` when the effective transfer shape changed. Callers use this
    /// to schedule a prompt refresh after catalog ownership or override changes.
    pub(crate) fn insert_preserving_generation_if_unchanged(
        &self,
        mut plan: ZoneTransferPlan,
    ) -> bool {
        let mut zones_by_key = self
            .zones_by_key
            .lock()
            .expect("transfer plan lock poisoned");
        let key = plan.origin.canonical_key();
        if let Some(current) = zones_by_key.get(&key)
            && current.same_transfer_shape(&plan)
        {
            plan.generation = current.generation;
            plan.cancellation = current.cancellation.clone();
            zones_by_key.insert(key, plan);
            return false;
        }
        if let Some(current) = zones_by_key.get(&key) {
            current.cancel();
        }
        assign_generation(&mut plan, &self.next_generation);
        zones_by_key.insert(key, plan);
        true
    }

    pub(crate) fn catalog_member_plan(
        &self,
        catalog_origin: &DomainName,
        member_origin: DomainName,
        transfer_override: Option<&CatalogMemberTransfer>,
    ) -> Option<ZoneTransferPlan> {
        let template = self
            .catalog_member_templates_by_key
            .get(&catalog_origin.canonical_key())
            .map(|plan| plan.for_member_origin(member_origin))?;
        if let Some(transfer_override) = transfer_override {
            let mut plan = self.apply_catalog_member_override(template, transfer_override)?;
            assign_generation(&mut plan, &self.next_generation);
            Some(plan)
        } else {
            let mut plan = template;
            assign_generation(&mut plan, &self.next_generation);
            Some(plan)
        }
    }

    fn apply_catalog_member_override(
        &self,
        mut plan: ZoneTransferPlan,
        transfer_override: &CatalogMemberTransfer,
    ) -> Option<ZoneTransferPlan> {
        if !transfer_override.primaries.is_empty() {
            let transport = transfer_override
                .xfr
                .as_ref()
                .and_then(|xfr| xfr.transport)
                .unwrap_or(CatalogMemberTransport::Tcp);
            let port = transfer_override
                .xfr
                .as_ref()
                .and_then(|xfr| xfr.port)
                .unwrap_or(match transport {
                    CatalogMemberTransport::Tcp => 53,
                    CatalogMemberTransport::Xot => 853,
                });
            let server_name = transfer_override
                .xfr
                .as_ref()
                .and_then(|xfr| xfr.server_name.clone());
            let xot_profile = if transport == CatalogMemberTransport::Xot {
                Some(
                    plan.primaries
                        .iter()
                        .find(|primary| primary.transport == TransferTransportConfig::Xot)?
                        .clone(),
                )
            } else {
                None
            };
            plan.primaries = transfer_override
                .primaries
                .iter()
                .map(|primary| {
                    let addr = std::net::SocketAddr::new(primary.addr, port);
                    match transport {
                        CatalogMemberTransport::Tcp => TransferPrimaryConfig::tcp(addr),
                        CatalogMemberTransport::Xot => {
                            let mut primary_config = xot_profile
                                .clone()
                                .expect("XoT profile checked before override construction");
                            primary_config.addr = addr;
                            if server_name.is_some() {
                                primary_config.server_name = server_name.clone();
                            }
                            primary_config
                        }
                    }
                })
                .collect();
        }

        if let Some(tsig_key_name) = &transfer_override.tsig_key_name {
            plan.tsig_key_name = Some(tsig_key_name.clone());
        }

        if plan.tsig_key_name.is_none()
            && plan.primaries.iter().any(|primary| {
                primary.transport == TransferTransportConfig::Tcp
                    && !is_legacy_private_primary(primary.addr.ip())
            })
        {
            return None;
        }

        Some(plan)
    }

    pub(crate) fn remove(&self, origin: &DomainName) {
        if let Some(plan) = self
            .zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .remove(&origin.canonical_key())
        {
            plan.cancel();
        }
    }

    pub(crate) fn initial_origins(&self) -> Vec<DomainName> {
        let mut origins = self
            .zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .values()
            .map(|plan| plan.origin.clone())
            .collect::<Vec<_>>();
        origins.sort_by_key(|origin| origin.canonical_key());
        origins
    }
}

fn assign_generation(plan: &mut ZoneTransferPlan, next_generation: &AtomicU64) {
    plan.generation = next_generation.fetch_add(1, Ordering::Relaxed);
    plan.cancellation = fresh_cancellation();
}

fn fresh_cancellation() -> watch::Sender<bool> {
    watch::channel(false).0
}

fn transfer_plan_from_zone_config(
    zone: &ZoneConfig,
    tsig_fudge_seconds: u16,
    max_transfer_ingest_bytes: u64,
    max_transfer_ingest_messages: u64,
    transfer_sources: &[SocketAddr],
    primary_start_index: &impl Fn(usize) -> Result<usize, getrandom::Error>,
) -> Result<ZoneTransferPlan, RuntimeError> {
    let origin = DomainName::from_absolute_str(&zone.name)
        .expect("configuration validation rejects invalid zone names");
    let tsig_key_name = zone.tsig_key.as_ref().map(|name| {
        DomainName::from_absolute_str(name)
            .expect("configuration validation rejects invalid TSIG key references")
    });
    let primaries = zone.transfer_targets();
    let primary_start =
        primary_start_index(primaries.len()).map_err(RuntimeError::PrimaryRotationRandom)?;
    let primaries = rotate_transfer_targets(primaries, primary_start);
    Ok(ZoneTransferPlan {
        origin,
        qclass: 1,
        primaries,
        tsig_key_name,
        tsig_fudge_seconds,
        max_transfer_ingest_bytes,
        max_transfer_ingest_messages,
        transfer_sources: transfer_sources.to_vec(),
        generation: 0,
        cancellation: fresh_cancellation(),
    })
}

fn transfer_plan_from_catalog_zone_config(
    zone: &CatalogZoneConfig,
    tsig_fudge_seconds: u16,
    max_transfer_ingest_bytes: u64,
    max_transfer_ingest_messages: u64,
    transfer_sources: &[SocketAddr],
    primary_start_index: &impl Fn(usize) -> Result<usize, getrandom::Error>,
) -> Result<ZoneTransferPlan, RuntimeError> {
    let zone = ZoneConfig {
        name: zone.name.clone(),
        class: zone.class.clone(),
        primaries: Vec::new(),
        transfer_primaries: zone.catalog_transfer_targets(),
        notify_sources: zone.notify_sources.clone(),
        tsig_key: zone.catalog_tsig_key_name().map(str::to_owned),
    };
    transfer_plan_from_zone_config(
        &zone,
        tsig_fudge_seconds,
        max_transfer_ingest_bytes,
        max_transfer_ingest_messages,
        transfer_sources,
        primary_start_index,
    )
}

fn transfer_plan_from_catalog_member_config(
    zone: &CatalogZoneConfig,
    tsig_fudge_seconds: u16,
    max_transfer_ingest_bytes: u64,
    max_transfer_ingest_messages: u64,
    transfer_sources: &[SocketAddr],
    primary_start_index: &impl Fn(usize) -> Result<usize, getrandom::Error>,
) -> Result<ZoneTransferPlan, RuntimeError> {
    let zone = ZoneConfig {
        name: zone.name.clone(),
        class: zone.class.clone(),
        primaries: Vec::new(),
        transfer_primaries: zone.member_transfer_targets(),
        notify_sources: zone.notify_sources.clone(),
        tsig_key: zone.member_tsig_key_name().map(str::to_owned),
    };
    transfer_plan_from_zone_config(
        &zone,
        tsig_fudge_seconds,
        max_transfer_ingest_bytes,
        max_transfer_ingest_messages,
        transfer_sources,
        primary_start_index,
    )
}

pub(crate) fn rotate_transfer_targets(
    primaries: Vec<TransferPrimaryConfig>,
    start_index: usize,
) -> Vec<TransferPrimaryConfig> {
    if primaries.len() <= 1 {
        return primaries;
    }

    let start_index = start_index % primaries.len();
    primaries
        .iter()
        .cycle()
        .skip(start_index)
        .take(primaries.len())
        .cloned()
        .collect()
}

fn random_primary_start_index(primary_count: usize) -> Result<usize, getrandom::Error> {
    if primary_count <= 1 {
        return Ok(0);
    }

    loop {
        let sample = random_u64()?;
        if let Some(index) = uniform_index_from_u64(sample, primary_count) {
            return Ok(index);
        }
    }
}

fn random_u64() -> Result<u64, getrandom::Error> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

pub(crate) fn uniform_index_from_u64(sample: u64, primary_count: usize) -> Option<usize> {
    if primary_count == 0 {
        return None;
    }
    if primary_count == 1 {
        return Some(0);
    }

    let primary_count = primary_count as u128;
    let sample = u128::from(sample);
    let sample_space = u128::from(u64::MAX) + 1;
    let accepted_samples = (sample_space / primary_count) * primary_count;
    if sample >= accepted_samples {
        return None;
    }

    Some((sample % primary_count) as usize)
}
