use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use oxidedns_core::{
    ServerConfig, axfr,
    config::{CatalogZoneConfig, TransferPrimaryConfig, ZoneConfig},
    dns::DomainName,
    tsig::TsigKey,
};

use crate::RuntimeError;

#[derive(Debug, Clone)]
pub(crate) struct ZoneTransferPlan {
    pub(crate) origin: DomainName,
    pub(crate) qclass: u16,
    pub(crate) primaries: Vec<TransferPrimaryConfig>,
    pub(crate) tsig_key: Option<Arc<TsigKey>>,
    pub(crate) tsig_fudge_seconds: u16,
    pub(crate) max_transfer_ingest_bytes: u64,
    pub(crate) parse_options: axfr::TransferParseOptions,
    pub(crate) transfer_sources: Vec<SocketAddr>,
}

impl ZoneTransferPlan {
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
            tsig_key: self.tsig_key.clone(),
            tsig_fudge_seconds: self.tsig_fudge_seconds,
            max_transfer_ingest_bytes: self.max_transfer_ingest_bytes,
            parse_options: self.parse_options,
            transfer_sources: self.transfer_sources.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransferPlan {
    zones_by_key: Arc<Mutex<HashMap<String, ZoneTransferPlan>>>,
}

impl TransferPlan {
    pub(crate) fn from_config(config: &ServerConfig) -> Result<Self, RuntimeError> {
        Self::from_config_with_primary_start(config, random_primary_start_index)
    }

    pub(crate) fn from_config_with_primary_start(
        config: &ServerConfig,
        primary_start_index: impl Fn(usize) -> Result<usize, getrandom::Error>,
    ) -> Result<Self, RuntimeError> {
        let tsig_keys = config
            .tsig_keys
            .iter()
            .map(|key| {
                let secret = key
                    .secret_base64()
                    .expect("configuration validation rejects invalid TSIG key secret sources");
                let key = TsigKey::from_base64(&key.name, &key.algorithm, &secret)
                    .expect("configuration validation rejects invalid TSIG keys");
                (key.name.canonical_key(), Arc::new(key))
            })
            .collect::<HashMap<_, _>>();
        let mut zones_by_key = HashMap::new();
        for zone in &config.zones {
            let plan = transfer_plan_from_zone_config(
                zone,
                &tsig_keys,
                config.tsig.fudge_seconds,
                config.limits.max_transfer_ingest_bytes,
                axfr::TransferParseOptions {
                    accept_out_of_zone_glue: config.transfer.accept_out_of_zone_glue,
                },
                &config.interfaces.transfer,
                &primary_start_index,
            )?;
            zones_by_key.insert(plan.origin.canonical_key(), plan);
        }
        for catalog_zone in &config.catalog_zones {
            let plan = transfer_plan_from_catalog_zone_config(
                catalog_zone,
                &tsig_keys,
                config.tsig.fudge_seconds,
                config.limits.max_transfer_ingest_bytes,
                axfr::TransferParseOptions {
                    accept_out_of_zone_glue: config.transfer.accept_out_of_zone_glue,
                },
                &config.interfaces.transfer,
                &primary_start_index,
            )?;
            zones_by_key.insert(plan.origin.canonical_key(), plan);
        }

        Ok(Self {
            zones_by_key: Arc::new(Mutex::new(zones_by_key)),
        })
    }

    pub(crate) fn get(&self, origin: &DomainName) -> Option<ZoneTransferPlan> {
        self.zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .get(&origin.canonical_key())
            .cloned()
    }

    pub(crate) fn insert(&self, plan: ZoneTransferPlan) {
        self.zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .insert(plan.origin.canonical_key(), plan);
    }

    pub(crate) fn remove(&self, origin: &DomainName) {
        self.zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .remove(&origin.canonical_key());
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

fn transfer_plan_from_zone_config(
    zone: &ZoneConfig,
    tsig_keys: &HashMap<String, Arc<TsigKey>>,
    tsig_fudge_seconds: u16,
    max_transfer_ingest_bytes: u64,
    parse_options: axfr::TransferParseOptions,
    transfer_sources: &[SocketAddr],
    primary_start_index: &impl Fn(usize) -> Result<usize, getrandom::Error>,
) -> Result<ZoneTransferPlan, RuntimeError> {
    let origin = DomainName::from_absolute_str(&zone.name)
        .expect("configuration validation rejects invalid zone names");
    let tsig_key = zone.tsig_key.as_ref().map(|name| {
        let name = DomainName::from_absolute_str(name)
            .expect("configuration validation rejects invalid TSIG key references");
        tsig_keys
            .get(&name.canonical_key())
            .expect("configuration validation rejects unknown TSIG key references")
            .clone()
    });
    let primaries = zone.transfer_targets();
    let primary_start =
        primary_start_index(primaries.len()).map_err(RuntimeError::PrimaryRotationRandom)?;
    let primaries = rotate_transfer_targets(primaries, primary_start);
    Ok(ZoneTransferPlan {
        origin,
        qclass: 1,
        primaries,
        tsig_key,
        tsig_fudge_seconds,
        max_transfer_ingest_bytes,
        parse_options,
        transfer_sources: transfer_sources.to_vec(),
    })
}

fn transfer_plan_from_catalog_zone_config(
    zone: &CatalogZoneConfig,
    tsig_keys: &HashMap<String, Arc<TsigKey>>,
    tsig_fudge_seconds: u16,
    max_transfer_ingest_bytes: u64,
    parse_options: axfr::TransferParseOptions,
    transfer_sources: &[SocketAddr],
    primary_start_index: &impl Fn(usize) -> Result<usize, getrandom::Error>,
) -> Result<ZoneTransferPlan, RuntimeError> {
    let zone = ZoneConfig {
        name: zone.name.clone(),
        class: zone.class.clone(),
        primaries: zone.primaries.clone(),
        transfer_primaries: zone.transfer_primaries.clone(),
        notify_sources: zone.notify_sources.clone(),
        tsig_key: zone.tsig_key.clone(),
    };
    transfer_plan_from_zone_config(
        &zone,
        tsig_keys,
        tsig_fudge_seconds,
        max_transfer_ingest_bytes,
        parse_options,
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
