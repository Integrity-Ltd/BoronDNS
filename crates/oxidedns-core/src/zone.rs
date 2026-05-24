use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneState {
    Loading,
    Active,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSnapshot {
    pub origin: String,
    pub state: ZoneState,
    pub serial: Option<u32>,
}

impl ZoneSnapshot {
    pub fn loading(origin: impl Into<String>) -> Self {
        Self {
            origin: origin.into(),
            state: ZoneState::Loading,
            serial: None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ZoneStore {
    zones: HashMap<String, Arc<ZoneSnapshot>>,
}

impl ZoneStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_loading(&mut self, origin: impl Into<String>) {
        let origin = origin.into();
        self.zones
            .insert(origin.clone(), Arc::new(ZoneSnapshot::loading(origin)));
    }

    pub fn get(&self, origin: &str) -> Option<Arc<ZoneSnapshot>> {
        self.zones.get(origin).cloned()
    }

    pub fn len(&self) -> usize {
        self.zones.len()
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}
