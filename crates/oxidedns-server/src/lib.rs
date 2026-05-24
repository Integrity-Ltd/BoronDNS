use thiserror::Error;
use tracing::info;
use oxidedns_core::{ServerConfig, zone::ZoneStore};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime is a skeleton; DNS serving is not implemented yet")]
    NotImplemented,
}

#[derive(Debug)]
pub struct Runtime {
    config: ServerConfig,
    zones: ZoneStore,
}

impl Runtime {
    pub fn new(config: ServerConfig) -> Self {
        let mut zones = ZoneStore::new();
        for zone in &config.zones {
            zones.insert_loading(zone.name.clone());
        }

        Self { config, zones }
    }

    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }

    pub async fn run(self) -> Result<(), RuntimeError> {
        info!(
            udp_listeners = self.config.server.listen_udp.len(),
            tcp_listeners = self.config.server.listen_tcp.len(),
            zones = self.zones.len(),
            "OxideDNS runtime skeleton initialized"
        );

        tokio::signal::ctrl_c()
            .await
            .map_err(|_| RuntimeError::NotImplemented)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use oxidedns_core::ServerConfig;

    use super::Runtime;

    #[test]
    fn runtime_initializes_loading_zones() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        let runtime = Runtime::new(config);
        assert_eq!(runtime.zone_count(), 1);
    }
}
