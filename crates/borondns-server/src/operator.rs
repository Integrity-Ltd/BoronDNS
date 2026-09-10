//! Opt-in, same-UID/root local administration. No HTTP or DNS transfer listener.
use std::{
    fmt::Write as _,
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use borondns_core::{
    dns::DomainName,
    zone::{ZoneState, ZoneStore},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, mpsc},
    task::JoinSet,
};

use crate::{RefreshReason, RefreshRequest, RuntimeError, TransferPlan, ZoneRefreshRegistry};

const REQUEST_LIMIT: usize = 4096;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    command: String,
    zone: String,
}

pub(crate) struct OperatorListener {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
    uid: u32,
}

impl OperatorListener {
    pub(crate) fn bind(path: &Path) -> io::Result<Self> {
        let uid = crate::privilege::current_effective_uid();
        validate_socket_parent(path, uid)?;
        // Never unlink/adopt a pre-existing file, socket, or symlink.
        let listener = UnixListener::bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let bound = Self {
            listener,
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
            uid,
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(bound)
    }

    pub(crate) async fn serve(
        self,
        zones: ZoneStore,
        plans: TransferPlan,
        registry: ZoneRefreshRegistry,
        refresh_tx: mpsc::Sender<RefreshRequest>,
    ) -> Result<(), RuntimeError> {
        let slots = Arc::new(Semaphore::new(4));
        let dump_slot = Arc::new(Semaphore::new(1));
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    let (stream, _) = result.map_err(|e| RuntimeError::InvalidRuntimeConfig(format!("operator socket accept: {e}")))?;
                    let peer = match stream.peer_cred() { Ok(peer) => peer, Err(_) => continue };
                    if !authorized_uid(self.uid, peer.uid()) { continue; }
                    let Ok(slot) = slots.clone().try_acquire_owned() else { continue; };
                    let (zones, plans, registry, refresh_tx, dump_slot) =
                        (zones.clone(), plans.clone(), registry.clone(), refresh_tx.clone(), dump_slot.clone());
                    clients.spawn(async move {
                        let _slot = slot;
                        // Includes request reads, streaming writes, and slow consumers.
                        let _ = tokio::time::timeout(COMMAND_TIMEOUT, handle(stream, zones, plans, registry, refresh_tx, dump_slot)).await;
                    });
                }
                Some(_) = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    }
}

impl Drop for OperatorListener {
    fn drop(&mut self) {
        // Parent is trusted and non-writable by other users. Never remove a
        // foreign replacement, including a file left by a different instance.
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.identity)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn authorized_uid(server: u32, peer: u32) -> bool {
    peer == 0 || peer == server
}

fn validate_socket_parent(path: &Path, uid: u32) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, std::path::Component::ParentDir))
    {
        return Err(io::Error::other(
            "operator socket path must be absolute without parent traversal",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("operator socket needs a parent directory"))?;
    for ancestor in parent.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor)?;
        let writable = meta.mode() & 0o022 != 0;
        // /tmp is usable only as a root-owned sticky ancestor, not as the
        // immediate socket directory. The private child must already exist.
        let sticky_ancestor = ancestor != parent && meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        if !meta.is_dir() || ![0, uid].contains(&meta.uid()) || (writable && !sticky_ancestor) {
            return Err(io::Error::other(
                "operator socket requires trusted, non-symlink, non-group/world-writable parent directories",
            ));
        }
    }
    Ok(())
}

async fn write_header(stream: &mut UnixStream, value: Value) -> io::Result<()> {
    let mut text = value.to_string();
    text.push('\n');
    stream.write_all(text.as_bytes()).await
}

async fn handle(
    mut stream: UnixStream,
    zones: ZoneStore,
    plans: TransferPlan,
    registry: ZoneRefreshRegistry,
    refresh_tx: mpsc::Sender<RefreshRequest>,
    dump_slot: Arc<Semaphore>,
) -> io::Result<()> {
    let request = tokio::time::timeout(Duration::from_secs(5), async {
        let length = stream.read_u32().await? as usize;
        if length == 0 || length > REQUEST_LIMIT {
            return Err(io::Error::other("invalid request length"));
        }
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        serde_json::from_slice::<Request>(&bytes).map_err(io::Error::other)
    })
    .await
    .map_err(io::Error::other)??;
    let name = if request.zone.ends_with('.') {
        request.zone.clone()
    } else {
        format!("{}.", request.zone)
    };
    let Ok(origin) = DomainName::from_absolute_str(&name) else {
        return write_header(
            &mut stream,
            json!({"ok": false, "error": "invalid zone name"}),
        )
        .await;
    };
    let Some(metadata) = zones.exact_zone_metadata(&origin) else {
        return write_header(&mut stream, json!({"ok": false, "error": "zone not found"})).await;
    };
    match request.command.as_str() {
        "show" => {
            let schedule = {
                let statuses = registry
                    .statuses
                    .lock()
                    .expect("zone refresh registry lock poisoned");
                statuses.get(&origin.canonical_key()).map(|s| {
                    json!({
                        "last_success_unix_seconds": s.last_success_unix_secs,
                        "last_success_serial": s.last_success_serial,
                        "next_refresh_unix_seconds": s.next_refresh_unix_secs,
                        "failures_since_success": s.failures_since_success,
                        "in_progress": s.in_progress,
                        "last_failure": s.last_failure_cause,
                    })
                })
            };
            let primaries = plans.get(&origin).map(|p| {
                p.primaries
                    .iter()
                    .map(|p| p.addr.to_string())
                    .collect::<Vec<_>>()
            });
            write_header(&mut stream, json!({"ok": true, "data": {
                "zone": metadata.origin.to_string(), "state": format!("{:?}", metadata.state).to_lowercase(),
                "serial": metadata.serial,
                "soa": metadata.soa_timers.map(|s| json!({"refresh": s.refresh, "retry": s.retry, "expire": s.expire, "minimum": s.minimum})),
                "rrsets": metadata.shape.map(|s| s.rrset_count),
                "records": metadata.shape.map(|s| s.rdata_count),
                "primaries": primaries, "refresh": schedule,
            }})).await
        }
        "refresh" | "retransfer" => {
            let result = enqueue(&plans, &refresh_tx, origin, request.command == "retransfer");
            let reply = match result {
                Ok(()) => {
                    json!({"ok": true, "data": {"status": "queued", "command": request.command, "zone": name}})
                }
                Err(error) => json!({"ok": false, "error": error}),
            };
            write_header(&mut stream, reply).await
        }
        "dump" => {
            let Ok(slot) = dump_slot.try_acquire_owned() else {
                return write_header(
                    &mut stream,
                    json!({"ok": false, "error": "another zone dump is active"}),
                )
                .await;
            };
            let Some(snapshot) = zones.exact_snapshot_for_transfer(&origin) else {
                return write_header(
                    &mut stream,
                    json!({"ok": false, "error": "zone no longer exists"}),
                )
                .await;
            };
            if snapshot.metadata().state != ZoneState::Active {
                return write_header(
                    &mut stream,
                    json!({"ok": false, "error": "zone is not active"}),
                )
                .await;
            }
            let count = snapshot.snapshot_for_transfer().rdata_record_count();
            write_header(
                &mut stream,
                json!({"ok": true, "records": count, "serial": snapshot.metadata().serial}),
            )
            .await?;
            let (tx, mut rx) = mpsc::channel::<String>(2);
            // Dropping rx on timeout/disconnect unblocks the producer and
            // releases both the snapshot generation and the global dump slot.
            let producer = tokio::task::spawn_blocking(move || {
                let _slot = slot;
                snapshot
                    .snapshot_for_transfer()
                    .try_visit_persistence_records(|owner, rr_type, class, ttl, rdata| {
                        tx.blocking_send(record_line(owner, rr_type, class, ttl, rdata))
                            .map_err(io::Error::other)
                    })
            });
            while let Some(line) = rx.recv().await {
                stream.write_all(line.as_bytes()).await?;
            }
            producer.await.map_err(io::Error::other)??;
            Ok(())
        }
        _ => {
            write_header(
                &mut stream,
                json!({"ok": false, "error": "unknown command"}),
            )
            .await
        }
    }
}

fn enqueue(
    plans: &TransferPlan,
    tx: &mpsc::Sender<RefreshRequest>,
    zone: DomainName,
    force: bool,
) -> Result<(), String> {
    let plan = plans.get(&zone).ok_or("zone has no transfer plan")?;
    let permit = tx
        .try_reserve()
        .map_err(|_| "refresh queue is full or closed")?;
    if !plans.is_current_plan(&plan) {
        return Err("zone transfer plan changed; retry".to_owned());
    }
    if force {
        plan.request_axfr();
    }
    permit.send(
        RefreshRequest::new(zone, None, RefreshReason::ControlPlane).with_plan_generation(&plan),
    );
    Ok(())
}

fn record_line(owner: &DomainName, rr_type: u16, class: u16, ttl: u32, rdata: &[u8]) -> String {
    // RFC 3597 generic RDATA works for known and unknown types, preserving
    // canonical uncompressed bytes without a second per-type zone-file codec.
    let mut line = String::new();
    let wire = owner.to_wire();
    let mut offset = 0;
    while wire[offset] != 0 {
        let length = wire[offset] as usize;
        offset += 1;
        for byte in &wire[offset..offset + length] {
            match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'*' => {
                    line.push(*byte as char)
                }
                _ => {
                    let _ = write!(line, "\\{byte:03}");
                }
            }
        }
        line.push('.');
        offset += length;
    }
    if line.is_empty() {
        line.push('.');
    }
    let _ = write!(
        line,
        " {ttl} CLASS{class} TYPE{rr_type} \\# {} ",
        rdata.len()
    );
    for byte in rdata {
        let _ = write!(line, "{byte:02X}");
    }
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use borondns_core::{
        ServerConfig,
        zone::{Rrset, ZoneSnapshot},
    };

    fn config() -> ServerConfig {
        ServerConfig::from_toml_str(
            r#"
[server]
allow_non_rfc5936_cold_start = true
[[zones]]
name = "example.test."
primaries = ["127.0.0.1:9"]
"#,
        )
        .unwrap()
    }

    fn registry() -> ZoneRefreshRegistry {
        ZoneRefreshRegistry::new(
            Duration::from_secs(1),
            Duration::from_secs(3600),
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
    }

    fn private_dir() -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!(
            "borondns-operator-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        path
    }

    #[test]
    fn operator_peer_authorization_is_same_uid_or_root_only() {
        assert!(authorized_uid(1000, 1000));
        assert!(authorized_uid(1000, 0));
        assert!(!authorized_uid(1000, 1001));
        assert!(!authorized_uid(0, 1000));
    }

    #[tokio::test]
    async fn operator_socket_permissions_collision_and_cleanup() {
        let dir = private_dir();
        let path = dir.join("operator.sock");
        let listener = OperatorListener::bind(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(OperatorListener::bind(&path).is_err());
        drop(listener);
        assert!(!path.exists());
        let listener = OperatorListener::bind(&path).unwrap();
        std::fs::rename(&path, dir.join("old.sock")).unwrap();
        std::fs::write(&path, "foreign").unwrap();
        drop(listener);
        assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn operator_socket_rejects_untrusted_parent_and_symlinks() {
        let dir = private_dir();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(OperatorListener::bind(&dir.join("operator.sock")).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&dir, dir.join("link")).unwrap();
        assert!(OperatorListener::bind(&dir.join("link/operator.sock")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn operator_dump_escapes_owner_and_preserves_unknown_and_empty_rdata() {
        let (owner, _) = DomainName::parse(b"\x07a;\"()@\\\x04test\0", 0).unwrap();
        assert_eq!(
            record_line(&owner, 65280, 1, 300, &[0, 0xff]),
            "a\\059\\034\\040\\041\\064\\092.test. 300 CLASS1 TYPE65280 \\# 2 00FF\n"
        );
        assert_eq!(
            record_line(&DomainName::root(), 65280, 1, 0, &[]),
            ". 0 CLASS1 TYPE65280 \\# 0 \n"
        );
    }

    #[tokio::test]
    async fn operator_force_survives_queue_merge_and_does_not_leak_on_rejection() {
        let plans = TransferPlan::from_config(&config()).unwrap();
        let zone = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = plans.get(&zone).unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        enqueue(&plans, &tx, zone.clone(), false).unwrap();
        assert!(enqueue(&plans, &tx, zone.clone(), true).is_err());
        assert!(!plan.take_requested_axfr());
        let mut ordinary = rx.recv().await.unwrap();
        enqueue(&plans, &tx, zone.clone(), true).unwrap();
        let forced = rx.recv().await.unwrap();
        crate::merge_refresh_request(&mut ordinary, forced);
        crate::merge_refresh_request(
            &mut ordinary,
            RefreshRequest::new(zone, None, RefreshReason::Scheduled),
        );
        drop(ordinary); // Even internal eviction cannot lose the plan's bit.
        assert!(plan.take_requested_axfr());
        assert!(!plan.take_requested_axfr());
        plan.request_axfr();
        assert!(
            !plan
                .for_member_origin(DomainName::root())
                .take_requested_axfr()
        );
        assert!(plan.take_requested_axfr());
    }

    async fn exchange(zones: ZoneStore, request: Value, dump_slot: Arc<Semaphore>) -> String {
        let (server, mut client) = UnixStream::pair().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let task = tokio::spawn(handle(
            server,
            zones,
            TransferPlan::from_config(&config()).unwrap(),
            registry(),
            tx,
            dump_slot,
        ));
        let bytes = request.to_string();
        client.write_u32(bytes.len() as u32).await.unwrap();
        client.write_all(bytes.as_bytes()).await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        task.await.unwrap().unwrap();
        response
    }

    #[tokio::test]
    async fn operator_show_missing_loading_and_dump_busy_are_explicit() {
        let zones = ZoneStore::new();
        let slot = Arc::new(Semaphore::new(1));
        let missing = exchange(
            zones.clone(),
            json!({"command":"show","zone":"missing.test"}),
            slot.clone(),
        )
        .await;
        assert!(missing.contains("zone not found"));
        zones.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());
        let shown = exchange(
            zones.clone(),
            json!({"command":"show","zone":"EXAMPLE.test"}),
            slot.clone(),
        )
        .await;
        assert!(shown.contains("\"state\":\"loading\""));
        let dumped = exchange(
            zones.clone(),
            json!({"command":"dump","zone":"example.test"}),
            slot.clone(),
        )
        .await;
        assert!(dumped.contains("not active"));
        let _permit = slot.clone().acquire_owned().await.unwrap();
        let busy = exchange(zones, json!({"command":"dump","zone":"example.test"}), slot).await;
        assert!(busy.contains("another zone dump"));
    }

    #[test]
    fn operator_record_traversal_stops_on_first_writer_failure() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            None,
            vec![Rrset::new(
                origin,
                65280,
                1,
                300,
                vec![vec![1], vec![2], vec![3]],
            )],
        );
        let mut visits = 0;
        let result = snapshot.try_visit_persistence_records(|_, _, _, _, _| {
            visits += 1;
            Err::<(), _>("closed")
        });
        assert_eq!(result, Err("closed"));
        assert_eq!(visits, 1);
    }

    #[tokio::test]
    async fn operator_dump_holds_one_generation_during_publication() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let zones = ZoneStore::new();
        zones.insert_snapshot(ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin.clone(),
                65280,
                1,
                300,
                (0_u32..20_000).map(|n| n.to_be_bytes().to_vec()).collect(),
            )],
        ));
        let (server, mut client) = UnixStream::pair().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let slot = Arc::new(Semaphore::new(1));
        let task = tokio::spawn(handle(
            server,
            zones.clone(),
            TransferPlan::from_config(&config()).unwrap(),
            registry(),
            tx,
            slot.clone(),
        ));
        let bytes = json!({"command":"dump","zone":"example.test"}).to_string();
        client.write_u32(bytes.len() as u32).await.unwrap();
        client.write_all(bytes.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(client);
        let mut header = String::new();
        reader.read_line(&mut header).await.unwrap();
        assert!(header.contains("\"serial\":1"));
        zones.insert_snapshot(ZoneSnapshot::active(
            origin.clone(),
            Some(2),
            vec![Rrset::new(
                origin,
                65280,
                1,
                300,
                vec![b"new-generation".to_vec()],
            )],
        ));
        let mut text = String::new();
        reader.read_to_string(&mut text).await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(text.lines().count(), 20_000);
        assert!(text.lines().all(|line| line.contains("\\# 4 ")));
        assert_eq!(slot.available_permits(), 1);
    }

    #[tokio::test]
    async fn operator_dump_disconnect_releases_generation_and_slot() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let zones = ZoneStore::new();
        zones.insert_snapshot(ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin,
                65280,
                1,
                300,
                (0_u32..20_000).map(|n| n.to_be_bytes().to_vec()).collect(),
            )],
        ));
        let (server, mut client) = UnixStream::pair().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let slot = Arc::new(Semaphore::new(1));
        let task = tokio::spawn(handle(
            server,
            zones,
            TransferPlan::from_config(&config()).unwrap(),
            registry(),
            tx,
            slot.clone(),
        ));
        let bytes = json!({"command":"dump","zone":"example.test"}).to_string();
        client.write_u32(bytes.len() as u32).await.unwrap();
        client.write_all(bytes.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(client);
        reader.read_line(&mut String::new()).await.unwrap();
        drop(reader);
        assert!(task.await.unwrap().is_err());
        let _permit = tokio::time::timeout(Duration::from_secs(2), slot.acquire())
            .await
            .unwrap()
            .unwrap();
    }
}
