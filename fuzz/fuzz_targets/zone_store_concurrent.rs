#![no_main]

use borondns_core::{
    dns::DomainName,
    zone::{ZoneSnapshot, ZoneState, ZoneStore},
};
use libfuzzer_sys::fuzz_target;
use std::{
    sync::{
        Arc, OnceLock,
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
};

const ZONE_COUNT: usize = 16;
const WORKER_COUNT: usize = 4;
const MAX_OPERATIONS: usize = 512;

struct WorkerJob {
    store: ZoneStore,
    zones: Arc<[DomainName]>,
    operations: Arc<[[u8; 4]]>,
    completed: SyncSender<()>,
}

fn run_worker(worker: usize, receiver: Receiver<WorkerJob>) {
    while let Ok(job) = receiver.recv() {
        for operation in job
            .operations
            .iter()
            .filter(|operation| (operation[0] as usize >> 6) == worker)
        {
            let opcode = operation[0] & 0x0f;
            let origin = &job.zones[operation[1] as usize % job.zones.len()];
            let serial =
                u32::from_be_bytes([operation[2], operation[3], operation[0], operation[1]]);
            match opcode % 8 {
                0 => job.store.insert_loading(origin.clone()),
                1 => job.store.insert_loading_hidden(origin.clone()),
                2 => {
                    job.store
                        .try_insert_snapshot(ZoneSnapshot::active(
                            origin.clone(),
                            Some(serial),
                            Vec::new(),
                        ))
                        .expect("empty fuzz zone compiles");
                }
                3 => {
                    job.store.hide_zone(origin);
                }
                4 => {
                    job.store.show_zone(origin);
                }
                5 => {
                    job.store.expire_zone(origin);
                }
                6 => {
                    job.store.remove_zone(origin);
                }
                _ => {
                    let second = &job.zones[(operation[1] as usize + 1) % job.zones.len()];
                    let remove_first = &job.zones[(operation[1] as usize + 2) % job.zones.len()];
                    let remove_second = &job.zones[(operation[1] as usize + 3) % job.zones.len()];
                    job.store.apply_atomic_directory_update(
                        &[origin.clone(), second.clone()],
                        &[remove_first.clone(), remove_second.clone()],
                        &[],
                        &[],
                    );
                }
            }
            if operation[3] & 0x1f == 0 {
                thread::yield_now();
            }
        }
        job.completed
            .send(())
            .expect("fuzz invocation waits for every persistent worker");
    }
}

fn workers() -> &'static [SyncSender<WorkerJob>] {
    static WORKERS: OnceLock<Vec<SyncSender<WorkerJob>>> = OnceLock::new();
    WORKERS.get_or_init(|| {
        (0..WORKER_COUNT)
            .map(|worker| {
                let (sender, receiver) = mpsc::sync_channel(1);
                thread::Builder::new()
                    .name(format!("zone-store-fuzz-{worker}"))
                    .spawn(move || run_worker(worker, receiver))
                    .expect("persistent fuzz worker starts");
                sender
            })
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let store = ZoneStore::new();
    let zones: Arc<[DomainName]> = (0..ZONE_COUNT)
        .map(|index| {
            DomainName::from_absolute_str(&format!("zone{index}.concurrent-state-fuzz."))
                .expect("static fuzz zone is valid")
        })
        .collect::<Vec<_>>()
        .into();
    let operations: Arc<[[u8; 4]]> = data
        .chunks(4)
        .take(MAX_OPERATIONS)
        .map(|operation| {
            let mut copied = [0u8; 4];
            copied[..operation.len()].copy_from_slice(operation);
            copied
        })
        .collect::<Vec<_>>()
        .into();

    // libFuzzer invokes this callback millions of times. Spawning four fresh
    // OS threads per input made AddressSanitizer retain thread bookkeeping and
    // eventually report leaks or cross its 2 GiB RSS limit. A fixed worker set
    // preserves real concurrent ZoneStore mutation while bounding process-wide
    // thread state for multi-day runs.
    let (completed, completions) = mpsc::sync_channel(WORKER_COUNT);
    for worker in workers() {
        worker
            .send(WorkerJob {
                store: store.clone(),
                zones: zones.clone(),
                operations: operations.clone(),
                completed: completed.clone(),
            })
            .expect("persistent fuzz worker remains available");
    }
    drop(completed);
    for _ in 0..WORKER_COUNT {
        completions
            .recv()
            .expect("persistent fuzz worker completes its operation stream");
    }

    let all = store.zone_metadata();
    let published = store.published_zone_metadata();
    let active = published
        .iter()
        .filter(|metadata| metadata.state == ZoneState::Active)
        .count();
    assert_eq!(store.active_count(), active);
    assert_eq!(store.has_active_zone(), active > 0);
    assert!(published.len() <= all.len());
    for metadata in all {
        let exact = store
            .exact_zone_control_metadata(&metadata.origin)
            .expect("enumerated zone remains present after workers join");
        assert_eq!(exact.origin_key, metadata.origin_key);
        assert_eq!(exact.state, metadata.state);
        assert_eq!(exact.serial, metadata.serial);
        let hidden = store.is_hidden(&metadata.origin);
        assert_eq!(
            store.find_published_zone(&metadata.origin).is_some(),
            !hidden
        );
    }
});
