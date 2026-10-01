//! Experimental bounded group commit for authenticated, unchanged SOA refreshes.
//! The journal is only restart freshness evidence, never zone content. Every
//! record binds a cache namespace, exact content checksum and serial. Callers
//! retain their normal post-I/O publication/authorization checks.
use super::*;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

const FILE_NAME: &str = "freshness-v1.bfg";
const BATCH_MAGIC: &[u8; 8] = b"BORONFG1";
const RECORD_BYTES: usize = 80;
const MAX_BATCH: usize = 256;
const MAX_KEYS: usize = 2_000_000;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const COMPACT_MIN: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    key: [u8; 32],
    checksum: [u8; 32],
    serial: Option<u32>,
    observed: u64,
}

fn cache_key(persistence: &ZonePersistence, origin: &DomainName) -> [u8; 32] {
    let path = persistence.path_for(origin);
    let stem = path.file_stem().unwrap().to_str().unwrap();
    std::array::from_fn(|i| u8::from_str_radix(&stem[i * 2..i * 2 + 2], 16).unwrap())
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn frame(records: &[Record]) -> Vec<u8> {
    assert!(!records.is_empty() && records.len() <= MAX_BATCH);
    let mut bytes = Vec::with_capacity(12 + records.len() * RECORD_BYTES + 32);
    bytes.extend_from_slice(BATCH_MAGIC);
    bytes.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for record in records {
        bytes.extend_from_slice(&record.key);
        bytes.extend_from_slice(&record.checksum);
        bytes.push(u8::from(record.serial.is_some()));
        bytes.extend_from_slice(&record.serial.unwrap_or_default().to_be_bytes());
        bytes.extend_from_slice(&record.observed.to_be_bytes());
        bytes.extend_from_slice(&[0; 3]);
    }
    let digest = Sha256::digest(&bytes);
    bytes.extend_from_slice(&digest);
    bytes
}

fn apply(index: &mut HashMap<[u8; 32], Record>, record: Record) {
    let entry = index.entry(record.key).or_insert(record);
    if entry.serial != record.serial
        || entry.checksum != record.checksum
        || record.observed > entry.observed
    {
        *entry = record;
    }
}

fn replay(file: &mut File) -> io::Result<(HashMap<[u8; 32], Record>, u64)> {
    let length = file.metadata()?.len();
    if length > MAX_BYTES {
        return Err(invalid("freshness journal exceeds byte bound"));
    }
    let mut index = HashMap::new();
    let mut offset = 0;
    file.seek(SeekFrom::Start(0))?;
    while length - offset >= 12 {
        let mut header = [0; 12];
        file.read_exact(&mut header)?;
        if &header[..8] != BATCH_MAGIC {
            return Err(invalid("bad freshness batch magic"));
        }
        let count = u32::from_be_bytes(header[8..].try_into().unwrap()) as usize;
        if count == 0 || count > MAX_BATCH {
            return Err(invalid("bad freshness batch count"));
        }
        let size = 12 + count * RECORD_BYTES + 32;
        if length - offset < size as u64 {
            break;
        } // uncommitted torn tail
        let mut bytes = vec![0; size];
        bytes[..12].copy_from_slice(&header);
        file.read_exact(&mut bytes[12..])?;
        let end = size - 32;
        if Sha256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
            return Err(invalid("freshness batch checksum mismatch"));
        }
        let (raw_records, remainder) = bytes[12..end].as_chunks::<RECORD_BYTES>();
        debug_assert!(remainder.is_empty());
        for raw in raw_records {
            let serial = u32::from_be_bytes(raw[65..69].try_into().unwrap());
            let serial = match raw[64] {
                0 if serial == 0 => None,
                1 => Some(serial),
                _ => return Err(invalid("bad freshness serial marker")),
            };
            if raw[77..] != [0; 3] {
                return Err(invalid("bad freshness reserved bytes"));
            }
            let record = Record {
                key: raw[..32].try_into().unwrap(),
                checksum: raw[32..64].try_into().unwrap(),
                serial,
                observed: u64::from_be_bytes(raw[69..77].try_into().unwrap()),
            };
            if !index.contains_key(&record.key) && index.len() == MAX_KEYS {
                return Err(invalid("freshness journal exceeds key bound"));
            }
            apply(&mut index, record);
        }
        offset += size as u64;
    }
    Ok((index, offset))
}

fn open_regular(path: &Path, create_new: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).truncate(false);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("freshness path is not a regular file"));
    }
    #[cfg(unix)]
    if file.metadata()?.nlink() != 1 {
        return Err(invalid("freshness path has multiple links"));
    }
    Ok(file)
}

#[derive(Debug)]
struct Journal {
    directory: PathBuf,
    file: File,
    _lock: File,
    index: HashMap<[u8; 32], Record>,
    bytes: u64,
    poisoned: bool,
}

impl Journal {
    fn open(directory: &Path) -> io::Result<Self> {
        let lock = open_regular(&directory.join("freshness-v1.lock"), false)?;
        #[cfg(unix)]
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        #[cfg(not(unix))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "freshness batching needs a filesystem lock",
        ));
        let mut file = open_regular(&directory.join(FILE_NAME), false)?;
        let (index, bytes) = replay(&mut file)?;
        // Remove only an incomplete trailing frame. Never scan past corruption.
        file.set_len(bytes)?;
        file.seek(SeekFrom::Start(bytes))?;
        file.sync_all()?;
        File::open(directory)?.sync_all()?;
        Ok(Self {
            directory: directory.to_owned(),
            file,
            _lock: lock,
            index,
            bytes,
            poisoned: false,
        })
    }

    fn compact(&mut self) -> io::Result<()> {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = self.directory.join(format!(
            ".freshness-v1.tmp.{}.{sequence}",
            std::process::id()
        ));
        let result = (|| {
            let mut file = open_regular(&temp, true)?;
            let mut records = Vec::with_capacity(MAX_BATCH);
            let mut bytes = 0;
            for record in self.index.values() {
                records.push(*record);
                if records.len() != MAX_BATCH {
                    continue;
                }
                let encoded = frame(&records);
                file.write_all(&encoded)?;
                bytes += encoded.len() as u64;
                records.clear();
            }
            if !records.is_empty() {
                let encoded = frame(&records);
                file.write_all(&encoded)?;
                bytes += encoded.len() as u64;
            }
            file.sync_all()?;
            fs::rename(&temp, self.directory.join(FILE_NAME))?;
            // Use the new inode even if directory sync fails; then poison writes.
            self.file = file;
            self.bytes = bytes;
            File::open(&self.directory)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn commit(&mut self, records: &[Record]) -> io::Result<()> {
        self.commit_with_sync(records, |file| file.sync_all())
    }

    fn commit_with_sync(
        &mut self,
        records: &[Record],
        sync: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "freshness writer failed; restart required",
            ));
        }
        if records.is_empty() || records.len() > MAX_BATCH {
            return Err(invalid("bad freshness commit size"));
        }
        let additions = records
            .iter()
            .map(|r| r.key)
            .filter(|key| !self.index.contains_key(key))
            .collect::<BTreeSet<_>>()
            .len();
        if self.index.len() + additions > MAX_KEYS {
            return Err(invalid("freshness key limit reached"));
        }
        let encoded = frame(records);
        let result = (|| {
            let compact_at = COMPACT_MIN.max(self.index.len() as u64 * RECORD_BYTES as u64 * 3);
            if self.bytes + encoded.len() as u64 > MAX_BYTES || self.bytes > compact_at {
                self.compact()?;
            }
            if self.bytes + encoded.len() as u64 > MAX_BYTES {
                return Err(invalid("freshness byte limit reached"));
            }
            self.file.write_all(&encoded)?;
            sync(&self.file)?;
            self.bytes += encoded.len() as u64;
            // This index is the acknowledgement boundary: never expose an
            // un-synced record to a same-process restore or return success.
            for record in records {
                apply(&mut self.index, *record);
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

struct Request {
    persistence: ZonePersistence,
    origin: DomainName,
    serial: Option<u32>,
    observed: u64,
    reply: oneshot::Sender<Result<(), String>>,
}

#[derive(Debug)]
pub(super) struct Batcher {
    sender: Option<mpsc::Sender<Request>>,
    worker: Option<JoinHandle<()>>,
    journal: Arc<Mutex<Journal>>,
}

impl Batcher {
    pub(super) fn open(directory: &Path) -> io::Result<Self> {
        let journal = Arc::new(Mutex::new(Journal::open(directory)?));
        let (sender, mut receiver) = mpsc::channel::<Request>(MAX_BATCH);
        let state = journal.clone();
        let worker = thread::Builder::new()
            .name("boron-freshness".into())
            .spawn(move || {
                while let Some(first) = receiver.blocking_recv() {
                    // Only this dedicated writer sleeps; no Tokio runtime worker
                    // waits on disk or spends a blocking-pool thread per refresh.
                    thread::sleep(Duration::from_millis(2));
                    let mut requests = Vec::with_capacity(MAX_BATCH);
                    requests.push(first);
                    while requests.len() < MAX_BATCH {
                        match receiver.try_recv() {
                            Ok(request) => requests.push(request),
                            Err(_) => break,
                        }
                    }
                    let mut records = Vec::with_capacity(requests.len());
                    let mut replies = Vec::with_capacity(requests.len());
                    for request in requests {
                        match request.persistence.active_cache_checksum(&request.origin) {
                            Ok(checksum) => {
                                records.push(Record {
                                    key: cache_key(&request.persistence, &request.origin),
                                    checksum,
                                    serial: request.serial,
                                    observed: request.observed,
                                });
                                replies.push(request.reply);
                            }
                            Err(error) => {
                                let _ = request.reply.send(Err(error.to_string()));
                            }
                        }
                    }
                    if records.is_empty() {
                        continue;
                    }
                    let result = state
                        .lock()
                        .map_err(|_| "freshness writer panicked".to_owned())
                        .and_then(|mut journal| {
                            journal.commit(&records).map_err(|error| error.to_string())
                        });
                    for reply in replies {
                        let _ = reply.send(result.clone());
                    }
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            journal,
        })
    }

    pub(super) async fn renew(
        &self,
        persistence: &ZonePersistence,
        origin: &DomainName,
        serial: Option<u32>,
        observed: u64,
    ) -> Result<(), String> {
        let (reply, result) = oneshot::channel();
        // The queued context must not retain the writer's sender: otherwise
        // the final context could drop/join its own worker during shutdown.
        let context = ZonePersistence {
            directory: persistence.directory.clone(),
            max_file_bytes: persistence.max_file_bytes,
            binding: persistence.binding,
            freshness_batch: Default::default(),
        };
        self.sender
            .as_ref()
            .unwrap()
            .send(Request {
                persistence: context,
                origin: origin.clone(),
                serial,
                observed,
                reply,
            })
            .await
            .map_err(|_| "freshness writer stopped".to_owned())?;
        result
            .await
            .map_err(|_| "freshness writer stopped before durable acknowledgement".to_owned())?
    }

    pub(super) fn read(
        &self,
        persistence: &ZonePersistence,
        origin: &DomainName,
        serial: Option<u32>,
        checksum: &[u8; 32],
    ) -> Option<u64> {
        let state = self.journal.lock().ok()?;
        let record = state.index.get(&cache_key(persistence, origin))?;
        (record.serial == serial && &record.checksum == checksum).then_some(record.observed)
    }
}

impl Drop for Batcher {
    fn drop(&mut self) {
        self.sender.take(); // drain already accepted requests, then close
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "borondns-freshness-journal-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        root
    }
    fn record(id: u8, time: u64) -> Record {
        Record {
            key: [id; 32],
            checksum: [id.wrapping_add(1); 32],
            serial: Some(7),
            observed: time,
        }
    }

    #[test]
    fn one_sync_covers_a_whole_batch_and_replays_every_record() {
        let root = directory();
        let mut journal = Journal::open(&root).unwrap();
        let records: Vec<_> = (0..=255).map(|id| record(id, 123)).collect();
        let mut syncs = 0;
        journal
            .commit_with_sync(&records, |file| {
                syncs += 1;
                file.sync_all()
            })
            .unwrap();
        assert_eq!(syncs, 1);
        assert_eq!(journal.index.len(), 256);
        drop(journal);
        let replayed = Journal::open(&root).unwrap();
        for record in records {
            assert_eq!(replayed.index.get(&record.key), Some(&record));
        }
        drop(replayed);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sync_failure_never_publishes_or_allows_another_commit() {
        let root = directory();
        let mut journal = Journal::open(&root).unwrap();
        let old = record(1, 10);
        journal.commit(&[old]).unwrap();
        assert!(
            journal
                .commit_with_sync(&[record(1, 20)], |_| Err(io::Error::other(
                    "injected sync failure"
                )))
                .is_err()
        );
        assert_eq!(journal.index.get(&old.key), Some(&old));
        assert!(journal.commit(&[record(2, 30)]).is_err());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_torn_tail_keeps_prior_commits_and_allows_a_new_durable_batch() {
        let root = directory();
        let old = record(1, 10);
        let next = record(2, 20);
        let first = frame(&[old]);
        let tail = frame(&[next]);
        for cut in 0..tail.len() {
            let mut bytes = first.clone();
            bytes.extend_from_slice(&tail[..cut]);
            fs::write(root.join(FILE_NAME), bytes).unwrap();
            let mut journal = Journal::open(&root).unwrap();
            assert_eq!(journal.index.len(), 1, "cut {cut}");
            assert_eq!(journal.index.get(&old.key), Some(&old));
            assert_eq!(journal.bytes, first.len() as u64);
            journal.commit(&[next]).unwrap();
            drop(journal);
            let journal = Journal::open(&root).unwrap();
            assert_eq!(journal.index.get(&next.key), Some(&next));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checksum_corruption_and_unbounded_frame_count_are_not_skipped() {
        let root = directory();
        let original = frame(&[record(1, 10)]);
        for offset in [0, 12, 44, 77, original.len() - 1] {
            let mut bytes = original.clone();
            bytes[offset] ^= 1;
            bytes.extend_from_slice(&original);
            fs::write(root.join(FILE_NAME), bytes).unwrap();
            assert!(Journal::open(&root).is_err(), "offset {offset}");
        }
        let mut bytes = original;
        bytes[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        fs::write(root.join(FILE_NAME), bytes).unwrap();
        assert!(Journal::open(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compaction_retains_latest_proofs_and_append_position() {
        let root = directory();
        let mut journal = Journal::open(&root).unwrap();
        journal.commit(&[record(1, 10), record(2, 20)]).unwrap();
        journal.commit(&[record(1, 30)]).unwrap();
        let original = journal.bytes;
        journal.compact().unwrap();
        assert!(journal.bytes < original);
        journal.commit(&[record(3, 40)]).unwrap();
        drop(journal);
        let recovered = Journal::open(&root).unwrap();
        assert_eq!(recovered.index.len(), 3);
        for record in [record(1, 30), record(2, 20), record(3, 40)] {
            assert_eq!(recovered.index.get(&record.key), Some(&record));
        }
        drop(recovered);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn automatic_compaction_bounds_repeated_renewals_and_replays_them() {
        let root = directory();
        let mut journal = Journal::open(&root).unwrap();
        for observed in 1..=100 {
            let records: Vec<_> = (0..=255).map(|id| record(id, observed)).collect();
            journal.commit(&records).unwrap();
            assert!(journal.bytes <= COMPACT_MIN + frame(&records).len() as u64);
        }
        drop(journal);
        let recovered = Journal::open(&root).unwrap();
        assert_eq!(recovered.index.len(), 256);
        assert!(
            recovered
                .index
                .values()
                .all(|record| record.observed == 100)
        );
        drop(recovered);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_journal_and_commit_are_rejected_before_processing() {
        let root = directory();
        let mut journal = Journal::open(&root).unwrap();
        assert!(journal.commit(&[]).is_err());
        assert!(journal.commit(&vec![record(1, 10); MAX_BATCH + 1]).is_err());
        assert_eq!(journal.bytes, 0);
        journal.file.set_len(MAX_BYTES + 1).unwrap();
        drop(journal);
        assert!(Journal::open(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cancelled_reply_and_missing_cache_do_not_kill_the_writer() {
        let root = directory();
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let snapshot = super::super::tests::snapshot();
        persistence.persist(&snapshot).unwrap();
        let batcher = Batcher::open(&root).unwrap();
        let (reply, cancelled) = oneshot::channel();
        drop(cancelled);
        batcher
            .sender
            .as_ref()
            .unwrap()
            .send(Request {
                persistence: persistence.clone(),
                origin: snapshot.origin().clone(),
                serial: snapshot.serial(),
                observed: 100,
                reply,
            })
            .await
            .unwrap();
        let missing = DomainName::from_absolute_str("missing.test.").unwrap();
        assert!(
            batcher
                .renew(&persistence, &missing, Some(7), 100)
                .await
                .is_err()
        );
        batcher
            .renew(&persistence, snapshot.origin(), snapshot.serial(), 101)
            .await
            .unwrap();
        let checksum = persistence
            .active_cache_checksum(snapshot.origin())
            .unwrap();
        assert_eq!(
            batcher.read(
                &persistence,
                snapshot.origin(),
                snapshot.serial(),
                &checksum
            ),
            Some(101)
        );
        drop(batcher);
        drop(persistence);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_observations_cannot_move_freshness_backwards() {
        let root = directory();
        let mut journal = Journal::open(&root).unwrap();
        journal.commit(&[record(1, 30), record(1, 10)]).unwrap();
        drop(journal);
        let recovered = Journal::open(&root).unwrap();
        assert_eq!(recovered.index.get(&[1; 32]), Some(&record(1, 30)));
        drop(recovered);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn writer_lock_and_unsafe_file_types_fail_closed() {
        use std::os::unix::fs::symlink;
        let root = directory();
        let journal = Journal::open(&root).unwrap();
        assert!(Journal::open(&root).is_err());
        drop(journal);
        let moved = root.join("old-journal");
        fs::rename(root.join(FILE_NAME), &moved).unwrap();
        symlink(&moved, root.join(FILE_NAME)).unwrap();
        assert!(Journal::open(&root).is_err());
        fs::remove_file(root.join(FILE_NAME)).unwrap();
        fs::hard_link(&moved, root.join(FILE_NAME)).unwrap();
        assert!(Journal::open(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_requires_matching_namespace_serial_and_content_checksum() {
        let root = directory();
        let persistence = ZonePersistence::new(root.clone(), 1024);
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let mut journal = Journal::open(&root).unwrap();
        let proof = Record {
            key: cache_key(&persistence, &origin),
            ..record(1, 100)
        };
        journal.commit(&[proof]).unwrap();
        drop(journal);
        let batcher = Batcher::open(&root).unwrap();
        assert_eq!(
            batcher.read(&persistence, &origin, Some(7), &proof.checksum),
            Some(100)
        );
        assert_eq!(
            batcher.read(&persistence, &origin, Some(8), &proof.checksum),
            None
        );
        assert_eq!(
            batcher.read(&persistence, &origin, None, &proof.checksum),
            None
        );
        assert_eq!(
            batcher.read(&persistence, &origin, Some(7), &[99; 32]),
            None
        );
        let different = DomainName::from_absolute_str("other.test.").unwrap();
        assert_eq!(
            batcher.read(&persistence, &different, Some(7), &proof.checksum),
            None
        );
        drop(batcher);
        fs::remove_dir_all(root).unwrap();
    }
}
