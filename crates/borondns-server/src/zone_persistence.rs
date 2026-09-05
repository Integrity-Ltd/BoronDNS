use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use borondns_core::{
    axfr::{AxfrError, validate_persisted_zone_delta, validated_persisted_zone_snapshot},
    dns::DomainName,
    zone::{PersistenceRrsetChange, ResourceRecord, Rrset, ZoneSnapshot},
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"BORONZ01";
const FRESHNESS_MAGIC: &[u8; 8] = b"BORONF01";
const JOURNAL_MAGIC: &[u8; 8] = b"BORONJ01";
const MAX_RECORDS: u64 = u32::MAX as u64;
const MIN_RECORD_BYTES: u64 = 13;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JOURNAL_ENTRIES: u32 = 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub(crate) enum ZonePersistenceError {
    #[error("last-good zone cache I/O failed for {path}: {source}")]
    Io { path: String, source: io::Error },
    #[error("last-good zone cache {path} is malformed: {reason}")]
    Malformed { path: String, reason: String },
    #[error("last-good zone cache {path} failed zone validation: {source}")]
    InvalidZone { path: String, source: AxfrError },
}

#[derive(Debug, Clone)]
pub(crate) struct ZonePersistence {
    directory: PathBuf,
    max_file_bytes: u64,
}

pub(crate) struct RestoredZone {
    pub(crate) snapshot: ZoneSnapshot,
    pub(crate) persisted_unix_secs: u64,
}

struct JournalEntry {
    old_serial: u32,
    new_serial: u32,
    persisted_unix_secs: u64,
    changes: Vec<PersistenceRrsetChange>,
}

struct DecodedJournal {
    base_checksum: [u8; 32],
    base_serial: u32,
    entries: Vec<JournalEntry>,
}

pub(crate) struct StagedZoneCache {
    persistence: ZonePersistence,
    origin: DomainName,
    temp_path: PathBuf,
    final_path: PathBuf,
    remove_journal: bool,
    promoted: bool,
}

impl StagedZoneCache {
    pub(crate) fn promote(mut self) -> Result<(), ZonePersistenceError> {
        fs::rename(&self.temp_path, &self.final_path)
            .map_err(|source| self.persistence.io_error(&self.final_path, source))?;
        self.promoted = true;
        if self.remove_journal {
            match fs::remove_file(self.persistence.journal_path_for(&self.origin)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => return Err(self.persistence.io_error(&self.final_path, source)),
            }
        }
        match fs::remove_file(self.persistence.freshness_path_for(&self.origin)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(self.persistence.io_error(&self.final_path, source)),
        }
        File::open(&self.persistence.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| {
                self.persistence
                    .io_error(&self.persistence.directory, source)
            })
    }
}

impl Drop for StagedZoneCache {
    fn drop(&mut self) {
        if !self.promoted {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

impl ZonePersistence {
    pub(crate) fn new(directory: PathBuf, max_file_bytes: u64) -> Self {
        Self {
            directory,
            max_file_bytes,
        }
    }

    #[cfg(test)]
    pub(crate) fn persist(&self, snapshot: &ZoneSnapshot) -> Result<(), ZonePersistenceError> {
        self.stage(snapshot)?.promote()
    }

    pub(crate) fn stage(
        &self,
        snapshot: &ZoneSnapshot,
    ) -> Result<StagedZoneCache, ZonePersistenceError> {
        fs::create_dir_all(&self.directory)
            .map_err(|source| self.io_error(&self.directory, source))?;
        let final_path = self.path_for(snapshot.origin());
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = self.directory.join(format!(
            ".{}.tmp.{}.{}",
            final_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("zone"),
            std::process::id(),
            sequence
        ));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let file = options
                .open(&temp_path)
                .map_err(|source| self.io_error(&temp_path, source))?;
            let mut writer = BufWriter::new(file);
            let mut digest = Sha256::new();
            write_hashed(&mut writer, &mut digest, MAGIC, &temp_path, self)?;
            let origin_wire = snapshot.origin().to_wire();
            write_hashed(
                &mut writer,
                &mut digest,
                &(origin_wire.len() as u16).to_be_bytes(),
                &temp_path,
                self,
            )?;
            write_hashed(&mut writer, &mut digest, &origin_wire, &temp_path, self)?;
            match snapshot.serial() {
                Some(serial) => {
                    write_hashed(&mut writer, &mut digest, &[1], &temp_path, self)?;
                    write_hashed(
                        &mut writer,
                        &mut digest,
                        &serial.to_be_bytes(),
                        &temp_path,
                        self,
                    )?;
                }
                None => write_hashed(&mut writer, &mut digest, &[0], &temp_path, self)?,
            }
            let persisted_unix_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            write_hashed(
                &mut writer,
                &mut digest,
                &persisted_unix_secs.to_be_bytes(),
                &temp_path,
                self,
            )?;
            let count = snapshot.persistence_record_count();
            if count > MAX_RECORDS {
                return Err(self.malformed(&temp_path, "record count exceeds format limit"));
            }
            write_hashed(
                &mut writer,
                &mut digest,
                &count.to_be_bytes(),
                &temp_path,
                self,
            )?;
            let mut write_error = None;
            snapshot.visit_persistence_records(|owner, rr_type, class, ttl, rdata| {
                if write_error.is_some() {
                    return;
                }
                write_error = write_record(
                    &mut writer,
                    &mut digest,
                    owner,
                    rr_type,
                    class,
                    ttl,
                    rdata,
                    &temp_path,
                    self,
                )
                .err();
            });
            if let Some(error) = write_error {
                return Err(error);
            }
            writer
                .write_all(&digest.finalize())
                .map_err(|source| self.io_error(&temp_path, source))?;
            writer
                .flush()
                .map_err(|source| self.io_error(&temp_path, source))?;
            if writer
                .get_ref()
                .metadata()
                .map_err(|source| self.io_error(&temp_path, source))?
                .len()
                > self.max_file_bytes
            {
                return Err(self.malformed(
                    &temp_path,
                    "serialized zone exceeds the configured derived cache safety limit",
                ));
            }
            writer
                .get_ref()
                .sync_all()
                .map_err(|source| self.io_error(&temp_path, source))?;
            Ok(StagedZoneCache {
                persistence: self.clone(),
                origin: snapshot.origin().clone(),
                temp_path: temp_path.clone(),
                final_path,
                remove_journal: true,
                promoted: false,
            })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    /// Stage only the RRsets changed by a directly-descended IXFR snapshot.
    /// The bounded journal is rewritten and fsynced outside publication locks;
    /// promotion only atomically replaces that small journal file.
    pub(crate) fn stage_incremental(
        &self,
        previous: &ZoneSnapshot,
        snapshot: &ZoneSnapshot,
    ) -> Result<StagedZoneCache, ZonePersistenceError> {
        let Some(old_serial) = previous.serial() else {
            return self.stage(snapshot);
        };
        let Some(new_serial) = snapshot.serial() else {
            return self.stage(snapshot);
        };
        let Some(changes) = snapshot.persistence_changes_from(previous) else {
            return self.stage(snapshot);
        };
        let base_path = self.path_for(snapshot.origin());
        if !base_path.exists() {
            return self.stage(snapshot);
        }
        let base_checksum = self.cache_checksum(&base_path)?;
        let journal_path = self.journal_path_for(snapshot.origin());
        let (mut bytes, entries, current_serial) = match fs::symlink_metadata(&journal_path) {
            Ok(_) => {
                let (bytes, decoded, _) = self.read_journal_bytes(snapshot.origin())?;
                if decoded.base_checksum != base_checksum {
                    return self.stage(snapshot);
                }
                let current_serial = decoded
                    .entries
                    .last()
                    .map_or(decoded.base_serial, |entry| entry.new_serial);
                (bytes, decoded.entries.len() as u32, current_serial)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(JOURNAL_MAGIC);
                let origin_wire = snapshot.origin().to_wire();
                bytes.extend_from_slice(&(origin_wire.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&origin_wire);
                bytes.extend_from_slice(&base_checksum);
                bytes.extend_from_slice(&old_serial.to_be_bytes());
                bytes.extend_from_slice(&0u32.to_be_bytes());
                (bytes, 0, old_serial)
            }
            Err(source) => return Err(self.io_error(&journal_path, source)),
        };
        if current_serial != old_serial || entries >= MAX_JOURNAL_ENTRIES {
            return self.stage(snapshot);
        }
        let count_offset = JOURNAL_MAGIC.len() + 2 + snapshot.origin().to_wire().len() + 32 + 4;
        bytes[count_offset..count_offset + 4].copy_from_slice(&(entries + 1).to_be_bytes());
        encode_journal_entry(&mut bytes, old_serial, new_serial, &changes)
            .map_err(|reason| self.malformed(&journal_path, reason))?;
        let digest = Sha256::digest(&bytes);
        bytes.extend_from_slice(&digest);
        if bytes.len() as u64 > self.max_file_bytes.min(MAX_JOURNAL_BYTES) {
            return self.stage(snapshot);
        }
        fs::create_dir_all(&self.directory)
            .map_err(|source| self.io_error(&self.directory, source))?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = self.directory.join(format!(
            ".{}.tmp.{}.{}",
            journal_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("zone-journal"),
            std::process::id(),
            sequence
        ));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options
                .open(&temp_path)
                .map_err(|source| self.io_error(&temp_path, source))?;
            file.write_all(&bytes)
                .map_err(|source| self.io_error(&temp_path, source))?;
            file.sync_all()
                .map_err(|source| self.io_error(&temp_path, source))?;
            Ok(StagedZoneCache {
                persistence: self.clone(),
                origin: snapshot.origin().clone(),
                temp_path: temp_path.clone(),
                final_path: journal_path,
                remove_journal: false,
                promoted: false,
            })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    pub(crate) fn restore(
        &self,
        expected_origin: &DomainName,
        qclass: u16,
    ) -> Result<Option<RestoredZone>, ZonePersistenceError> {
        let path = self.path_for(expected_origin);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(self.io_error(&path, source)),
        };
        if !metadata.file_type().is_file() || metadata.len() > self.max_file_bytes {
            return Err(self.malformed(&path, "not a bounded regular file"));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .map_err(|source| self.io_error(&path, source))?;
        let opened_metadata = file
            .metadata()
            .map_err(|source| self.io_error(&path, source))?;
        if !opened_metadata.file_type().is_file()
            || opened_metadata.len() != metadata.len()
            || opened_metadata.len() > self.max_file_bytes
        {
            return Err(self.malformed(&path, "cache file changed while opening"));
        }
        let mut reader = HashingReader::new(BufReader::new(file));
        expect_bytes(&mut reader, MAGIC, &path, self)?;
        let origin_len = read_u16(&mut reader, &path, self)? as usize;
        if origin_len == 0 || origin_len > 255 {
            return Err(self.malformed(&path, "invalid origin length"));
        }
        let origin_wire = read_vec(&mut reader, origin_len, &path, self)?;
        let (origin, consumed) = DomainName::parse(&origin_wire, 0)
            .map_err(|_| self.malformed(&path, "invalid origin wire name"))?;
        if consumed != origin_wire.len()
            || origin.canonical_key() != expected_origin.canonical_key()
        {
            return Err(self.malformed(&path, "cache origin does not match configured zone"));
        }
        let serial = match read_u8(&mut reader, &path, self)? {
            0 => None,
            1 => Some(read_u32(&mut reader, &path, self)?),
            _ => return Err(self.malformed(&path, "invalid serial presence marker")),
        };
        let persisted_unix_secs = read_u64(&mut reader, &path, self)?;
        let count = read_u64(&mut reader, &path, self)?;
        if count > MAX_RECORDS {
            return Err(self.malformed(&path, "record count exceeds format limit"));
        }
        if count > opened_metadata.len() / MIN_RECORD_BYTES {
            return Err(self.malformed(&path, "record count cannot fit in cache file"));
        }
        // The count is untrusted until the checksum and zone are validated. Do
        // not let a tiny forged file request a multi-gigabyte allocation.
        let mut records = Vec::new();
        for _ in 0..count {
            records.push(read_record(&mut reader, &path, self)?);
        }
        let computed = reader.digest.clone().finalize();
        let mut inner = reader.into_inner();
        let mut stored = [0u8; 32];
        inner
            .read_exact(&mut stored)
            .map_err(|source| self.io_error(&path, source))?;
        if computed.as_slice() != stored {
            return Err(self.malformed(&path, "checksum mismatch"));
        }
        let mut trailing = [0u8; 1];
        if inner
            .read(&mut trailing)
            .map_err(|source| self.io_error(&path, source))?
            != 0
        {
            return Err(self.malformed(&path, "trailing bytes"));
        }
        let mut snapshot = validated_persisted_zone_snapshot(&origin, qclass, serial, records)
            .map_err(|source| ZonePersistenceError::InvalidZone {
                path: path.display().to_string(),
                source,
            })?;
        let mut active_checksum = stored;
        let mut effective_persisted_unix_secs = persisted_unix_secs;
        let journal_path = self.journal_path_for(&origin);
        match fs::symlink_metadata(&journal_path) {
            Ok(_) => {
                let (_, decoded, journal_checksum) = self.read_journal_bytes(&origin)?;
                // A full-checkpoint promotion replaces the base before it
                // removes the old journal. If the process stops in between,
                // the independently valid journal is stale rather than a
                // reason to hide the newly durable checkpoint.
                if decoded.base_checksum == stored {
                    if snapshot.serial() != Some(decoded.base_serial) {
                        return Err(self.malformed(&journal_path, "journal base serial mismatch"));
                    }
                    for entry in decoded.entries {
                        if snapshot.serial() != Some(entry.old_serial) {
                            return Err(
                                self.malformed(&journal_path, "journal serial chain mismatch")
                            );
                        }
                        let updated = snapshot
                            .with_persistence_changes(entry.new_serial, entry.changes.clone());
                        validate_persisted_zone_delta(
                            &origin,
                            qclass,
                            &snapshot,
                            &updated,
                            &entry.changes,
                        )
                        .map_err(|source| {
                            ZonePersistenceError::InvalidZone {
                                path: journal_path.display().to_string(),
                                source,
                            }
                        })?;
                        snapshot = updated;
                        effective_persisted_unix_secs = entry.persisted_unix_secs;
                    }
                    active_checksum = journal_checksum;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(self.io_error(&journal_path, source)),
        }
        effective_persisted_unix_secs = self
            .read_freshness(&origin, snapshot.serial(), &active_checksum)
            .unwrap_or(effective_persisted_unix_secs)
            .max(effective_persisted_unix_secs);
        {
            let elapsed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(effective_persisted_unix_secs);
            let snapshot = if snapshot
                .soa_timers()
                .is_some_and(|timers| elapsed >= u64::from(timers.expire))
            {
                snapshot.with_state(borondns_core::zone::ZoneState::Expired)
            } else {
                snapshot
            };
            Ok(Some(RestoredZone {
                snapshot,
                persisted_unix_secs: effective_persisted_unix_secs,
            }))
        }
    }

    pub(crate) fn remove(&self, origin: &DomainName) -> Result<(), ZonePersistenceError> {
        let path = self.path_for(origin);
        let freshness_path = self.freshness_path_for(origin);
        let journal_path = self.journal_path_for(origin);
        let mut removed = false;
        for candidate in [&path, &freshness_path, &journal_path] {
            match fs::remove_file(candidate) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => return Err(self.io_error(candidate, source)),
            }
        }
        if removed {
            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| self.io_error(&self.directory, source))?;
        }
        Ok(())
    }

    pub(crate) fn renew_freshness(
        &self,
        origin: &DomainName,
        serial: Option<u32>,
    ) -> Result<(), ZonePersistenceError> {
        let final_path = self.path_for(origin);
        let base_checksum = self.cache_checksum(&final_path)?;
        let journal_path = self.journal_path_for(origin);
        let cache_checksum = match fs::symlink_metadata(&journal_path) {
            Ok(_) => {
                let (_, decoded, journal_checksum) = self.read_journal_bytes(origin)?;
                if decoded.base_checksum == base_checksum {
                    journal_checksum
                } else {
                    base_checksum
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => base_checksum,
            Err(source) => return Err(self.io_error(&journal_path, source)),
        };
        let refreshed_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let freshness_path = self.freshness_path_for(origin);
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = self.directory.join(format!(
            ".{}.tmp.{}.{}",
            freshness_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("freshness"),
            std::process::id(),
            sequence
        ));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let file = options
                .open(&temp_path)
                .map_err(|source| self.io_error(&temp_path, source))?;
            let mut writer = BufWriter::new(file);
            let mut digest = Sha256::new();
            write_hashed(&mut writer, &mut digest, FRESHNESS_MAGIC, &temp_path, self)?;
            match serial {
                Some(serial) => {
                    write_hashed(&mut writer, &mut digest, &[1], &temp_path, self)?;
                    write_hashed(
                        &mut writer,
                        &mut digest,
                        &serial.to_be_bytes(),
                        &temp_path,
                        self,
                    )?;
                }
                None => write_hashed(&mut writer, &mut digest, &[0], &temp_path, self)?,
            }
            write_hashed(&mut writer, &mut digest, &cache_checksum, &temp_path, self)?;
            write_hashed(
                &mut writer,
                &mut digest,
                &refreshed_unix_secs.to_be_bytes(),
                &temp_path,
                self,
            )?;
            writer
                .write_all(&digest.finalize())
                .map_err(|source| self.io_error(&temp_path, source))?;
            writer
                .flush()
                .map_err(|source| self.io_error(&temp_path, source))?;
            writer
                .get_ref()
                .sync_all()
                .map_err(|source| self.io_error(&temp_path, source))?;
            fs::rename(&temp_path, &freshness_path)
                .map_err(|source| self.io_error(&freshness_path, source))?;
            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| self.io_error(&self.directory, source))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn path_for(&self, origin: &DomainName) -> PathBuf {
        let digest = Sha256::digest(origin.canonical_key().as_bytes());
        let name = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        self.directory.join(format!("{name}.bdz"))
    }

    fn freshness_path_for(&self, origin: &DomainName) -> PathBuf {
        self.path_for(origin).with_extension("fresh")
    }

    fn journal_path_for(&self, origin: &DomainName) -> PathBuf {
        self.path_for(origin).with_extension("bdj")
    }

    fn read_journal_bytes(
        &self,
        origin: &DomainName,
    ) -> Result<(Vec<u8>, DecodedJournal, [u8; 32]), ZonePersistenceError> {
        let path = self.journal_path_for(origin);
        let maximum = self.max_file_bytes.min(MAX_JOURNAL_BYTES);
        let mut file = self.open_bounded_regular(&path, 32, maximum)?;
        let length = file
            .metadata()
            .map_err(|source| self.io_error(&path, source))?
            .len() as usize;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)
            .map_err(|source| self.io_error(&path, source))?;
        if bytes.len() < 32 {
            return Err(self.malformed(&path, "journal is shorter than its checksum"));
        }
        let checksum_at = bytes.len() - 32;
        let computed = Sha256::digest(&bytes[..checksum_at]);
        if computed.as_slice() != &bytes[checksum_at..] {
            return Err(self.malformed(&path, "journal checksum mismatch"));
        }
        let checksum = bytes[checksum_at..]
            .try_into()
            .expect("journal checksum has exact length");
        bytes.truncate(checksum_at);
        let decoded =
            decode_journal(&bytes, origin).map_err(|reason| self.malformed(&path, reason))?;
        Ok((bytes, decoded, checksum))
    }

    fn cache_checksum(&self, path: &Path) -> Result<[u8; 32], ZonePersistenceError> {
        let mut file = self.open_bounded_regular(path, 32, self.max_file_bytes)?;
        file.seek(SeekFrom::End(-32))
            .map_err(|source| self.io_error(path, source))?;
        let mut checksum = [0u8; 32];
        file.read_exact(&mut checksum)
            .map_err(|source| self.io_error(path, source))?;
        Ok(checksum)
    }

    fn read_freshness(
        &self,
        origin: &DomainName,
        expected_serial: Option<u32>,
        expected_cache_checksum: &[u8; 32],
    ) -> Option<u64> {
        let path = self.freshness_path_for(origin);
        let payload_len =
            FRESHNESS_MAGIC.len() + 1 + if expected_serial.is_some() { 4 } else { 0 } + 32 + 8;
        let expected_len = payload_len + 32;
        let mut file = self
            .open_bounded_regular(&path, expected_len as u64, expected_len as u64)
            .ok()?;
        let mut bytes = vec![0; expected_len];
        file.read_exact(&mut bytes).ok()?;
        let mut trailing = [0u8; 1];
        if file.read(&mut trailing).ok()? != 0 || &bytes[..8] != FRESHNESS_MAGIC {
            return None;
        }
        let mut offset = 8;
        let serial = match bytes[offset] {
            0 => {
                offset += 1;
                None
            }
            1 => {
                offset += 1;
                let value = u32::from_be_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
                offset += 4;
                Some(value)
            }
            _ => return None,
        };
        if serial != expected_serial || bytes.get(offset..offset + 32)? != expected_cache_checksum {
            return None;
        }
        offset += 32;
        let refreshed = u64::from_be_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?);
        offset += 8;
        let checksum = Sha256::digest(&bytes[..offset]);
        (checksum.as_slice() == bytes.get(offset..offset + 32)?).then_some(refreshed)
    }

    fn open_bounded_regular(
        &self,
        path: &Path,
        minimum: u64,
        maximum: u64,
    ) -> Result<File, ZonePersistenceError> {
        let before = fs::symlink_metadata(path).map_err(|source| self.io_error(path, source))?;
        if !before.file_type().is_file() || before.len() < minimum || before.len() > maximum {
            return Err(self.malformed(path, "not a bounded regular file"));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let file = options
            .open(path)
            .map_err(|source| self.io_error(path, source))?;
        let opened = file
            .metadata()
            .map_err(|source| self.io_error(path, source))?;
        if !opened.file_type().is_file()
            || opened.len() < minimum
            || opened.len() > maximum
            || opened.len() != before.len()
        {
            return Err(self.malformed(path, "file changed while opening"));
        }
        #[cfg(unix)]
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err(self.malformed(path, "file changed while opening"));
        }
        Ok(file)
    }

    fn io_error(&self, path: &Path, source: io::Error) -> ZonePersistenceError {
        ZonePersistenceError::Io {
            path: path.display().to_string(),
            source,
        }
    }

    fn malformed(&self, path: &Path, reason: impl Into<String>) -> ZonePersistenceError {
        ZonePersistenceError::Malformed {
            path: path.display().to_string(),
            reason: reason.into(),
        }
    }
}

fn encode_journal_entry(
    output: &mut Vec<u8>,
    old_serial: u32,
    new_serial: u32,
    changes: &[PersistenceRrsetChange],
) -> Result<(), &'static str> {
    output.extend_from_slice(&old_serial.to_be_bytes());
    output.extend_from_slice(&new_serial.to_be_bytes());
    output.extend_from_slice(
        &SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_be_bytes(),
    );
    let count = u32::try_from(changes.len()).map_err(|_| "too many changed RRsets")?;
    output.extend_from_slice(&count.to_be_bytes());
    for change in changes {
        let owner = change.owner.to_wire();
        let owner_len = u16::try_from(owner.len()).map_err(|_| "journal owner is too long")?;
        output.extend_from_slice(&owner_len.to_be_bytes());
        output.extend_from_slice(&owner);
        output.extend_from_slice(&change.rr_type.to_be_bytes());
        output.extend_from_slice(&change.class.to_be_bytes());
        match &change.replacement {
            None => output.push(0),
            Some(rrset) => {
                output.push(1);
                output.extend_from_slice(&rrset.ttl.to_be_bytes());
                let rdata_count = u32::try_from(rrset.persistence_rdatas().count())
                    .map_err(|_| "journal RRset has too many records")?;
                if rdata_count == 0 {
                    return Err("journal replacement RRset is empty");
                }
                output.extend_from_slice(&rdata_count.to_be_bytes());
                for rdata in rrset.persistence_rdatas() {
                    let length =
                        u16::try_from(rdata.len()).map_err(|_| "journal RDATA is too long")?;
                    output.extend_from_slice(&length.to_be_bytes());
                    output.extend_from_slice(rdata);
                }
            }
        }
    }
    Ok(())
}

fn decode_journal(
    bytes: &[u8],
    expected_origin: &DomainName,
) -> Result<DecodedJournal, &'static str> {
    let mut cursor = Cursor::new(bytes);
    if take_bytes(&mut cursor, JOURNAL_MAGIC.len())? != JOURNAL_MAGIC {
        return Err("invalid journal magic");
    }
    let owner_len = take_u16(&mut cursor)? as usize;
    if owner_len == 0 || owner_len > 255 {
        return Err("invalid journal origin length");
    }
    let owner_wire = take_bytes(&mut cursor, owner_len)?;
    let (origin, consumed) =
        DomainName::parse(&owner_wire, 0).map_err(|_| "invalid journal origin")?;
    if consumed != owner_wire.len() || origin.canonical_key() != expected_origin.canonical_key() {
        return Err("journal origin mismatch");
    }
    let base_checksum = take_bytes(&mut cursor, 32)?
        .try_into()
        .expect("journal base checksum has exact length");
    let base_serial = take_u32(&mut cursor)?;
    let entry_count = take_u32(&mut cursor)?;
    if entry_count > MAX_JOURNAL_ENTRIES {
        return Err("journal entry count exceeds limit");
    }
    let mut entries = Vec::with_capacity(entry_count as usize);
    let mut expected_serial = base_serial;
    for _ in 0..entry_count {
        let old_serial = take_u32(&mut cursor)?;
        let new_serial = take_u32(&mut cursor)?;
        if old_serial != expected_serial {
            return Err("journal serial chain mismatch");
        }
        let persisted_unix_secs = take_u64(&mut cursor)?;
        let change_count = take_u32(&mut cursor)?;
        if change_count as u64 > bytes.len() as u64 / MIN_RECORD_BYTES {
            return Err("journal change count cannot fit");
        }
        let mut changes = Vec::with_capacity(change_count as usize);
        let mut changed_rrsets = BTreeSet::new();
        for _ in 0..change_count {
            let owner_len = take_u16(&mut cursor)? as usize;
            if owner_len == 0 || owner_len > 255 {
                return Err("invalid journal owner length");
            }
            let owner_wire = take_bytes(&mut cursor, owner_len)?;
            let (owner, consumed) =
                DomainName::parse(&owner_wire, 0).map_err(|_| "invalid journal owner")?;
            if consumed != owner_wire.len() {
                return Err("trailing journal owner bytes");
            }
            let rr_type = take_u16(&mut cursor)?;
            let class = take_u16(&mut cursor)?;
            if !changed_rrsets.insert((owner.canonical_key(), rr_type, class)) {
                return Err("duplicate journal RRset change");
            }
            let replacement = match take_u8(&mut cursor)? {
                0 => None,
                1 => {
                    let ttl = take_u32(&mut cursor)?;
                    let rdata_count = take_u32(&mut cursor)?;
                    if rdata_count == 0 {
                        return Err("journal replacement RRset is empty");
                    }
                    if rdata_count as u64 > bytes.len() as u64 / 2 {
                        return Err("journal RDATA count cannot fit");
                    }
                    let mut rdatas = Vec::with_capacity(rdata_count as usize);
                    for _ in 0..rdata_count {
                        let length = take_u16(&mut cursor)? as usize;
                        rdatas.push(take_bytes(&mut cursor, length)?);
                    }
                    Some(Rrset::new(owner.clone(), rr_type, class, ttl, rdatas))
                }
                _ => return Err("invalid journal replacement marker"),
            };
            changes.push(PersistenceRrsetChange {
                owner,
                rr_type,
                class,
                replacement,
            });
        }
        entries.push(JournalEntry {
            old_serial,
            new_serial,
            persisted_unix_secs,
            changes,
        });
        expected_serial = new_serial;
    }
    if cursor.position() != bytes.len() as u64 {
        return Err("trailing journal bytes");
    }
    Ok(DecodedJournal {
        base_checksum,
        base_serial,
        entries,
    })
}

fn take_bytes(cursor: &mut Cursor<&[u8]>, length: usize) -> Result<Vec<u8>, &'static str> {
    let position = cursor.position() as usize;
    let end = position
        .checked_add(length)
        .ok_or("journal length overflow")?;
    let bytes = cursor
        .get_ref()
        .get(position..end)
        .ok_or("truncated journal")?
        .to_vec();
    cursor.set_position(end as u64);
    Ok(bytes)
}

fn take_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, &'static str> {
    Ok(take_bytes(cursor, 1)?[0])
}

fn take_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, &'static str> {
    Ok(u16::from_be_bytes(
        take_bytes(cursor, 2)?.try_into().expect("exact length"),
    ))
}

fn take_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, &'static str> {
    Ok(u32::from_be_bytes(
        take_bytes(cursor, 4)?.try_into().expect("exact length"),
    ))
}

fn take_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, &'static str> {
    Ok(u64::from_be_bytes(
        take_bytes(cursor, 8)?.try_into().expect("exact length"),
    ))
}

#[allow(clippy::too_many_arguments)]
fn write_record(
    writer: &mut BufWriter<File>,
    digest: &mut Sha256,
    owner: &DomainName,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: &[u8],
    path: &Path,
    persistence: &ZonePersistence,
) -> Result<(), ZonePersistenceError> {
    let owner_wire = owner.to_wire();
    write_hashed(
        writer,
        digest,
        &(owner_wire.len() as u16).to_be_bytes(),
        path,
        persistence,
    )?;
    write_hashed(writer, digest, &owner_wire, path, persistence)?;
    write_hashed(writer, digest, &rr_type.to_be_bytes(), path, persistence)?;
    write_hashed(writer, digest, &class.to_be_bytes(), path, persistence)?;
    write_hashed(writer, digest, &ttl.to_be_bytes(), path, persistence)?;
    write_hashed(
        writer,
        digest,
        &(rdata.len() as u16).to_be_bytes(),
        path,
        persistence,
    )?;
    write_hashed(writer, digest, rdata, path, persistence)
}

fn write_hashed(
    writer: &mut BufWriter<File>,
    digest: &mut Sha256,
    bytes: &[u8],
    path: &Path,
    persistence: &ZonePersistence,
) -> Result<(), ZonePersistenceError> {
    writer
        .write_all(bytes)
        .map_err(|source| persistence.io_error(path, source))?;
    digest.update(bytes);
    Ok(())
}

struct HashingReader<R> {
    inner: R,
    digest: Sha256,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
        }
    }
    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.digest.update(&buffer[..read]);
        Ok(read)
    }
}

fn expect_bytes(
    reader: &mut impl Read,
    expected: &[u8],
    path: &Path,
    persistence: &ZonePersistence,
) -> Result<(), ZonePersistenceError> {
    let actual = read_vec(reader, expected.len(), path, persistence)?;
    (actual == expected)
        .then_some(())
        .ok_or_else(|| persistence.malformed(path, "invalid magic"))
}

fn read_record(
    reader: &mut impl Read,
    path: &Path,
    persistence: &ZonePersistence,
) -> Result<ResourceRecord, ZonePersistenceError> {
    let owner_len = read_u16(reader, path, persistence)? as usize;
    if owner_len == 0 || owner_len > 255 {
        return Err(persistence.malformed(path, "invalid owner length"));
    }
    let owner_wire = read_vec(reader, owner_len, path, persistence)?;
    let (owner, consumed) = DomainName::parse(&owner_wire, 0)
        .map_err(|_| persistence.malformed(path, "invalid owner wire name"))?;
    if consumed != owner_wire.len() {
        return Err(persistence.malformed(path, "trailing owner wire bytes"));
    }
    let rr_type = read_u16(reader, path, persistence)?;
    let class = read_u16(reader, path, persistence)?;
    let ttl = read_u32(reader, path, persistence)?;
    let rdata_len = read_u16(reader, path, persistence)? as usize;
    let rdata = read_vec(reader, rdata_len, path, persistence)?;
    Ok(ResourceRecord {
        owner,
        rr_type,
        class,
        ttl,
        rdata,
    })
}

fn read_vec(
    reader: &mut impl Read,
    len: usize,
    path: &Path,
    persistence: &ZonePersistence,
) -> Result<Vec<u8>, ZonePersistenceError> {
    let mut bytes = vec![0u8; len];
    reader
        .read_exact(&mut bytes)
        .map_err(|source| persistence.io_error(path, source))?;
    Ok(bytes)
}

fn read_u8(
    reader: &mut impl Read,
    path: &Path,
    persistence: &ZonePersistence,
) -> Result<u8, ZonePersistenceError> {
    Ok(read_vec(reader, 1, path, persistence)?[0])
}
fn read_u16(
    reader: &mut impl Read,
    path: &Path,
    persistence: &ZonePersistence,
) -> Result<u16, ZonePersistenceError> {
    let bytes = read_vec(reader, 2, path, persistence)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
fn read_u32(
    reader: &mut impl Read,
    path: &Path,
    persistence: &ZonePersistence,
) -> Result<u32, ZonePersistenceError> {
    let bytes = read_vec(reader, 4, path, persistence)?;
    Ok(u32::from_be_bytes(bytes.try_into().expect("exact length")))
}
fn read_u64(
    reader: &mut impl Read,
    path: &Path,
    persistence: &ZonePersistence,
) -> Result<u64, ZonePersistenceError> {
    let bytes = read_vec(reader, 8, path, persistence)?;
    Ok(u64::from_be_bytes(bytes.try_into().expect("exact length")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use borondns_core::{dns::RecordType, zone::Rrset};

    fn soa_rdata(serial: u32) -> Vec<u8> {
        let mut rdata = DomainName::from_absolute_str("ns.example.test.")
            .unwrap()
            .to_wire();
        rdata.extend(
            DomainName::from_absolute_str("hostmaster.example.test.")
                .unwrap()
                .to_wire(),
        );
        for value in [serial, 3600, 600, 604800, 300] {
            rdata.extend(value.to_be_bytes());
        }
        rdata
    }

    fn snapshot() -> ZoneSnapshot {
        ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(7),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata(7)],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![
                        DomainName::from_absolute_str("ns.example.test.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
            ],
        )
    }

    #[test]
    fn persists_and_restores_validated_last_good_zone() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-test-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let snapshot = snapshot();
        persistence.persist(&snapshot).unwrap();
        let restored = persistence.restore(snapshot.origin(), 1).unwrap().unwrap();
        assert_eq!(restored.snapshot.serial(), Some(7));
        assert_eq!(
            restored.snapshot.persistence_record_count(),
            snapshot.persistence_record_count()
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn incremented_snapshot(previous: &ZoneSnapshot, serial: u32) -> ZoneSnapshot {
        let owner = DomainName::from_absolute_str("ns.example.test.").unwrap();
        let apex = previous.origin().clone();
        previous.with_persistence_changes(
            serial,
            vec![
                PersistenceRrsetChange {
                    owner: apex.clone(),
                    rr_type: RecordType::Soa as u16,
                    class: 1,
                    replacement: Some(Rrset::new(
                        apex,
                        RecordType::Soa as u16,
                        1,
                        3600,
                        vec![soa_rdata(serial)],
                    )),
                },
                PersistenceRrsetChange {
                    owner: owner.clone(),
                    rr_type: RecordType::A as u16,
                    class: 1,
                    replacement: Some(Rrset::new(
                        owner,
                        RecordType::A as u16,
                        1,
                        300,
                        vec![vec![192, 0, 2, serial as u8]],
                    )),
                },
            ],
        )
    }

    #[test]
    fn incremental_stage_persists_small_journal_and_restores_latest_zone() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-journal-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let original = snapshot();
        persistence.persist(&original).unwrap();
        let updated = incremented_snapshot(&original, 8);

        persistence
            .stage_incremental(&original, &updated)
            .unwrap()
            .promote()
            .unwrap();

        assert!(
            fs::metadata(persistence.journal_path_for(original.origin()))
                .unwrap()
                .len()
                < 1024
        );
        let restored = persistence.restore(original.origin(), 1).unwrap().unwrap();
        assert_eq!(restored.snapshot.serial(), Some(8));
        assert_eq!(
            restored
                .snapshot
                .persistence_records()
                .into_iter()
                .find(|record| {
                    record.owner.canonical_key() == "ns.example.test."
                        && record.rr_type == RecordType::A as u16
                })
                .unwrap()
                .rdata,
            vec![192, 0, 2, 8]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn abandoned_incremental_stage_does_not_advance_restart_state() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-journal-abandon-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let original = snapshot();
        persistence.persist(&original).unwrap();
        let updated = incremented_snapshot(&original, 8);

        drop(persistence.stage_incremental(&original, &updated).unwrap());

        assert_eq!(
            persistence
                .restore(original.origin(), 1)
                .unwrap()
                .unwrap()
                .snapshot
                .serial(),
            Some(7)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_incremental_journal_is_rejected_without_partial_restore() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-journal-corrupt-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let original = snapshot();
        persistence.persist(&original).unwrap();
        let updated = incremented_snapshot(&original, 8);
        persistence
            .stage_incremental(&original, &updated)
            .unwrap()
            .promote()
            .unwrap();
        let journal = persistence.journal_path_for(original.origin());
        let mut bytes = fs::read(&journal).unwrap();
        bytes[20] ^= 1;
        fs::write(&journal, bytes).unwrap();

        assert!(persistence.restore(original.origin(), 1).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incremental_journal_chains_generations_and_full_checkpoint_resets_it() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-journal-chain-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let original = snapshot();
        persistence.persist(&original).unwrap();
        let second = incremented_snapshot(&original, 8);
        persistence
            .stage_incremental(&original, &second)
            .unwrap()
            .promote()
            .unwrap();
        let third = incremented_snapshot(&second, 9);
        persistence
            .stage_incremental(&second, &third)
            .unwrap()
            .promote()
            .unwrap();

        assert_eq!(
            persistence
                .restore(original.origin(), 1)
                .unwrap()
                .unwrap()
                .snapshot
                .serial(),
            Some(9)
        );

        persistence.stage(&third).unwrap().promote().unwrap();
        assert!(!persistence.journal_path_for(original.origin()).exists());
        assert_eq!(
            persistence
                .restore(original.origin(), 1)
                .unwrap()
                .unwrap()
                .snapshot
                .serial(),
            Some(9)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn full_checkpoint_restore_ignores_stale_pre_promotion_journal() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-journal-stale-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let original = snapshot();
        persistence.persist(&original).unwrap();
        let updated = incremented_snapshot(&original, 8);
        persistence
            .stage_incremental(&original, &updated)
            .unwrap()
            .promote()
            .unwrap();

        let mut staged = persistence.stage(&updated).unwrap();
        fs::rename(&staged.temp_path, &staged.final_path).unwrap();
        staged.promoted = true;
        drop(staged);

        assert!(persistence.journal_path_for(original.origin()).exists());
        assert_eq!(
            persistence
                .restore(original.origin(), 1)
                .unwrap()
                .unwrap()
                .snapshot
                .serial(),
            Some(8)
        );
        persistence
            .renew_freshness(original.origin(), Some(8))
            .unwrap();
        let base_checksum = persistence
            .cache_checksum(&persistence.path_for(original.origin()))
            .unwrap();
        assert!(
            persistence
                .read_freshness(original.origin(), Some(8), &base_checksum)
                .is_some()
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn journal_payload_prefix(origin: &DomainName, change_count: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JOURNAL_MAGIC);
        let origin_wire = origin.to_wire();
        bytes.extend_from_slice(&(origin_wire.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&origin_wire);
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(&8u32.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&change_count.to_be_bytes());
        bytes
    }

    fn append_journal_change_key(bytes: &mut Vec<u8>, owner: &DomainName) {
        let owner_wire = owner.to_wire();
        bytes.extend_from_slice(&(owner_wire.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&owner_wire);
        bytes.extend_from_slice(&(RecordType::A as u16).to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
    }

    #[test]
    fn journal_decoder_rejects_empty_and_duplicate_replacements() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("www.example.test.").unwrap();

        let mut empty = journal_payload_prefix(&origin, 1);
        append_journal_change_key(&mut empty, &owner);
        empty.push(1);
        empty.extend_from_slice(&300u32.to_be_bytes());
        empty.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            decode_journal(&empty, &origin).err(),
            Some("journal replacement RRset is empty")
        );

        let mut duplicate = journal_payload_prefix(&origin, 2);
        append_journal_change_key(&mut duplicate, &owner);
        duplicate.push(0);
        append_journal_change_key(&mut duplicate, &owner);
        duplicate.push(0);
        assert_eq!(
            decode_journal(&duplicate, &origin).err(),
            Some("duplicate journal RRset change")
        );
    }

    #[test]
    fn rejects_corrupt_last_good_zone_without_partial_restore() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-corrupt-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let snapshot = snapshot();
        persistence.persist(&snapshot).unwrap();
        let path = persistence.path_for(snapshot.origin());
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(persistence.restore(snapshot.origin(), 1).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restored_last_good_zone_respects_soa_expire_across_downtime() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-expired-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let snapshot = snapshot();
        persistence.persist(&snapshot).unwrap();
        let path = persistence.path_for(snapshot.origin());
        let mut bytes = fs::read(&path).unwrap();
        let timestamp_offset = MAGIC.len() + 2 + snapshot.origin().to_wire().len() + 1 + 4;
        bytes[timestamp_offset..timestamp_offset + 8].copy_from_slice(&0u64.to_be_bytes());
        let checksum_offset = bytes.len() - 32;
        let checksum = Sha256::digest(&bytes[..checksum_offset]);
        bytes[checksum_offset..].copy_from_slice(&checksum);
        fs::write(&path, bytes).unwrap();

        let restored = persistence.restore(snapshot.origin(), 1).unwrap().unwrap();
        assert_eq!(
            restored.snapshot.state(),
            borondns_core::zone::ZoneState::Expired
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authenticated_freshness_renewal_keeps_unchanged_zone_active_after_restart() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-freshness-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let snapshot = snapshot();
        persistence.persist(&snapshot).unwrap();
        let path = persistence.path_for(snapshot.origin());
        let mut bytes = fs::read(&path).unwrap();
        let timestamp_offset = MAGIC.len() + 2 + snapshot.origin().to_wire().len() + 1 + 4;
        bytes[timestamp_offset..timestamp_offset + 8].copy_from_slice(&0u64.to_be_bytes());
        let checksum_offset = bytes.len() - 32;
        let checksum = Sha256::digest(&bytes[..checksum_offset]);
        bytes[checksum_offset..].copy_from_slice(&checksum);
        fs::write(&path, bytes).unwrap();

        persistence
            .renew_freshness(snapshot.origin(), snapshot.serial())
            .unwrap();
        let restored = persistence.restore(snapshot.origin(), 1).unwrap().unwrap();

        assert_eq!(
            restored.snapshot.state(),
            borondns_core::zone::ZoneState::Active
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cache_and_freshness_readers_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-symlink-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let snapshot = snapshot();
        persistence.persist(&snapshot).unwrap();
        persistence
            .renew_freshness(snapshot.origin(), snapshot.serial())
            .unwrap();

        let cache_path = persistence.path_for(snapshot.origin());
        let cache_checksum = persistence.cache_checksum(&cache_path).unwrap();
        let freshness_path = persistence.freshness_path_for(snapshot.origin());
        let moved_freshness = root.join("moved.fresh");
        fs::rename(&freshness_path, &moved_freshness).unwrap();
        symlink(&moved_freshness, &freshness_path).unwrap();
        assert_eq!(
            persistence.read_freshness(snapshot.origin(), snapshot.serial(), &cache_checksum),
            None
        );

        let moved_cache = root.join("moved.bdz");
        fs::rename(&cache_path, &moved_cache).unwrap();
        symlink(&moved_cache, &cache_path).unwrap();
        assert!(
            persistence
                .renew_freshness(snapshot.origin(), snapshot.serial())
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_candidate_write_preserves_previous_atomic_last_good_file() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-atomic-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let snapshot = snapshot();
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        persistence.persist(&snapshot).unwrap();

        let undersized = ZonePersistence::new(root.clone(), 1);
        assert!(undersized.persist(&snapshot).is_err());
        let restored = persistence.restore(snapshot.origin(), 1).unwrap().unwrap();
        assert_eq!(restored.snapshot.serial(), Some(7));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn abandoned_staged_candidate_preserves_previous_last_good_file() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-staged-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let original = snapshot();
        persistence.persist(&original).unwrap();
        let replacement = ZoneSnapshot::active(original.origin().clone(), Some(8), Vec::new());

        let staged = persistence.stage(&replacement).unwrap();
        assert_eq!(
            persistence
                .restore(original.origin(), 1)
                .unwrap()
                .unwrap()
                .snapshot
                .serial(),
            Some(7)
        );
        drop(staged);
        assert_eq!(
            persistence
                .restore(original.origin(), 1)
                .unwrap()
                .unwrap()
                .snapshot
                .serial(),
            Some(7)
        );
        assert_eq!(
            fs::read_dir(&root).unwrap().filter_map(Result::ok).count(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn removing_zone_lifecycle_removes_last_good_cache() {
        let root = std::env::temp_dir().join(format!(
            "borondns-zone-cache-remove-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        let snapshot = snapshot();
        persistence.persist(&snapshot).unwrap();

        persistence.remove(snapshot.origin()).unwrap();

        assert!(persistence.restore(snapshot.origin(), 1).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
