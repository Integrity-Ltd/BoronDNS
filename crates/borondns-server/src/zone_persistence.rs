use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use borondns_core::{
    axfr::{AxfrError, validated_persisted_zone_snapshot},
    dns::DomainName,
    zone::{ResourceRecord, ZoneSnapshot},
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"BORONZ01";
const FRESHNESS_MAGIC: &[u8; 8] = b"BORONF01";
const MAX_RECORDS: u64 = u32::MAX as u64;
const MIN_RECORD_BYTES: u64 = 13;
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

pub(crate) struct StagedZoneCache {
    persistence: ZonePersistence,
    origin: DomainName,
    temp_path: PathBuf,
    final_path: PathBuf,
    promoted: bool,
}

impl StagedZoneCache {
    pub(crate) fn promote(mut self) -> Result<(), ZonePersistenceError> {
        fs::rename(&self.temp_path, &self.final_path)
            .map_err(|source| self.persistence.io_error(&self.final_path, source))?;
        self.promoted = true;
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
        let effective_persisted_unix_secs = self
            .read_freshness(&origin, serial, &stored)
            .unwrap_or(persisted_unix_secs)
            .max(persisted_unix_secs);
        validated_persisted_zone_snapshot(&origin, qclass, serial, records)
            .map(|snapshot| {
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
                Some(RestoredZone {
                    snapshot,
                    persisted_unix_secs: effective_persisted_unix_secs,
                })
            })
            .map_err(|source| ZonePersistenceError::InvalidZone {
                path: path.display().to_string(),
                source,
            })
    }

    pub(crate) fn remove(&self, origin: &DomainName) -> Result<(), ZonePersistenceError> {
        let path = self.path_for(origin);
        let freshness_path = self.freshness_path_for(origin);
        let mut removed = false;
        for candidate in [&path, &freshness_path] {
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
        let cache_checksum = self.cache_checksum(&final_path)?;
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

    fn cache_checksum(&self, path: &Path) -> Result<[u8; 32], ZonePersistenceError> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|source| self.io_error(path, source))?;
        let length = file
            .metadata()
            .map_err(|source| self.io_error(path, source))?
            .len();
        if length < 32 || length > self.max_file_bytes {
            return Err(self.malformed(path, "cache file cannot contain a bounded checksum"));
        }
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
        let bytes = fs::read(self.freshness_path_for(origin)).ok()?;
        let payload_len =
            FRESHNESS_MAGIC.len() + 1 + if expected_serial.is_some() { 4 } else { 0 } + 32 + 8;
        if bytes.len() != payload_len + 32 || &bytes[..8] != FRESHNESS_MAGIC {
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

    fn soa_rdata() -> Vec<u8> {
        let mut rdata = DomainName::from_absolute_str("ns.example.test.")
            .unwrap()
            .to_wire();
        rdata.extend(
            DomainName::from_absolute_str("hostmaster.example.test.")
                .unwrap()
                .to_wire(),
        );
        for value in [7u32, 3600, 600, 604800, 300] {
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
                    vec![soa_rdata()],
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
