use crate::{Error, Options};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const SCHEMA: i64 = 3;
/// `ALTER TABLE … ADD COLUMN`, unless the column is already there: a database half-migrated
/// by an earlier build must open, not fail on a duplicate column.
fn add_column(
    db: &rusqlite::Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), Error> {
    let present = db
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |row| row.get::<_, String>(1))?
        .any(|name| name.is_ok_and(|n| n == column));
    if !present {
        db.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition};"
        ))?;
    }
    Ok(())
}
// Statements name their columns: `ALTER TABLE ... ADD COLUMN` appends, so a migrated table has
// `codec` after `result` while a fresh one has it before, and positional values would swap them.
pub(crate) fn digest(path: &Path) -> Result<String, Error> {
    let mut file = fs::File::open(path)?;
    let mut hash = blake3::Hasher::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().to_hex().to_string())
}
pub(crate) fn key(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
/// Authoritative payload codec marker for schema 3 rows.
///
/// `jobs.result` / `cfg_blocks.result` store the raw postcard bytes with an
/// explicit `codec` column: `0` = raw postcard (legacy or incompressible),
/// `1` = zstd-compressed postcard (level 3). There is no byte-prefix sniffing:
/// the column is the contract, so a genuine raw payload starting with `p`,
/// `z`, or `pp` can never be confused with a tag. Schema 2 databases are
/// migrated by content-address verification (durable `cfg_blocks`) or retired
/// (rebuildable `jobs`); see `migrate_schema_2_rows`.
pub(crate) const CODEC_RAW: u8 = 0;
pub(crate) const CODEC_ZSTD: u8 = 1;
/// Payloads larger than 64 MiB after decompression are rejected: legitimate
/// postcard artifacts (single CFG blocks, resolution views, recovery state)
/// are far smaller, and an unbounded `decode_all` would let a hostile `z`
/// row expand into memory before any caller validates it.
const MAX_DECODED_BYTES: usize = 64 * 1024 * 1024;
/// zstd level for stored payloads.
const ZSTD_LEVEL: i32 = 3;
thread_local! {
    /// One compression context per thread. `zstd::encode_all` builds and
    /// zeroes a fresh context for every call, which dominated the
    /// coordinator when every translated block is stored as its own blob.
    static COMPRESSOR: std::cell::RefCell<Option<zstd::bulk::Compressor<'static>>> =
        const { std::cell::RefCell::new(None) };
}
fn compress(raw: &[u8]) -> Result<Vec<u8>, Error> {
    COMPRESSOR.with(|slot| {
        let mut slot = slot.borrow_mut();
        let compressor = match &mut *slot {
            Some(compressor) => compressor,
            empty => empty.insert(
                zstd::bulk::Compressor::new(ZSTD_LEVEL)
                    .map_err(|e| Error::Engine(e.to_string()))?,
            ),
        };
        compressor
            .compress(raw)
            .map_err(|e| Error::Engine(e.to_string()))
    })
}
pub(crate) fn encode_blob(raw: &[u8]) -> Result<(u8, Vec<u8>), Error> {
    if raw.len() > MAX_DECODED_BYTES {
        return Err(Error::Engine("analysis payload exceeds 64 MiB".into()));
    }
    let compressed = compress(raw)?;
    // Store compressed only when it actually shrinks: tiny artifacts would
    // otherwise grow, and the codec column keeps either form explicit.
    if compressed.len() < raw.len() {
        Ok((CODEC_ZSTD, compressed))
    } else {
        Ok((CODEC_RAW, raw.to_vec()))
    }
}
/// Decompress a zstd frame to at most [`MAX_DECODED_BYTES`], into a buffer as big as the
/// output. `zstd::bulk::decompress(blob, cap)` allocates `cap` bytes of address space for every
/// call and keeps it for the life of the returned `Vec`, so a cache holding decoded blocks used
/// 64 MiB of address space per block and a coordinator under an address-space limit died after
/// about thirty of them.
fn decompress(blob: &[u8]) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let io = |e: std::io::Error| Error::Engine(e.to_string());
    let mut out = Vec::new();
    zstd::stream::read::Decoder::new(blob)
        .map_err(io)?
        .take(MAX_DECODED_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(io)?;
    if out.len() > MAX_DECODED_BYTES {
        return Err(Error::Engine("analysis payload exceeds 64 MiB".into()));
    }
    out.shrink_to_fit();
    Ok(out)
}
pub(crate) fn decode_blob(codec: u8, blob: &[u8]) -> Result<Vec<u8>, Error> {
    match codec {
        CODEC_ZSTD => decompress(blob),
        CODEC_RAW => Ok(blob.to_vec()),
        _ => Err(Error::Engine("unknown analysis payload codec".into())),
    }
}

pub(crate) struct StoredRecovery {
    pub graph: Option<Vec<u8>>,
    pub resolver_graph: Option<Vec<u8>>,
    pub resolver_state: Option<Vec<u8>>,
    pub resolver_state_codec: u8,
    pub finished: bool,
}

pub(crate) struct Store {
    pub db: Connection,
    pub project: String,
    pub variant: String,
    pub snapshot: PathBuf,
    pub binary_hash: String,
    pub library_hash: String,
}
impl Store {
    pub fn open(options: &Options, variant_input: &[u8]) -> Result<Self, Error> {
        let binary_hash = digest(&options.binary)?;
        let library_hash = digest(&options.libtcg)?;
        // Include executable identity so changed analysis code never consumes
        // a result from a different implementation with the same wire schema.
        let engine_hash = digest(&options.executable)?;
        let project = key(&postcard::to_stdvec(&(
            &binary_hash,
            &library_hash,
            &options.cpu,
            &engine_hash,
            biara_proto::ANALYSIS_TRIPLE,
            SCHEMA,
        ))?);
        let variant = key(&postcard::to_stdvec(&(&project, variant_input))?);
        let database = match &options.database {
            Some(path) => path.clone(),
            None => {
                let cache = std::env::var_os("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
                    .ok_or_else(|| {
                        Error::Engine("no user cache directory; provide --database".into())
                    })?;
                cache
                    .join("biara")
                    .join(&binary_hash)
                    .join("analysis.sqlite")
            }
        };
        let directory = database
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(directory)?;
        // Serialize first-time WAL/schema initialization across coordinators.
        // SQLite's busy handler cannot resolve concurrent journal-mode upgrades.
        let mut lock_path = database.as_os_str().to_os_string();
        lock_path.push(".lock");
        let initialization = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(PathBuf::from(lock_path))?;
        initialization.lock()?;
        let mut db = Connection::open(&database)?;
        db.busy_timeout(Duration::from_secs(30))?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if !(0..=SCHEMA).contains(&version) {
            return Err(Error::Engine(format!(
                "unsupported analysis database schema {version}, expected {SCHEMA}"
            )));
        }
        let journal: String = db.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        if journal != "wal" {
            db.pragma_update(None, "journal_mode", "WAL")?;
        }
        // WAL with `synchronous=NORMAL` keeps every transaction atomic and the database
        // uncorrupted, and a killed process loses nothing (the OS still holds the WAL). It
        // syncs only at WAL checkpoints instead of at every commit, so an operating-system
        // crash can drop the most recent commits, which resume recomputes: the store is a
        // rebuildable cache. `FULL` fsynced each of the many small commits and cost 35 s of a
        // 46 s libc recovery on an NVMe disk (11 s with the database on tmpfs).
        db.pragma_update(None, "synchronous", "NORMAL")?;
        let migration = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if version == 1 {
            // Old payloads bind the previous executable's codec/analysis.
            // Retire those graphs, retaining projects, candidates and job artifacts.
            migration.execute_batch(
                "
ALTER TABLE variants DROP COLUMN cfg;
ALTER TABLE variants DROP COLUMN snapshot;
ALTER TABLE variants ADD COLUMN graph BLOB;
ALTER TABLE variants ADD COLUMN resolver_graph BLOB;
ALTER TABLE variants ADD COLUMN resolver_state BLOB;
UPDATE variants SET finished=0;
UPDATE candidates SET state='pending';",
            )?;
        }
        migration.execute_batch("
CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,binary_hash TEXT NOT NULL,library_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS variants(id TEXT PRIMARY KEY,project TEXT NOT NULL,graph BLOB,resolver_graph BLOB,resolver_graph_codec INTEGER NOT NULL DEFAULT 0,resolver_state BLOB,resolver_state_codec INTEGER NOT NULL DEFAULT 0,finished INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS candidates(variant TEXT NOT NULL,address TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(variant,address));
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,project TEXT NOT NULL,stage TEXT NOT NULL,codec INTEGER NOT NULL DEFAULT 0,result BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS cfg_blocks(id BLOB PRIMARY KEY,project TEXT NOT NULL,codec INTEGER NOT NULL DEFAULT 0,result BLOB NOT NULL);")?;
        // Versions 1 and 2 both lack the codec columns (version 1 stored raw postcard, which is
        // what the default of 0 means). Adding them is idempotent.
        if version == 1 || version == 2 {
            add_column(&migration, "jobs", "codec", "INTEGER NOT NULL DEFAULT 0")?;
            add_column(
                &migration,
                "cfg_blocks",
                "codec",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            add_column(
                &migration,
                "variants",
                "resolver_graph_codec",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            add_column(
                &migration,
                "variants",
                "resolver_state_codec",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        if version == 2 {
            // Schema 2 rows carry bare postcard/zstd-prefix bytes with no
            // authoritative marker, so their first byte proves nothing: a
            // genuine raw block starting with `p` (`pc=0x7070...`) is
            // byte-identical to a stacked migration tag. Never mutate those
            // bytes on prefix evidence.
            //
            // Rebuildable `jobs` rows are retired: resume recomputes them
            // through workers rather than risking a wrong decode. Durable
            // `cfg_blocks` rows are verified by content address before any
            // rewrite: each row's `id` is `block_id(project, raw_bytes)`, so
            // the only safe migration is trial decode (raw, then `z`-prefix
            // zstd) accepted exclusively when the verified artifact hash
            // matches the row id. Anything unverifiable is deleted and
            // re-recovered from the image on resume; durable checkpoint data
            // is never destroyed by guessing.
            migration.execute_batch("DELETE FROM jobs;")?;
            {
                let mut select = migration.prepare("SELECT id, project, result FROM cfg_blocks")?;
                let rows: Vec<(Vec<u8>, String, Vec<u8>)> = select
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .collect::<Result<_, _>>()?;
                drop(select);
                for (id, project, result) in rows {
                    let id: [u8; 32] = id.try_into().map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            "bad block id".into(),
                        )
                    })?;
                    // Order matters: try the bytes as-is first (genuine raw
                    // payloads, including `pp...`/`pz...` prefixes), then the
                    // historical single-byte tag strips, accepting only the
                    // first candidate whose hash verifies against the row id.
                    let mut candidates: Vec<(u8, Vec<u8>)> = Vec::new();
                    candidates.push((CODEC_RAW, result.clone()));
                    if result.first() == Some(&b'p') {
                        candidates.push((CODEC_RAW, result[1..].to_vec()));
                    }
                    if result.first() == Some(&b'z') {
                        candidates.push((CODEC_ZSTD, result[1..].to_vec()));
                    }
                    if result.first() == Some(&b'p') && result.get(1) == Some(&b'z') {
                        candidates.push((CODEC_ZSTD, result[2..].to_vec()));
                    }
                    let mut migrated = false;
                    for (codec, raw) in candidates {
                        let stored = match codec {
                            CODEC_ZSTD => match decompress(&raw) {
                                Ok(decoded) => decoded,
                                Err(_) => continue,
                            },
                            _ => raw.clone(),
                        };
                        if crate::checkpoint::block_id(&project, &stored) == id {
                            let (codec, payload) = encode_blob(&stored)?;
                            migration.execute(
                                "UPDATE cfg_blocks SET codec=?3, result=?4 WHERE id=?1 AND project=?2",
                                params![id.as_slice(), project, codec, payload],
                            )?;
                            migrated = true;
                            break;
                        }
                    }
                    if !migrated {
                        // Unverifiable legacy row: drop it and let resume
                        // re-recover the block from the image snapshot.
                        migration.execute(
                            "DELETE FROM cfg_blocks WHERE id=?1 AND project=?2",
                            params![id.as_slice(), project],
                        )?;
                    }
                }
            }
            // Resolver heads without markers cannot be trusted either: drop
            // both heads so resume restarts resolution from durable blocks
            // rather than decoding ambiguous bytes.
            migration.execute_batch(
                "UPDATE variants SET graph=NULL, resolver_graph=NULL, resolver_graph_codec=0, resolver_state=NULL, resolver_state_codec=0, finished=0;",
            )?;
            migration.execute_batch("UPDATE candidates SET state='pending';")?;
        }
        // Commit the schema migration before any filesystem I/O: the
        // snapshot publication below needs `&db` again and must see the
        // migrated schema. Migration is fully transactional; a crash
        // before this point replays it on the next open.
        // Record where the schema now stands, or the next open would migrate again.
        migration.pragma_update(None, "user_version", SCHEMA)?;
        migration.commit()?;
        db.execute(
            "INSERT OR IGNORE INTO projects VALUES(?1,?2,?3)",
            params![project, binary_hash, library_hash],
        )?;
        db.execute(
            "INSERT OR IGNORE INTO variants(id,project) VALUES(?1,?2)",
            params![variant, project],
        )?;
        let objects = directory.join("biara-images");
        fs::create_dir_all(&objects)?;
        let snapshot = objects.join(&binary_hash);
        if snapshot.exists() {
            if digest(&snapshot)? != binary_hash {
                return Err(Error::Engine("immutable image snapshot is corrupt".into()));
            }
        } else {
            let temporary = objects.join(format!(
                "{binary_hash}.{}.{}.tmp",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| Error::Engine(e.to_string()))?
                    .as_nanos()
            ));
            let mut input = fs::File::open(&options.binary)?;
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            let copied = (|| -> Result<(), Error> {
                std::io::copy(&mut input, &mut output)?;
                output.flush()?;
                output.sync_all()?;
                if digest(&temporary)? != binary_hash {
                    return Err(Error::Engine("binary changed while snapshotting".into()));
                }
                let mut permissions = output.metadata()?.permissions();
                permissions.set_readonly(true);
                output.set_permissions(permissions)?;
                // Hard-link publication never replaces a snapshot mapped by
                // another engine. A competing publisher may win harmlessly.
                match fs::hard_link(&temporary, &snapshot) {
                    Ok(()) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        if digest(&snapshot)? != binary_hash {
                            return Err(Error::Engine("snapshot publication conflict".into()));
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
                Ok(())
            })();
            let _ = fs::remove_file(&temporary);
            copied?;
        }
        Ok(Self {
            db,
            project,
            variant,
            snapshot,
            binary_hash,
            library_hash,
        })
    }
    pub fn seed(&mut self, entries: &[u64]) -> Result<(), Error> {
        let transaction = self.db.transaction()?;
        {
            let mut insert = transaction
                .prepare_cached("INSERT OR IGNORE INTO candidates VALUES(?1,?2,'pending')")?;
            for pc in entries {
                insert.execute(params![self.variant, format!("{pc:016x}")])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }
    pub fn get(&self, id: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(
            match self
                .db
                .query_row("SELECT codec, result FROM jobs WHERE id=?1", [id], |r| {
                    Ok((r.get::<_, u8>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .optional()?
            {
                Some((codec, blob)) => Some(decode_blob(codec, &blob)?),
                None => None,
            },
        )
    }
    pub fn put<'a>(
        &mut self,
        stage: &str,
        results: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> Result<(), Error> {
        let transaction = self.db.transaction()?;
        {
            let mut insert = transaction.prepare_cached(
                "INSERT OR IGNORE INTO jobs(id,project,stage,codec,result) VALUES(?1,?2,?3,?4,?5)",
            )?;
            for (id, result) in results {
                let (codec, payload) = encode_blob(result)?;
                insert.execute(params![id, self.project, stage, codec, payload])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }
    pub fn state(&self) -> Result<StoredRecovery, Error> {
        Ok(self.db.query_row(
            "SELECT graph,resolver_graph,resolver_state,resolver_state_codec,finished FROM variants WHERE id=?1",
            [&self.variant],
            |r| {
                Ok(StoredRecovery {
                    graph: r.get(0)?,
                    resolver_graph: r.get(1)?,
                    resolver_state: r.get(2)?,
                    resolver_state_codec: r.get(3)?,
                    finished: r.get(4)?,
                })
            },
        )?)
    }
    /// The stored artifact, not yet checked against its identity.
    pub fn block_bytes(&self, id: &biara_cfg::BlockId) -> Result<Vec<u8>, Error> {
        let (codec, blob): (u8, Vec<u8>) = self
            .db
            .prepare_cached("SELECT codec, result FROM cfg_blocks WHERE id=?1 AND project=?2")?
            .query_row(params![id.as_slice(), self.project], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        decode_blob(codec, &blob)
    }
    pub fn checkpoint(
        &mut self,
        cfg: &biara_cfg::Cfg,
        prepared: &crate::checkpoint::Prepared,
        resolver_state: Option<&[u8]>,
        finished: bool,
    ) -> Result<(), Error> {
        let tx = self.db.transaction()?;
        if !prepared.changed.is_empty() {
            let mut insert = tx.prepare_cached(
                "INSERT OR IGNORE INTO cfg_blocks(id,project,codec,result) VALUES(?1,?2,?3,?4)",
            )?;
            for block in &prepared.changed {
                let (codec, payload) = encode_blob(&block.bytes)?;
                insert.execute(params![block.id.as_slice(), self.project, codec, payload])?;
            }
        }
        // Blocks and both resolver heads publish atomically. A later progress
        // checkpoint never mixes a newer graph with an older dependency state.
        // Resolver dependency rounds compress like any other payload; manifests
        // stay raw postcard so restores can read heads without decompression.
        let (resolver_codec, resolver) = match resolver_state {
            Some(raw) => {
                let (codec, payload) = encode_blob(raw)?;
                (Some(codec), Some(payload))
            }
            None => (None, None),
        };
        tx.execute(
            "UPDATE variants SET graph=?2,finished=?3,
resolver_graph=CASE WHEN ?4 IS NULL THEN resolver_graph ELSE ?2 END,
resolver_graph_codec=CASE WHEN ?4 IS NULL THEN resolver_graph_codec ELSE 0 END,
resolver_state=coalesce(?4,resolver_state),resolver_state_codec=coalesce(?5,resolver_state_codec) WHERE id=?1",
            params![
                self.variant,
                prepared.manifest,
                finished,
                resolver,
                resolver_codec
            ],
        )?;
        {
            let incomplete = cfg.issues().next().is_some();
            let mut update = tx.prepare_cached(
                "INSERT INTO candidates VALUES(?1,?2,?3) ON CONFLICT(variant,address) DO UPDATE SET state=excluded.state",
            )?;
            for (pc, function) in &cfg.functions {
                update.execute(params![
                    self.variant,
                    format!("{pc:016x}"),
                    if finished && !incomplete && !function.blocks.is_empty() {
                        "analyzed"
                    } else {
                        "partial"
                    },
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    /// Delete rebuildable per-block translation/resolution job cache rows for
    /// this project, keeping durable CFG artifacts (`cfg_blocks`, variant
    /// heads, candidates) intact. Returns deleted row count. Resume re-runs
    /// translations through workers; committed graphs need no rebuild.
    pub fn prune_rebuildable_cache(&mut self) -> Result<usize, Error> {
        let deleted = self
            .db
            .execute("DELETE FROM jobs WHERE project=?1", params![self.project])?;
        Ok(deleted)
    }
}

pub(crate) fn verify_block(
    project: &str,
    id: &biara_cfg::BlockId,
    bytes: &[u8],
) -> Result<(), Error> {
    if crate::checkpoint::block_id(project, bytes) != *id {
        return Err(Error::Engine(
            "checkpoint block artifact hash mismatch".into(),
        ));
    }
    Ok(())
}
