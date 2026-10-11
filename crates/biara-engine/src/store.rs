use crate::{Error, Options};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const SCHEMA: i64 = 2;
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

pub(crate) struct StoredRecovery {
    pub graph: Option<Vec<u8>>,
    pub resolver_graph: Option<Vec<u8>>,
    pub resolver_state: Option<Vec<u8>>,
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
        db.pragma_update(None, "synchronous", "FULL")?;
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
CREATE TABLE IF NOT EXISTS variants(id TEXT PRIMARY KEY,project TEXT NOT NULL,graph BLOB,resolver_graph BLOB,resolver_state BLOB,finished INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS candidates(variant TEXT NOT NULL,address TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(variant,address));
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,project TEXT NOT NULL,stage TEXT NOT NULL,result BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS cfg_blocks(id BLOB PRIMARY KEY,project TEXT NOT NULL,result BLOB NOT NULL);")?;
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
        Ok(self
            .db
            .query_row("SELECT result FROM jobs WHERE id=?1", [id], |r| r.get(0))
            .optional()?)
    }
    pub fn put<'a>(
        &mut self,
        stage: &str,
        results: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> Result<(), Error> {
        let transaction = self.db.transaction()?;
        {
            let mut insert =
                transaction.prepare_cached("INSERT OR IGNORE INTO jobs VALUES(?1,?2,?3,?4)")?;
            for (id, result) in results {
                insert.execute(params![id, self.project, stage, result])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }
    pub fn state(&self) -> Result<StoredRecovery, Error> {
        Ok(self.db.query_row(
            "SELECT graph,resolver_graph,resolver_state,finished FROM variants WHERE id=?1",
            [&self.variant],
            |r| {
                Ok(StoredRecovery {
                    graph: r.get(0)?,
                    resolver_graph: r.get(1)?,
                    resolver_state: r.get(2)?,
                    finished: r.get(3)?,
                })
            },
        )?)
    }
    /// The stored artifact, not yet checked against its identity.
    pub fn block_bytes(&self, id: &biara_cfg::BlockId) -> Result<Vec<u8>, Error> {
        Ok(self
            .db
            .prepare_cached("SELECT result FROM cfg_blocks WHERE id=?1 AND project=?2")?
            .query_row(params![id.as_slice(), self.project], |row| row.get(0))?)
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
            let mut insert =
                tx.prepare_cached("INSERT OR IGNORE INTO cfg_blocks VALUES(?1,?2,?3)")?;
            for block in &prepared.changed {
                insert.execute(params![block.id.as_slice(), self.project, block.bytes])?;
            }
        }
        // Blocks and both resolver heads publish atomically. A later progress
        // checkpoint never mixes a newer graph with an older dependency state.
        tx.execute(
            "UPDATE variants SET graph=?2,finished=?3,
resolver_graph=CASE WHEN ?4 IS NULL THEN resolver_graph ELSE ?2 END,
resolver_state=coalesce(?4,resolver_state) WHERE id=?1",
            params![self.variant, prepared.manifest, finished, resolver_state],
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
