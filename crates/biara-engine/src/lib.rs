//! Durable recovery jobs with private QEMU/LLVM worker processes.
//!
//! The coordinator owns canonical CFG updates and commits versioned SQLite WAL
//! artifacts. Long-lived workers map immutable image snapshots and keep private
//! QEMU state and LLVM contexts. Translation failures remain guest-analysis
//! facts; IPC, storage and worker failures abort rather than masquerade as them.
//!
//! Cache identity binds binary bytes, libtcg bytes, CPU model and executable
//! implementation. Recovery variants additionally bind entry sets and limits,
//! never the worker count. Resolution keys contain the relevant function body
//! and callee facts, invalidating jobs when recovery changes their dependencies.
//! Block jobs commit as responses arrive; graph checkpoints are throttled and
//! resolver checkpoints retain dependency rounds. Interrupted frontiers are
//! rebuilt from committed graph/translation artifacts, not serialized threads.
//! Translation workers take small leases and accept another as soon as they
//! finish. Resolution jobs also refill idle workers without fixed-batch barriers;
//! their complete call summaries (including memory and named-register returns)
//! merge in entry order, irrespective of completion or cache hits.
//! Resolver wire buffers are released before building LLVM IR. At job boundaries,
//! GNU/Linux workers return large amounts of freed arena memory to the OS rather
//! than retaining each worker's largest resolver allocation until process exit.
//!
//! Schema 2 checkpoints reference project-bound immutable block artifacts.
//! Strong Arc identities skip serialization/hashing of unchanged IR, including
//! after restoration. Copy-on-write edits and re-cuts publish new identities.
//! Artifact inserts, manifest heads, resolver state and candidate progress commit
//! in one transaction; failed publication leaves both disk and version cache old.
//! Progress can advance beyond the resolver checkpoint, but restoration pairs
//! resolver graphs with their own dependency state. Finished requests use the
//! final graph, even when the last resolver checkpoint predates a budget limit.
//! Restoration reads artifacts in bounded batches and verifies/decodes them
//! across the worker budget; any mismatch aborts the restore.
//! Schema 1 migration keeps historical jobs/candidates and retires obsolete graph
//! payloads; cache reuse still requires the same executable implementation.
//!
//! Default storage is `$XDG_CACHE_HOME/biara/<binary-hash>/analysis.sqlite`
//! (or `$HOME/.cache`); an explicit database can hold multiple images. Discovery
//! candidates and partial recovery are distinct from finished analysis requests.
mod checkpoint;
mod store;
mod worker;
use biara_lift::{RecoverySnapshot, RecoveryState, ResolutionArtifact};
use biara_tcg::{Block, ContextInfo, IrCodec, Libtcg, TranslationRequest, Translator};
use parking_lot::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
pub use worker::worker;
use worker::{Config, GuestError, Pool, Request, Response, Translation};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Wire(#[from] postcard::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Tcg(#[from] biara_tcg::Error),
    #[error(transparent)]
    Loader(#[from] biara_loader::Error),
    #[error(transparent)]
    Lift(#[from] biara_lift::Error),
    #[error("analysis engine: {0}")]
    Engine(String),
}
pub struct Options {
    pub binary: PathBuf,
    pub libtcg: PathBuf,
    pub cpu: Option<String>,
    pub database: Option<PathBuf>,
    pub workers: usize,
    pub executable: PathBuf,
}
pub struct Session {
    options: Options,
    store: store::Store,
    library: Arc<Mutex<Libtcg>>,
    info: ContextInfo,
    codec: IrCodec,
    pool: Option<Pool>,
    cached: BTreeMap<String, Vec<u8>>,
    versions: checkpoint::Versions,
    last_checkpoint: Instant,
    translated: usize,
    reused: usize,
    resolved: usize,
    reused_resolutions: usize,
}
impl Session {
    pub fn open(
        mut options: Options,
        entries: &[u64],
        resolve: &biara_lift::ResolveOptions,
    ) -> Result<Self, Error> {
        if options.workers == 0 {
            return Err(Error::Engine("worker budget must be nonzero".into()));
        }
        options.binary = options.binary.canonicalize()?;
        options.libtcg = options.libtcg.canonicalize()?;
        let variant = postcard::to_stdvec(&(
            entries,
            resolve.cfg.os,
            resolve.cfg.max_blocks,
            resolve.max_rounds,
            resolve.max_table_entries,
            &resolve.cfg.jump_tables,
            &resolve.cfg.incomplete_jump_tables,
            &resolve.cfg.indirect_calls,
            &resolve.cfg.imports,
            resolve
                .cfg
                .discovery
                .as_ref()
                .map(|d| (&d.code, &d.extents, &d.data_pointers)),
            &resolve.cfg.function_starts,
        ))?;
        let mut store = store::Store::open(&options, &variant)?;
        store.seed(entries)?;
        let library = Libtcg::load(&options.libtcg, options.cpu.as_deref())?;
        let (info, codec) = {
            let library = library.lock();
            (library.info().clone(), library.codec())
        };
        eprintln!(
            "analysis: {} candidate entries; persistent recovery enabled",
            entries.len()
        );
        Ok(Self {
            options,
            store,
            library,
            info,
            codec,
            pool: None,
            cached: BTreeMap::new(),
            versions: checkpoint::Versions::default(),
            last_checkpoint: Instant::now()
                .checked_sub(Duration::from_secs(2))
                .unwrap_or_else(Instant::now),
            translated: 0,
            reused: 0,
            resolved: 0,
            reused_resolutions: 0,
        })
    }
    pub fn lib(&self) -> Arc<Mutex<Libtcg>> {
        self.library.clone()
    }
    fn pool(&mut self) -> Result<&mut Pool, Error> {
        if self.pool.is_none() {
            let config = Config {
                binary: self.store.snapshot.clone(),
                library: self.options.libtcg.clone(),
                cpu: self.options.cpu.clone(),
                binary_hash: self.store.binary_hash.clone(),
                library_hash: self.store.library_hash.clone(),
                parent: std::process::id(),
            };
            self.pool = Some(Pool::new(
                &self.options.executable,
                &config,
                self.options.workers,
            )?);
        }
        Ok(self.pool.as_mut().expect("initialized worker pool"))
    }
    fn translation_key(&self, request: &TranslationRequest<'_>) -> Result<String, Error> {
        Ok(store::key(&postcard::to_stdvec(&(
            &self.store.project,
            "translate",
            request.pc,
            request.code_base,
            request.code.len(),
            request.max_insns,
        ))?))
    }
    fn prefetch_inner(&mut self, requests: &[TranslationRequest<'_>]) -> Result<(), Error> {
        // Bounded batches keep unscheduled work and decoded IR out of memory.
        for batch in requests.chunks(64) {
            let mut misses = Vec::new();
            let mut seen = BTreeSet::new();
            for request in batch {
                let key = self.translation_key(request)?;
                if !seen.insert(key.clone()) || self.cached.contains_key(&key) {
                    continue;
                }
                if let Some(bytes) = self.store.get(&key)? {
                    self.reused += 1;
                    self.remember(key, bytes);
                } else {
                    misses.push((
                        key,
                        Translation {
                            pc: request.pc,
                            base: request.code_base,
                            length: request.code.len(),
                            max_insns: request.max_insns,
                        },
                    ));
                }
            }
            if misses.is_empty() {
                continue;
            }
            let count = self.options.workers.min(misses.len());
            // Small leases keep an expensive block from trapping a worker's
            // remaining queue; completed workers immediately take another lease.
            let grain = misses.len().div_ceil(count).clamp(1, 4);
            let mut groups = misses.chunks(grain);
            let mut in_flight = vec![None; count];
            let mut active = 0;
            for (index, assigned) in in_flight.iter_mut().enumerate() {
                let Some(group) = groups.next() else { break };
                self.pool()?.send(
                    index,
                    &Request::Translate(group.iter().map(|(_, request)| request.clone()).collect()),
                )?;
                *assigned = Some(group);
                active += 1;
            }
            while active != 0 {
                let (index, response) = self.pool()?.receive()?;
                let Response::Translate(results) = response else {
                    return Err(Error::Engine("unexpected translation response".into()));
                };
                let group = in_flight
                    .get_mut(index)
                    .and_then(Option::take)
                    .ok_or_else(|| Error::Engine("unexpected worker response index".into()))?;
                if results.len() != group.len() {
                    return Err(Error::Engine("translation response count differs".into()));
                }
                let encoded = group
                    .iter()
                    .zip(results)
                    .map(|((key, _), result)| Ok((key.as_str(), postcard::to_stdvec(&result)?)))
                    .collect::<Result<Vec<_>, Error>>()?;
                // Durability follows completion, independently of lease order.
                self.store.put(
                    "translate",
                    encoded.iter().map(|(key, bytes)| (*key, bytes.as_slice())),
                )?;
                for (key, bytes) in encoded {
                    self.translated += 1;
                    self.remember(key.to_owned(), bytes);
                }
                if let Some(group) = groups.next() {
                    self.pool()?.send(
                        index,
                        &Request::Translate(
                            group.iter().map(|(_, request)| request.clone()).collect(),
                        ),
                    )?;
                    in_flight[index] = Some(group);
                } else {
                    active -= 1;
                }
            }
        }
        Ok(())
    }
    fn remember(&mut self, key: String, bytes: Vec<u8>) {
        if self.cached.len() >= 128 {
            self.cached.pop_first();
        }
        self.cached.insert(key, bytes);
    }
    pub fn finish(&mut self, cfg: &biara_cfg::Cfg) -> Result<(), Error> {
        self.save_checkpoint(cfg, None, true)?;
        eprintln!(
            "analysis: {} functions, {} blocks; {} new / {} cached translations; {} new / {} cached resolution jobs; {} limitations",
            cfg.functions.len(),
            cfg.blocks.len(),
            self.translated,
            self.reused,
            self.resolved,
            self.reused_resolutions,
            cfg.issues().count()
        );
        Ok(())
    }
    fn save_checkpoint(
        &mut self,
        cfg: &biara_cfg::Cfg,
        state: Option<&RecoveryState>,
        finished: bool,
    ) -> Result<(), Error> {
        let prepared = self
            .versions
            .prepare(cfg, &self.codec, &self.store.project)?;
        let resolver = state.map(postcard::to_stdvec).transpose()?;
        self.store
            .checkpoint(cfg, &prepared, resolver.as_deref(), finished)?;
        self.versions.commit(cfg, prepared);
        Ok(())
    }
    fn resolve_inner(
        &mut self,
        cfg: &biara_cfg::Cfg,
        pending: &BTreeSet<u64>,
        max_entries: u64,
    ) -> Result<ResolutionArtifact, Error> {
        let mut combined = ResolutionArtifact {
            targets: BTreeMap::new(),
            calls: Default::default(),
        };
        let count = self.options.workers.min(pending.len());
        let mut entries = pending.iter().copied();
        let mut results = BTreeMap::new();
        let mut in_flight = Vec::with_capacity(count);
        let mut active = 0;
        for index in 0..count {
            let job =
                self.fill_resolution_slot(index, &mut entries, cfg, max_entries, &mut results)?;
            active += usize::from(job.is_some());
            in_flight.push(job);
        }
        while active != 0 {
            let (index, response) = self.pool()?.receive()?;
            let Response::Resolve(artifact) = response else {
                return Err(Error::Engine("unexpected resolution response".into()));
            };
            let (entry, key) = in_flight
                .get_mut(index)
                .and_then(Option::take)
                .ok_or_else(|| Error::Engine("unexpected resolution index".into()))?;
            let bytes = postcard::to_stdvec(&artifact)?;
            self.store
                .put("resolve", [(key.as_str(), bytes.as_slice())])?;
            self.resolved += 1;
            results.insert(entry, artifact);
            let job =
                self.fill_resolution_slot(index, &mut entries, cfg, max_entries, &mut results)?;
            if job.is_none() {
                active -= 1;
            }
            in_flight[index] = job;
        }
        // Commit completion-order artifacts, but merge facts in entry order.
        for (_, artifact) in results {
            merge(&mut combined, artifact);
        }
        combined
            .calls
            .sites
            .sort_by_key(|site| (site.caller, site.pc));
        Ok(combined)
    }
    fn fill_resolution_slot(
        &mut self,
        index: usize,
        entries: &mut impl Iterator<Item = u64>,
        cfg: &biara_cfg::Cfg,
        max_entries: u64,
        results: &mut BTreeMap<u64, ResolutionArtifact>,
    ) -> Result<Option<(u64, String)>, Error> {
        for entry in entries {
            let selected = BTreeSet::from([entry]);
            let view = biara_lift::resolution_view(cfg, &selected);
            let bytes = view.encode(&self.codec)?;
            let key = store::key(&postcard::to_stdvec(&(
                &self.store.project,
                "resolve",
                max_entries,
                &bytes,
            ))?);
            if let Some(result) = self.store.get(&key)? {
                results.insert(entry, postcard::from_bytes(&result)?);
                self.reused_resolutions += 1;
            } else {
                self.pool()?.send(
                    index,
                    &Request::Resolve {
                        cfg: bytes,
                        entries: selected,
                        max_entries,
                    },
                )?;
                return Ok(Some((entry, key)));
            }
        }
        Ok(None)
    }
}
fn merge(destination: &mut ResolutionArtifact, source: ResolutionArtifact) {
    for (pc, result) in source.targets {
        match destination.targets.entry(pc) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(result);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let old = entry.get_mut();
                old.targets.extend(result.targets);
                old.complete &= result.complete;
                old.limited |= result.limited;
            }
        }
    }
    destination.calls.merge(source.calls);
}
impl Translator for Session {
    fn info(&self) -> &ContextInfo {
        &self.info
    }
    fn prefetch(&mut self, requests: &[TranslationRequest<'_>]) -> Result<(), biara_tcg::Error> {
        self.prefetch_inner(requests)
            .map_err(|e| biara_tcg::Error::Backend(e.to_string()))
    }
    fn translate(
        &mut self,
        code: &[u8],
        code_base: u64,
        pc: u64,
        max_insns: u32,
    ) -> Result<Block, biara_tcg::Error> {
        let request = TranslationRequest {
            code,
            code_base,
            pc,
            max_insns,
        };
        let key = self
            .translation_key(&request)
            .map_err(|e| biara_tcg::Error::Backend(e.to_string()))?;
        self.prefetch(std::slice::from_ref(&request))?;
        let bytes = self
            .cached
            .remove(&key)
            .ok_or_else(|| biara_tcg::Error::Backend("translated block missing".into()))?;
        let result: Result<Vec<u8>, GuestError> =
            postcard::from_bytes(&bytes).map_err(|e| biara_tcg::Error::Codec(e.to_string()))?;
        match result {
            Ok(bytes) => self.codec.decode(&bytes),
            Err(error) => Err(error.into_error()),
        }
    }
}
impl biara_cfg::RecoveryBackend for Session {
    fn checkpoint_cfg(&mut self, cfg: &biara_cfg::Cfg) -> Result<(), biara_cfg::Error> {
        if self.last_checkpoint.elapsed() < Duration::from_secs(2) {
            return Ok(());
        }
        let result = (|| -> Result<(), Error> {
            self.save_checkpoint(cfg, None, false)?;
            self.last_checkpoint = Instant::now();
            eprintln!(
                "analysis: recovering {} candidates; {} committed blocks",
                cfg.functions.len(),
                cfg.blocks.len()
            );
            Ok(())
        })();
        result.map_err(|error| biara_cfg::Error::Backend(error.to_string()))
    }
}
impl biara_lift::RecoveryBackend for Session {
    fn restore(&mut self) -> Result<Option<RecoverySnapshot>, biara_lift::Error> {
        let store::StoredRecovery {
            graph,
            resolver_graph,
            resolver_state,
            finished,
        } = self
            .store
            .state()
            .map_err(|e| biara_lift::Error::Llvm(e.to_string()))?;
        let (manifest, state) = if finished {
            eprintln!("analysis: reusing completed recovery snapshot");
            (graph, RecoveryState::default())
        } else if let Some(manifest) = resolver_graph {
            let bytes = resolver_state.ok_or_else(|| {
                biara_lift::Error::Llvm(
                    "resolver checkpoint is missing its dependency state".into(),
                )
            })?;
            (
                Some(manifest),
                postcard::from_bytes(&bytes).map_err(|e| biara_lift::Error::Llvm(e.to_string()))?,
            )
        } else {
            if resolver_state.is_some() {
                return Err(biara_lift::Error::Llvm(
                    "dependency state has no resolver graph".into(),
                ));
            }
            (graph, RecoveryState::default())
        };
        let Some(bytes) = manifest else {
            if finished {
                return Err(biara_lift::Error::Llvm(
                    "finished recovery has no graph manifest".into(),
                ));
            }
            return Ok(None);
        };
        let project = &self.store.project;
        let backend = |e: Error| biara_tcg::Error::Backend(e.to_string());
        let (cfg, ids) = biara_cfg::Cfg::decode_manifest(
            &bytes,
            &self.codec,
            self.options.workers,
            |id| self.store.block_bytes(id).map_err(backend),
            |id, bytes| store::verify_block(project, id, bytes).map_err(backend),
        )?;
        self.versions.restore(&cfg, ids);
        Ok(Some(RecoverySnapshot {
            cfg,
            state,
            finished,
        }))
    }
    fn checkpoint(
        &mut self,
        cfg: &biara_cfg::Cfg,
        state: &RecoveryState,
    ) -> Result<(), biara_lift::Error> {
        self.save_checkpoint(cfg, Some(state), false)
            .map_err(|e| biara_lift::Error::Llvm(e.to_string()))
    }
    fn resolve(
        &mut self,
        cfg: &biara_cfg::Cfg,
        pending: &BTreeSet<u64>,
        _machine: &inkwell::targets::TargetMachine,
        _read: &dyn Fn(u64, &mut [u8]) -> bool,
        max_entries: u64,
    ) -> Result<ResolutionArtifact, biara_lift::Error> {
        self.resolve_inner(cfg, pending, max_entries)
            .map_err(|e| biara_lift::Error::Llvm(e.to_string()))
    }
}
