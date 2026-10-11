use crate::Error;
use biara_cfg::{BasicBlock, BlockId, Cfg};
use biara_tcg::IrCodec;
use std::{collections::BTreeMap, sync::Arc};

pub(crate) fn block_id(project: &str, bytes: &[u8]) -> BlockId {
    let mut hash = blake3::Hasher::new();
    hash.update(b"biara-cfg-block\0");
    hash.update(project.as_bytes());
    hash.update(bytes);
    *hash.finalize().as_bytes()
}

pub(crate) struct ChangedBlock {
    pub pc: u64,
    pub id: BlockId,
    pub bytes: Vec<u8>,
}
pub(crate) struct Prepared {
    pub manifest: Vec<u8>,
    pub changed: Vec<ChangedBlock>,
}

/// Strong references prevent allocator address reuse and force copy-on-write
/// when a consumer changes a published block. Identity comparisons are exact;
/// unchanged IR is never re-encoded or hashed at a checkpoint.
#[derive(Default)]
pub(crate) struct Versions {
    committed: BTreeMap<u64, (Arc<BasicBlock>, BlockId)>,
}
impl Versions {
    pub fn prepare(&self, cfg: &Cfg, codec: &IrCodec, project: &str) -> Result<Prepared, Error> {
        let mut ids = BTreeMap::new();
        let mut changed = Vec::new();
        for (&pc, block) in &cfg.blocks {
            let id = if let Some((old, id)) = self.committed.get(&pc)
                && Arc::ptr_eq(old, block)
            {
                *id
            } else {
                let bytes = block.encode(codec)?;
                let id = block_id(project, &bytes);
                changed.push(ChangedBlock { pc, id, bytes });
                id
            };
            ids.insert(pc, id);
        }
        Ok(Prepared {
            manifest: cfg.encode_manifest(&ids)?,
            changed,
        })
    }
    /// Publish in-memory versions only after the database transaction commits.
    pub fn commit(&mut self, cfg: &Cfg, prepared: Prepared) {
        self.committed.retain(|pc, _| cfg.blocks.contains_key(pc));
        for block in prepared.changed {
            self.committed
                .insert(block.pc, (Arc::clone(&cfg.blocks[&block.pc]), block.id));
        }
    }
    pub fn restore(&mut self, cfg: &Cfg, ids: BTreeMap<u64, BlockId>) {
        self.committed = ids
            .into_iter()
            .map(|(pc, id)| (pc, (Arc::clone(&cfg.blocks[&pc]), id)))
            .collect();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use crate::{Options, Session};
    use biara_cfg::{Cfg, Options as CfgOptions};
    use biara_lift::{RecoveryBackend, RecoveryState, ResolveOptions};
    use biara_tcg::Libtcg;
    use std::{fs, path::PathBuf};

    const BASE: u64 = 0x1000;
    const CODE: &[u8] = &[0x90, 0xb8, 7, 0, 0, 0, 0xc3]; // nop; mov eax,7; ret
    struct Fixture {
        session: Session,
        directory: PathBuf,
    }
    impl Fixture {
        fn new(name: &str) -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory =
                std::env::temp_dir().join(format!("biara-{name}-{}-{stamp}", std::process::id()));
            fs::create_dir(&directory).unwrap();
            let binary = directory.join("code");
            fs::write(&binary, CODE).unwrap();
            let session = Session::open(
                Options {
                    binary,
                    libtcg: Libtcg::find("x86_64").unwrap(),
                    cpu: None,
                    database: Some(directory.join("analysis.sqlite")),
                    workers: 1,
                    executable: std::env::current_exe().unwrap(),
                },
                &[BASE],
                &ResolveOptions::default(),
            )
            .unwrap();
            Self { session, directory }
        }
        fn recover(&self, entries: &[u64], previous: Cfg) -> Cfg {
            let library = self.session.lib();
            biara_cfg::recover_from(
                &mut *library.lock(),
                |pc| (pc >= BASE && pc - BASE < CODE.len() as u64).then_some((CODE, BASE)),
                entries.iter().copied(),
                &CfgOptions::default(),
                previous,
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn restored_unchanged_ir_is_not_rewritten_when_recovery_metadata_changes() {
        let mut fixture = Fixture::new("checkpoint-reuse");
        let cfg = fixture.recover(&[BASE], Cfg::default());
        fixture.session.save_checkpoint(&cfg, None, false).unwrap();
        let mut restored = fixture.session.restore().unwrap().unwrap().cfg;
        fixture.session.store.db.execute_batch(
            "CREATE TRIGGER forbid_ir_rewrite BEFORE INSERT ON cfg_blocks BEGIN SELECT RAISE(ABORT,'unchanged IR rewritten'); END;"
        ).unwrap();
        restored.recovery.table_entry_limit = 31;
        let state = RecoveryState {
            round: 3,
            ..Default::default()
        };
        fixture
            .session
            .save_checkpoint(&restored, Some(&state), false)
            .unwrap();
        let snapshot = fixture.session.restore().unwrap().unwrap();
        assert_eq!(snapshot.state.round, 3);
        assert_eq!(snapshot.cfg.recovery.table_entry_limit, 31);
        assert_eq!(snapshot.cfg.blocks[&BASE].end(), BASE + CODE.len() as u64);
        assert!(snapshot.cfg.functions[&BASE].returns);
    }

    #[test]
    fn failed_head_publication_rolls_back_blocks_and_retry_restores_the_cut_version() {
        let mut fixture = Fixture::new("checkpoint-atomic-cut");
        let cfg = fixture.recover(&[BASE], Cfg::default());
        fixture.session.save_checkpoint(&cfg, None, false).unwrap();
        let cut = fixture.recover(&[BASE, BASE + 1], cfg);
        let prepared = fixture
            .session
            .versions
            .prepare(&cut, &fixture.session.codec, &fixture.session.store.project)
            .unwrap();
        fixture.session.store.db.execute_batch(
            "CREATE TRIGGER fail_head BEFORE UPDATE ON variants BEGIN SELECT RAISE(ABORT,'head publication failed'); END;"
        ).unwrap();
        assert!(fixture.session.save_checkpoint(&cut, None, true).is_err());
        for block in &prepared.changed {
            assert!(fixture.session.store.block_bytes(&block.id).is_err());
        }
        let stored = fixture.session.store.state().unwrap();
        assert!(!stored.finished);
        let store = &fixture.session.store;
        let project = store.project.as_str();
        let backend = |e: crate::Error| biara_tcg::Error::Backend(e.to_string());
        let (restored, _) = Cfg::decode_manifest(
            &stored.graph.unwrap(),
            &fixture.session.codec,
            2,
            |id| store.block_bytes(id).map_err(backend),
            |id, bytes| crate::store::verify_block(project, id, bytes).map_err(backend),
        )
        .unwrap();
        assert_eq!(restored.blocks[&BASE].end(), BASE + CODE.len() as u64);
        assert!(!restored.functions.contains_key(&(BASE + 1)));
        fixture
            .session
            .store
            .db
            .execute_batch("DROP TRIGGER fail_head;")
            .unwrap();
        fixture.session.save_checkpoint(&cut, None, true).unwrap();
        let restored = fixture.session.restore().unwrap().unwrap();
        assert!(restored.finished);
        assert_eq!(restored.cfg.blocks[&BASE].end(), BASE + 1);
        assert_eq!(
            restored.cfg.functions[&BASE].tail_calls,
            std::collections::BTreeSet::from([BASE + 1])
        );
        assert!(restored.cfg.functions[&(BASE + 1)].returns);
    }

    #[test]
    fn newer_progress_never_replaces_a_resolver_graph_without_its_dependency_state() {
        let mut fixture = Fixture::new("checkpoint-resolver-pair");
        let cfg = fixture.recover(&[BASE], Cfg::default());
        let state = RecoveryState {
            round: 4,
            ..Default::default()
        };
        fixture
            .session
            .save_checkpoint(&cfg, Some(&state), false)
            .unwrap();
        let cut = fixture.recover(&[BASE, BASE + 1], cfg);
        fixture.session.save_checkpoint(&cut, None, false).unwrap();
        let restored = fixture.session.restore().unwrap().unwrap();
        assert_eq!(restored.state.round, 4);
        assert_eq!(restored.cfg.blocks[&BASE].end(), BASE + CODE.len() as u64);
        assert!(!restored.cfg.functions.contains_key(&(BASE + 1)));
        fixture.session.save_checkpoint(&cut, None, true).unwrap();
        let finished = fixture.session.restore().unwrap().unwrap();
        assert!(finished.finished);
        assert_eq!(finished.cfg.blocks[&BASE].end(), BASE + 1);
        assert!(finished.cfg.functions[&(BASE + 1)].returns);
    }
}
