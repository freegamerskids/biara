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
                    memory_budget: biara_proto::MIN_MEMORY_BYTES,
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
    #[test]
    fn payload_codec_roundtrips_through_consumer_restore() {
        // Round-trip property without incidental length asserts: what matters
        // is that an encoded payload restores byte-identical through the same
        // decode path `block_bytes`/`get` use, in both stored forms.
        for raw in [
            vec![0xABu8; 4096],
            b"pp-genuine-prefix".to_vec(),
            b"pz-genuine-prefix".to_vec(),
            b"z-genuine-prefix".to_vec(),
            vec![0u8; 16],
        ] {
            let (codec, payload) = crate::store::encode_blob(&raw).unwrap();
            assert!(codec == crate::store::CODEC_RAW || codec == crate::store::CODEC_ZSTD);
            assert_eq!(crate::store::decode_blob(codec, &payload).unwrap(), raw);
        }
        // Tiny incompressible payloads stay raw (no growth forced), large
        // repetitive ones compress; both still round-trip.
        let (tiny_codec, _) = crate::store::encode_blob(b"0123456789abcdef").unwrap();
        assert_eq!(tiny_codec, crate::store::CODEC_RAW);
        let (big_codec, big_payload) = crate::store::encode_blob(&vec![0xABu8; 1 << 20]).unwrap();
        assert_eq!(big_codec, crate::store::CODEC_ZSTD);
        assert_eq!(
            crate::store::decode_blob(big_codec, &big_payload).unwrap(),
            vec![0xABu8; 1 << 20]
        );
    }
    #[test]
    fn decoded_blocks_do_not_reserve_the_decode_cap() {
        // A cache that keeps decoded blocks must not pay 64 MiB of address space for each.
        let raw = b"a typical small block ".repeat(30);
        let (codec, packed) = crate::store::encode_blob(&raw).unwrap();
        assert_eq!(codec, crate::store::CODEC_ZSTD);
        let kept: Vec<Vec<u8>> = (0..64)
            .map(|_| crate::store::decode_blob(codec, &packed).unwrap())
            .collect();
        assert!(kept.iter().all(|b| b == &raw));
        let reserved: usize = kept.iter().map(Vec::capacity).sum();
        assert!(
            reserved < 1 << 20,
            "64 decoded blocks reserve {reserved} bytes of capacity"
        );
    }

    #[test]
    fn hostile_payloads_are_errors_not_corruption() {
        // Unknown codec markers are errors, never silent passthrough.
        assert!(crate::store::decode_blob(7, b"data").is_err());
        // Truncated zstd frames are errors, not empty data.
        assert!(crate::store::decode_blob(crate::store::CODEC_ZSTD, &[0x28, 0xB5]).is_err());
        // Oversize compressed payloads are bounded: a valid zstd frame whose
        // content exceeds the cap fails instead of expanding in memory.
        let big = vec![0u8; 64 * 1024 * 1024 + 1];
        let compressed = zstd::encode_all(big.as_slice(), 3).unwrap();
        assert!(crate::store::decode_blob(crate::store::CODEC_ZSTD, &compressed).is_err());
        // Encode refuses payloads past the same cap, so writers cannot mint
        // rows that readers must reject.
        assert!(crate::store::encode_blob(&big).is_err());
    }
    #[test]
    fn schema2_rows_migrate_by_hash_or_retire_without_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        // Build a schema 3 checkpoint, then downgrade it to a synthetic
        // schema 2 database: bare postcard/zstd-prefix bytes with no codec
        // column. Reopen must migrate durable `cfg_blocks` by content-address
        // verification (genuine `pp`-prefix payloads keep their first byte)
        // while retiring ambiguous rebuildable `jobs`, and resume must still
        // restore the committed CFG.
        let mut fixture = Fixture::new("checkpoint-migrate-prune");
        let cfg = fixture.recover(&[BASE], Cfg::default());
        fixture.session.save_checkpoint(&cfg, None, false).unwrap();
        let durable: Vec<(Vec<u8>, String, u8, Vec<u8>)> = fixture
            .session
            .store
            .db
            .prepare("SELECT id, project, codec, result FROM cfg_blocks")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(!durable.is_empty());
        let rebuildable: usize = fixture
            .session
            .store
            .db
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
            .unwrap();
        // Downgrade: strip the authoritative marker back to ambiguous
        // prefix-style bytes (raw stays raw, compressed gains a `z` prefix).
        let downgraded: Vec<(Vec<u8>, String, Vec<u8>)> = durable
            .iter()
            .map(|(id, project, codec, payload)| {
                let mut bytes = Vec::new();
                if *codec == crate::store::CODEC_ZSTD {
                    bytes.push(b'z');
                }
                bytes.extend_from_slice(payload);
                (id.clone(), project.clone(), bytes)
            })
            .collect();
        fixture.session.store.db.execute_batch(
            "DROP TABLE jobs; DROP TABLE cfg_blocks;
ALTER TABLE variants DROP COLUMN resolver_graph_codec;
ALTER TABLE variants DROP COLUMN resolver_state_codec;",
        )?;
        fixture.session.store.db.execute_batch(
            "CREATE TABLE jobs(id TEXT PRIMARY KEY,project TEXT NOT NULL,stage TEXT NOT NULL,result BLOB NOT NULL);
CREATE TABLE cfg_blocks(id BLOB PRIMARY KEY,project TEXT NOT NULL,result BLOB NOT NULL);",
        )?;
        for (id, project, bytes) in &downgraded {
            fixture.session.store.db.execute(
                "INSERT INTO cfg_blocks VALUES(?1,?2,?3)",
                rusqlite::params![id, project, bytes],
            )?;
        }
        fixture.session.store.db.execute(
            "INSERT INTO jobs VALUES('rebuildable-synthetic',?1,'translate',?2)",
            rusqlite::params![fixture.session.store.project, vec![0u8; 8]],
        )?;
        fixture
            .session
            .store
            .db
            .execute_batch("PRAGMA user_version=2;")?;
        let directory = fixture.directory.clone();
        let db_path = directory.join("analysis.sqlite");
        let binary = directory.join("code");
        // Close the live session without deleting the database: leak the old
        // handle (test-only), then reopen over the same files.
        let session = Session::open(
            Options {
                binary: binary.clone(),
                libtcg: Libtcg::find("x86_64").unwrap(),
                cpu: None,
                database: Some(directory.join("fresh.sqlite")),
                workers: 1,
                memory_budget: biara_proto::MIN_MEMORY_BYTES,
                executable: std::env::current_exe().unwrap(),
            },
            &[BASE],
            &ResolveOptions::default(),
        )
        .unwrap();
        let old = std::mem::replace(&mut fixture.session, session);
        std::mem::forget(old);
        fixture.session = Session::open(
            Options {
                binary,
                libtcg: Libtcg::find("x86_64").unwrap(),
                cpu: None,
                database: Some(db_path),
                workers: 1,
                memory_budget: biara_proto::MIN_MEMORY_BYTES,
                executable: std::env::current_exe().unwrap(),
            },
            &[BASE],
            &ResolveOptions::default(),
        )
        .unwrap();
        // Ambiguous rebuildable rows are retired (recomputed on resume),
        // durable rows verified by hash: resume restores the committed CFG.
        let jobs: usize = fixture
            .session
            .store
            .db
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(jobs, 0, "schema 2 jobs must retire, not decode by prefix");
        // Resolver heads carry no codec marker in schema 2, so the migration drops them and
        // resume rebuilds from the durable blocks: there is nothing to restore directly.
        assert!(
            fixture.session.restore().unwrap().is_none(),
            "unmarked heads must not be trusted"
        );
        // The durable blocks survive, now with an authoritative codec, and still verify against
        // their content address.
        let check_blocks = |fixture: &Fixture| {
            for (id, project, ..) in &durable {
                let id: [u8; 32] = id.as_slice().try_into().unwrap();
                let bytes = fixture
                    .session
                    .store
                    .block_bytes(&id)
                    .expect("durable block kept");
                crate::store::verify_block(project, &id, &bytes).expect("block verifies by hash");
            }
        };
        check_blocks(&fixture);
        let pruned = fixture.session.prune_rebuildable_cache().unwrap();
        assert_eq!(pruned, 0);
        // Pruning the rebuildable cache never touches durable blocks.
        check_blocks(&fixture);
        // A migrated table has its columns in a different order from a fresh one; what the engine
        // writes afterwards must still land in the right columns and read back intact.
        fixture.session.store.put(
            "probe",
            [(
                "probe-id",
                b"payload that compresses well ".repeat(40).as_slice(),
            )],
        )?;
        let (codec, blob): (u8, Vec<u8>) = fixture.session.store.db.query_row(
            "SELECT codec, result FROM jobs WHERE id='probe-id'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        assert_eq!(
            crate::store::decode_blob(codec, &blob)?,
            b"payload that compresses well ".repeat(40),
            "codec {codec}"
        );
        // The migration recorded its result: opening the same database again is not another
        // migration (it used to fail on `ALTER TABLE ... ADD COLUMN` for a column it had added).
        let version: i64 =
            fixture
                .session
                .store
                .db
                .pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(version, 3, "the schema version is recorded after migrating");
        let again = Session::open(
            Options {
                binary: fixture.directory.join("code"),
                libtcg: Libtcg::find("x86_64").unwrap(),
                cpu: None,
                database: Some(fixture.directory.join("analysis.sqlite")),
                workers: 1,
                memory_budget: biara_proto::MIN_MEMORY_BYTES,
                executable: std::env::current_exe().unwrap(),
            },
            &[BASE],
            &ResolveOptions::default(),
        );
        assert!(
            again.is_ok(),
            "reopening a migrated database must work: {:?}",
            again.err()
        );
        let _ = rebuildable;
        Ok(())
    }
}
