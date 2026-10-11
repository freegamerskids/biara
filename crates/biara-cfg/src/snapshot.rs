use crate::{BasicBlock, Cfg, Exit, Function, IndirectTargets, RecoveryStatus};
use biara_tcg::{Error, IrCodec};
use serde::{Serialize, de::DeserializeOwned, ser::SerializeSeq};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Content-addressed, project-bound immutable block artifact identity.
pub type BlockId = [u8; 32];
type BlockMap = BTreeMap<u64, Arc<BasicBlock>>;
type WireBlock = (u64, Vec<u8>, Vec<u64>, Vec<Exit>, Vec<u64>);
type WireCfg<B> = (
    String,
    B,
    BTreeMap<u64, Function>,
    BTreeMap<u64, String>,
    BTreeMap<u64, BTreeSet<u64>>,
    BTreeSet<u64>,
    BTreeMap<u64, IndirectTargets>,
    BTreeMap<u64, String>,
    BTreeSet<u64>,
    RecoveryStatus,
);

struct Blocks<'a> {
    cfg: &'a Cfg,
    codec: &'a IrCodec,
}
impl Serialize for Blocks<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.cfg.blocks.len()))?;
        for (pc, block) in &self.cfg.blocks {
            let bytes = self
                .codec
                .encode(&block.block)
                .map_err(serde::ser::Error::custom)?;
            sequence.serialize_element(&(
                pc,
                bytes,
                &block.insns,
                &block.exits,
                &block.constants,
            ))?;
        }
        sequence.end()
    }
}

impl BasicBlock {
    /// Encode IR and its derived control-flow facts as one immutable artifact.
    pub fn encode(&self, codec: &IrCodec) -> Result<Vec<u8>, Error> {
        let bytes = codec.encode(&self.block)?;
        postcard::to_stdvec(&(self.pc(), bytes, &self.insns, &self.exits, &self.constants))
            .map_err(|e| Error::Codec(e.to_string()))
    }
    pub fn decode(bytes: &[u8], codec: &IrCodec) -> Result<Self, Error> {
        let wire = postcard::from_bytes(bytes).map_err(|e| Error::Codec(e.to_string()))?;
        Self::from_wire(wire, codec)
    }
    fn from_wire(
        (pc, bytes, insns, exits, constants): WireBlock,
        codec: &IrCodec,
    ) -> Result<Self, Error> {
        let block = codec.decode(&bytes)?;
        if block.pc != pc || exits.iter().any(|e| e.op >= block.ops.len()) {
            return Err(Error::Codec("invalid CFG block identity/exits".into()));
        }
        Ok(Self {
            block,
            insns,
            exits,
            constants,
        })
    }
}

impl Cfg {
    /// Self-contained graph encoding for worker IPC, independent of the database.
    pub fn encode(&self, codec: &IrCodec) -> Result<Vec<u8>, Error> {
        self.encode_with(Blocks { cfg: self, codec })
    }
    /// Encode metadata and exact immutable block references, without serializing IR.
    pub fn encode_manifest(&self, blocks: &BTreeMap<u64, BlockId>) -> Result<Vec<u8>, Error> {
        if !blocks.keys().eq(self.blocks.keys()) {
            return Err(Error::Codec(
                "manifest block addresses do not match CFG".into(),
            ));
        }
        self.encode_with(blocks)
    }
    fn encode_with(&self, blocks: impl Serialize) -> Result<Vec<u8>, Error> {
        postcard::to_stdvec(&(
            self.os,
            blocks,
            &self.functions,
            &self.unresolved,
            &self.jump_tables,
            &self.incomplete_jump_tables,
            &self.indirect_calls,
            &self.imports,
            &self.discovered,
            &self.recovery,
        ))
        .map_err(|e| Error::Codec(e.to_string()))
    }
    pub fn decode(bytes: &[u8], codec: &IrCodec) -> Result<Self, Error> {
        decode_cfg(bytes, |wire: Vec<WireBlock>| {
            let mut blocks = BTreeMap::new();
            for record in wire {
                let block = BasicBlock::from_wire(record, codec)?;
                if blocks.insert(block.pc(), Arc::new(block)).is_some() {
                    return Err(Error::Codec("duplicate CFG block".into()));
                }
            }
            Ok((blocks, ()))
        })
        .map(|(cfg, ())| cfg)
    }
    /// Restore a manifest and return its identities for incremental checkpoint reuse.
    /// `load` fetches artifacts in bounded batches on this thread; `verify`
    /// and IR decoding run on up to `workers` threads. Any failure aborts.
    pub fn decode_manifest(
        bytes: &[u8],
        codec: &IrCodec,
        workers: usize,
        mut load: impl FnMut(&BlockId) -> Result<Vec<u8>, Error>,
        verify: impl Fn(&BlockId, &[u8]) -> Result<(), Error> + Sync,
    ) -> Result<(Self, BTreeMap<u64, BlockId>), Error> {
        // Bounds raw artifact bytes held at once, independent of graph size.
        const BATCH: usize = 4096;
        decode_cfg(bytes, |references: BTreeMap<u64, BlockId>| {
            let mut blocks = BTreeMap::new();
            let references_vec: Vec<_> = references.iter().collect();
            let mut raw = Vec::with_capacity(BATCH.min(references_vec.len()));
            for batch in references_vec.chunks(BATCH) {
                raw.clear();
                for (_, id) in batch {
                    raw.push(load(id)?);
                }
                let decode = |items: &[(&(&u64, &BlockId), &Vec<u8>)]| {
                    items
                        .iter()
                        .map(|&(&(&pc, id), bytes)| {
                            verify(id, bytes)?;
                            let block = BasicBlock::decode(bytes, codec)?;
                            if block.pc() != pc {
                                return Err(Error::Codec(
                                    "manifest references a different block address".into(),
                                ));
                            }
                            Ok(block)
                        })
                        .collect::<Result<Vec<_>, Error>>()
                };
                let items: Vec<_> = batch.iter().zip(&raw).collect();
                let grain = items.len().div_ceil(workers.max(1));
                let decoded = std::thread::scope(|scope| {
                    let handles: Vec<_> = items
                        .chunks(grain)
                        .map(|chunk| scope.spawn(move || decode(chunk)))
                        .collect();
                    handles
                        .into_iter()
                        .map(|handle| handle.join().expect("block decoder panicked"))
                        .collect::<Result<Vec<_>, Error>>()
                })?;
                for (&(&pc, _), block) in batch.iter().zip(decoded.into_iter().flatten()) {
                    blocks.insert(pc, Arc::new(block));
                }
            }
            Ok((blocks, references))
        })
    }
}

fn decode_cfg<B: DeserializeOwned, T>(
    bytes: &[u8],
    load: impl FnOnce(B) -> Result<(BlockMap, T), Error>,
) -> Result<(Cfg, T), Error> {
    let (
        os,
        wire,
        functions,
        unresolved,
        jump_tables,
        incomplete_jump_tables,
        indirect_calls,
        imports,
        discovered,
        recovery,
    ): WireCfg<B> = postcard::from_bytes(bytes).map_err(|e| Error::Codec(e.to_string()))?;
    let os = match os.as_str() {
        "linux" => "linux",
        "windows" => "windows",
        "darwin" => "darwin",
        _ => return Err(Error::Codec("invalid snapshot OS".into())),
    };
    let (blocks, extra) = load(wire)?;
    if functions
        .values()
        .any(|f| f.blocks.iter().any(|b| !blocks.contains_key(b)))
    {
        return Err(Error::Codec("function references absent block".into()));
    }
    Ok((
        Cfg {
            os,
            blocks,
            functions,
            unresolved,
            jump_tables,
            incomplete_jump_tables,
            indirect_calls,
            imports,
            discovered,
            recovery,
        },
        extra,
    ))
}
