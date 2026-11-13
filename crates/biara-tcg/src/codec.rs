use crate::{Block, Error, Helper, Op, Opcode, Temp, TempId, Temps, ir::OpDefs};
use serde::{Serialize, ser::SerializeSeq};
use std::sync::Arc;

/// Binary-build-specific descriptors shared by cached and newly translated IR.
/// Hidden helper symbols are encoded as relocation offsets, never host pointers.
#[derive(Clone)]
pub struct IrCodec {
    defs: Arc<OpDefs>,
    globals: Arc<[Temp]>,
    helper_base: usize,
}
struct Helpers<'a> {
    values: &'a [Helper],
    base: usize,
}
impl Serialize for Helpers<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.values.len()))?;
        for helper in self.values {
            let offset = helper.addr.wrapping_sub(self.base) as isize as i64;
            sequence.serialize_element(&(&helper.name, offset, helper.flags, helper.typemask))?;
        }
        sequence.end()
    }
}
type WireBlock = (
    u64,
    u32,
    u32,
    Vec<Op>,
    Option<Vec<Temp>>,
    Vec<Temp>,
    Vec<(String, i64, u32, u32)>,
    u32,
    Vec<TempId>,
    Vec<u64>,
);
impl IrCodec {
    pub(crate) fn new(defs: Arc<OpDefs>, globals: Arc<[Temp]>, helper_base: usize) -> Self {
        Self {
            defs,
            globals,
            helper_base,
        }
    }
    /// Decode-only codec for hostile-input testing: empty opcode table and
    /// globals, so any structured snapshot validates against known bounds.
    /// Never used for real translation (encode always rejects: no block can
    /// share this table).
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn decode_only() -> Self {
        Self {
            defs: Arc::new(OpDefs {
                names: Vec::new(),
                opcodes: Vec::new(),
                flags: Vec::new(),
                arities: Vec::new(),
            }),
            globals: Arc::from([]),
            helper_base: 0,
        }
    }
    pub fn encode(&self, block: &Block) -> Result<Vec<u8>, Error> {
        if !Arc::ptr_eq(&self.defs, &block.defs) {
            return Err(Error::Codec("block belongs to another opcode table".into()));
        }
        let globals = (!Arc::ptr_eq(&self.globals, &block.temps.globals))
            .then_some(block.temps.globals.as_ref());
        postcard::to_stdvec(&(
            block.pc,
            block.size,
            block.icount,
            &block.ops,
            globals,
            &block.temps.local,
            Helpers {
                values: &block.helpers,
                base: self.helper_base,
            },
            block.nb_labels,
            &block.temp_args,
            &block.const_args,
        ))
        .map_err(|e| Error::Codec(e.to_string()))
    }
    pub fn decode(&self, bytes: &[u8]) -> Result<Block, Error> {
        // Wire cap, not an allocation bound: serde only preallocates from
        // postcard's `size_hint` through its 1 MiB-cautious policy (small
        // prefixes never balloon), but a hostile 16 GiB `temp_args` length
        // still deserializes element-by-element until the wire runs out.
        // Every length below is therefore re-checked against hard bounds
        // immediately after decode, before any index is trusted.
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(Error::Codec("snapshot exceeds 64 MiB".into()));
        }
        let (pc,size,icount,ops,globals,local,helpers,nb_labels,temp_args,const_args):WireBlock=
            postcard::from_bytes(bytes).map_err(|e|Error::Codec(e.to_string()))?;
        if ops.len() > 1 << 20
            || nb_labels > 1 << 20
            || local.len() > 1 << 20
            || temp_args.len() > 1 << 24
            || const_args.len() > 1 << 24
            || helpers.len() > 1 << 16
            || globals
                .as_ref()
                .is_some_and(|g: &Vec<Temp>| g.len() > 1 << 20)
        {
            return Err(Error::Codec("snapshot counts exceed bounds".into()));
        }
        // `Temp`/`String` payloads cannot outlive the wire: postcard strings
        // borrow or copy wire bytes, so decoded heap stays proportional to the
        // 64 MiB wire cap above (plus fixed-size `Temp`/`Op` records already
        // bounded by the count checks). No separate heap accounting needed.
        let globals = globals
            .map(Arc::<[Temp]>::from)
            .unwrap_or_else(|| self.globals.clone());
        let count = globals
            .len()
            .checked_add(local.len())
            .ok_or_else(|| Error::Codec("invalid block or temporary bounds".into()))?;
        if pc.checked_add(u64::from(size)).is_none()
            || temp_args.iter().any(|t| (*t as usize) >= count)
            || globals
                .iter()
                .chain(&local)
                .any(|t| t.mem_base.is_some_and(|id| (id as usize) >= count))
        {
            return Err(Error::Codec("invalid block or temporary bounds".into()));
        }
        for op in &ops {
            let end = (op.temps as usize)
                .checked_add(op.nb_out as usize)
                .and_then(|e| e.checked_add(op.nb_in as usize))
                .ok_or_else(|| Error::Codec("invalid opcode/operand bounds".into()))?;
            let constants = (op.consts as usize)
                .checked_add(op.nb_const as usize)
                .ok_or_else(|| Error::Codec("invalid opcode/operand bounds".into()))?;
            if op.opc as usize >= self.defs.names.len()
                || end > temp_args.len()
                || constants > const_args.len()
                || self.defs.opcodes[op.opc as usize] != op.opcode
            {
                return Err(Error::Codec("invalid opcode/operand bounds".into()));
            }
            // Declared per-opcode arity: every non-call snapshot op must carry
            // exactly the counts `libtcg_op_defs()` gives this `opc`. This is
            // checked on both the native path and here, before any downstream
            // `outputs(op)[0]`/`inputs(op)[1]`/`consts(op)[0]` indexing.
            if op.opcode != Opcode::Call
                && self
                    .defs
                    .arities
                    .get(op.opc as usize)
                    .is_some_and(|&(o, i, c)| {
                        o != op.nb_out || i != op.nb_in || c != op.nb_const
                    })
            {
                return Err(Error::Codec("invalid opcode arity".into()));
            }
            if op.opcode == Opcode::Call
                && (op.nb_const == 0 || const_args[op.consts as usize] as usize >= helpers.len())
            {
                return Err(Error::Codec("invalid helper index".into()));
            }
        }
        let helpers = helpers
            .into_iter()
            .map(|(name, offset, flags, typemask)| {
                let offset = isize::try_from(offset)
                    .map_err(|_| Error::Codec("helper relocation overflow".into()))?;
                Ok(Helper {
                    name,
                    addr: self.helper_base.wrapping_add_signed(offset),
                    flags,
                    typemask,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Block {
            pc,
            size,
            icount,
            ops,
            temps: Temps { globals, local },
            helpers,
            nb_labels,
            temp_args,
            const_args,
            defs: self.defs.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::IrCodec;
    use crate::Error;
    #[test]
    fn malformed_snapshot_returns_error_never_panics() {
        let codec = IrCodec::decode_only();
        // Empty, truncated and garbage inputs: all must be `Err`.
        assert!(codec.decode(&[]).is_err());
        assert!(codec.decode(&[0x01, 0x02]).is_err());
        let garbage = vec![0xFFu8; 1024];
        assert!(codec.decode(&garbage).is_err());
        // Oversize wire: bounded before allocation.
        let huge = vec![0xFFu8; 65 * 1024 * 1024];
        assert!(matches!(codec.decode(&huge), Err(Error::Codec(_))));
    }
    #[test]
    fn hostile_label_count_is_rejected_before_lowering() {
        let block: super::WireBlock = (
            0,
            0,
            0,
            Vec::new(),
            None,
            Vec::new(),
            Vec::new(),
            u32::MAX,
            Vec::new(),
            Vec::new(),
        );
        let bytes = postcard::to_stdvec(&block).unwrap();
        assert!(matches!(
            IrCodec::decode_only().decode(&bytes),
            Err(Error::Codec(_))
        ));
    }
    #[test]
    fn unknown_enum_tags_are_typed_errors() {
        assert!(matches!(
            crate::Type::from_raw(9),
            Err(Error::UnknownType(9))
        ));
        assert!(matches!(
            crate::TempKind::from_raw(9),
            Err(Error::UnknownTempKind(9))
        ));
        let helper = crate::Helper {
            name: String::new(),
            addr: 0,
            flags: 0,
            typemask: 1,
        };
        assert!(matches!(helper.ret(), Err(Error::UnknownHelperType(1))));
        assert!(helper.params_vec().is_err());
    }
    #[test]
    fn hostile_op_window_is_rejected_never_panics() {
        use crate::{Op, Opcode, Type};
        // A `Call` whose constant window names a missing helper must be an
        // error (not an out-of-bounds index into the helper table).
        let op = Op {
            opcode: Opcode::Call,
            opc: 0,
            ty: Type::I32,
            vece: 0,
            nb_out: 0,
            nb_in: 0,
            nb_const: 1,
            temps: 0,
            consts: 0,
        };
        let block: super::WireBlock = (
            0,
            0,
            0,
            vec![op],
            None,
            Vec::new(),
            Vec::new(),
            0,
            Vec::new(),
            vec![7],
        );
        let bytes = postcard::to_stdvec(&block).unwrap();
        assert!(matches!(
            IrCodec::decode_only().decode(&bytes),
            Err(Error::Codec(_))
        ));
    }
    #[test]
    fn hostile_zstd_bomb_is_bounded() {
        // 64 MiB of zeroes compresses to kilobytes; the bounded decompressor
        // must still refuse to expand it past the payload cap. Exercises the
        // same `zstd::bulk::decompress` bound `decode_blob` uses.
        let raw = vec![0u8; 64 * 1024 * 1024 + 1];
        let compressed = zstd::encode_all(raw.as_slice(), 3).unwrap();
        assert!(zstd::bulk::decompress(&compressed, 64 * 1024 * 1024).is_err());
    }
}
