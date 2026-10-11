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
        let (pc,size,icount,ops,globals,local,helpers,nb_labels,temp_args,const_args):WireBlock=
            postcard::from_bytes(bytes).map_err(|e|Error::Codec(e.to_string()))?;
        let globals = globals
            .map(Arc::<[Temp]>::from)
            .unwrap_or_else(|| self.globals.clone());
        let count = globals.len() + local.len();
        if pc.checked_add(u64::from(size)).is_none()
            || temp_args.iter().any(|t| *t as usize >= count)
            || globals
                .iter()
                .chain(&local)
                .any(|t| t.mem_base.is_some_and(|id| id as usize >= count))
        {
            return Err(Error::Codec("invalid block or temporary bounds".into()));
        }
        for op in &ops {
            let end = op.temps as usize + op.nb_out as usize + op.nb_in as usize;
            let constants = op.consts as usize + op.nb_const as usize;
            if op.opc as usize >= self.defs.names.len()
                || end > temp_args.len()
                || constants > const_args.len()
                || self.defs.opcodes[op.opc as usize] != op.opcode
            {
                return Err(Error::Codec("invalid opcode/operand bounds".into()));
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
