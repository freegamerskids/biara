//! Declared object bounds, separate from frame boundaries and runtime identity.
//!
//! Heap origins identify allocation *sites*, not unique runtime objects. In
//! particular realloc may return its input address or a different address, and
//! all allocator results may be null. Equal facts never establish must-alias.

use crate::calls::{Arg, SizeRange};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectOrigin {
    Heap {
        function: u64,
        pc: u64,
        allocator: String,
    },
    Global {
        name: String,
        address: u64,
    },
    Stack {
        function: u64,
        name: String,
        entry_offset: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectEvidence {
    AllocatorArguments { function: u64, pc: u64 },
    DataSymbol { name: String, address: u64 },
    Dwarf { function: u64, pc: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownExtent {
    AllocationSizeUnknown,
    NoDataSymbol,
    NoDebugObject,
    UnresolvedReturn,
    IncomingPointer,
    UnknownPointer,
    OffsetOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectPointer {
    pub origin: Option<ObjectOrigin>,
    /// Signed byte offset from the object start, not from the frame boundary.
    pub offset: i64,
    pub size: Option<SizeRange>,
    pub nullable: bool,
    pub unknown_extent: Option<UnknownExtent>,
    pub evidence: Vec<ObjectEvidence>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectQuery {
    Global {
        address: u64,
    },
    Stack {
        function: u64,
        pc: u64,
        entry_offset: i64,
    },
}

/// A provider must use declared symbol sizes or an exact debug location active
/// at the requested guest PC. Slot spacing and frame size are not object sizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectBound {
    pub origin: ObjectOrigin,
    pub offset: i64,
    pub size: SizeRange,
    pub evidence: ObjectEvidence,
}

/// Facts for one resolved pointer alternative. Resolve internal returns with
/// `CallSites::resolve_arg` first; `OneOf` alternatives should be kept separate.
/// Unknown extent is explicit, and does not imply a safe write.
pub fn pointer_facts(
    arg: &Arg,
    function: u64,
    pc: u64,
    objects: &dyn Fn(ObjectQuery) -> Option<ObjectBound>,
) -> ObjectPointer {
    let unknown = |reason| ObjectPointer {
        origin: None,
        offset: 0,
        size: None,
        nullable: false,
        unknown_extent: Some(reason),
        evidence: Vec::new(),
    };
    let declared = |query, reason| {
        objects(query).map_or_else(
            || unknown(reason),
            |bound| ObjectPointer {
                origin: Some(bound.origin),
                offset: bound.offset,
                size: Some(bound.size),
                nullable: false,
                unknown_extent: None,
                evidence: vec![bound.evidence],
            },
        )
    };
    match arg {
        Arg::Allocation {
            function,
            pc,
            allocator,
            size,
        } => ObjectPointer {
            origin: Some(ObjectOrigin::Heap {
                function: *function,
                pc: *pc,
                allocator: allocator.clone(),
            }),
            offset: 0,
            size: *size,
            nullable: true,
            unknown_extent: size
                .is_none()
                .then_some(UnknownExtent::AllocationSizeUnknown),
            evidence: vec![ObjectEvidence::AllocatorArguments {
                function: *function,
                pc: *pc,
            }],
        },
        Arg::Const(address) => declared(
            ObjectQuery::Global { address: *address },
            UnknownExtent::NoDataSymbol,
        ),
        Arg::Stack(off) => declared(
            ObjectQuery::Stack {
                function,
                pc,
                entry_offset: *off,
            },
            UnknownExtent::NoDebugObject,
        ),
        Arg::Frame { function, pc, off } => declared(
            ObjectQuery::Stack {
                function: *function,
                pc: *pc,
                entry_offset: *off,
            },
            UnknownExtent::NoDebugObject,
        ),
        Arg::Offset { base, off } => {
            let mut facts = pointer_facts(base, function, pc, objects);
            if let Some(offset) = facts.offset.checked_add(*off) {
                facts.offset = offset;
            } else {
                facts.size = None;
                facts.unknown_extent = Some(UnknownExtent::OffsetOverflow);
            }
            facts
        }
        Arg::FunctionResult { .. } | Arg::RegisterResult { .. } => {
            unknown(UnknownExtent::UnresolvedReturn)
        }
        Arg::Incoming(_) | Arg::Deref { .. } => unknown(UnknownExtent::IncomingPointer),
        Arg::Returned { .. }
        | Arg::Load { .. }
        | Arg::Range { .. }
        | Arg::OneOf(_)
        | Arg::Expr { .. }
        | Arg::Unknown => unknown(UnknownExtent::UnknownPointer),
    }
}

impl ObjectPointer {
    /// A possible nonempty write exceeds at least one established size in the
    /// interval. Arithmetic is widened so offset+length cannot wrap to safety.
    pub fn overflows(&self, len: SizeRange) -> bool {
        let Some(size) = self.size else { return false };
        len.hi != 0
            && (self.offset < 0
                || i128::from(self.offset) + i128::from(len.hi) > i128::from(size.lo))
    }
}
