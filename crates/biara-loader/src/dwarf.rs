//! Conservative whole-variable DWARF bounds plus function-entry formal
//! parameter registers and declared type descriptions. A register location
//! is converted only when a covering unwind row expresses the CFA in that
//! same register. In particular, SP-relative locations under an FP-based CFA
//! remain unknown rather than assuming SP stayed fixed. Offsets and validity
//! vary by CFA row, including rows before the function's frame has been
//! allocated.
//!
//! Function-entry names are even more conservative: only a direct single
//! `DW_OP_regN` location whose range covers the function's entry PC
//! qualifies as a formal parameter's entry register. Declaration and origin
//! links supply names and types only, never locations. Ambiguous
//! register/name evidence is dropped, never forced. Type descriptions spell
//! supported base/typedef-qualified names, arrays with known bounds,
//! aggregates with members, and function pointers accurately; anything else
//! (recursion, depth/overflow, bit-fields, array or qualified indirection,
//! unsupported compositions) is `None`. Missing pointer/subroutine types
//! mean void as specified by DWARF; unresolved references remain unknown.
//! Types are evidence for naming only and never change offsets.

use std::{borrow::Cow, collections::BTreeMap, ops::Range};

use gimli::{AttributeValue, EndianSlice, RunTimeEndian, UnwindSection};
use object::{Object, ObjectSection};

use crate::{DebugName, DebugStatus, StackObject};

pub(crate) struct DebugOutput {
    pub(crate) stack_objects: Vec<StackObject>,
    pub(crate) names: Vec<DebugName>,
}

type R<'a> = EndianSlice<'a, RunTimeEndian>;
type Attr<'a> = AttributeValue<R<'a>>;

#[derive(Clone)]
struct Cfa {
    range: Range<u64>,
    register: gimli::Register,
    offset: i64,
}

#[derive(Clone)]
struct Location<'a> {
    range: Range<u64>,
    expression: gimli::Expression<R<'a>>,
}

/// Bounded caches shared by one unit's type queries. Sizes and descriptions
/// are memoized by DIE offset; in-progress entries read back as absent so
/// recursive types terminate instead of recursing forever.
#[derive(Default)]
struct TypeCache {
    sizes: BTreeMap<usize, Option<u64>>,
    descriptions: BTreeMap<usize, Option<String>>,
}

/// Conservative type descriptions: at most this many DIEs visited and this
/// many characters emitted per variable type. Deeper or longer spellings
/// become `None` rather than unbounded strings.
const MAX_TYPE_DEPTH: usize = 64;
const MAX_TYPE_LEN: usize = 512;

#[derive(Clone, Default)]
struct Scope<'a> {
    function: Option<u64>,
    ranges: Vec<Range<u64>>,
    frame: Vec<Location<'a>>,
}

pub(crate) fn read(file: &object::File<'_>) -> (DebugOutput, DebugStatus) {
    let mut status = DebugStatus {
        present: file.sections().any(|s| {
            s.name().is_ok_and(|n| {
                n.starts_with(".debug_")
                    || n.starts_with(".zdebug_")
                    || n.starts_with("__debug_")
                    || n.starts_with("__zdebug_")
            })
        }),
        ..DebugStatus::default()
    };
    let mut output = DebugOutput {
        stack_objects: Vec::new(),
        names: Vec::new(),
    };
    if !status.present {
        return (output, status);
    }
    let entry_cfa = match file.architecture() {
        object::Architecture::X86_64 => 8,
        object::Architecture::Aarch64 => 0,
        _ => {
            status
                .errors
                .push("stack locations unsupported for this architecture".into());
            return (output, status);
        }
    };
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let sections = match gimli::DwarfSections::load(|id| section(file, id.name())) {
        Ok(sections) => sections,
        Err(error) => {
            status.errors.push(format!("DWARF sections: {error}"));
            return (output, status);
        }
    };
    let dwarf = sections.borrow(|bytes| EndianSlice::new(bytes, endian));
    let rows = unwind(file, endian, &mut status);
    let mut units = dwarf.units();
    loop {
        let header = match units.next() {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(error) => {
                status.errors.push(format!("DWARF unit header: {error}"));
                break;
            }
        };
        let unit = match dwarf.unit(header) {
            Ok(unit) => unit,
            Err(error) => {
                status.errors.push(format!("DWARF unit: {error}"));
                continue;
            }
        };
        // Commit a unit only after the entire tree has parsed successfully.
        // Malformed scope/range metadata must not leave purported bounds behind.
        let mut unit_output = DebugOutput {
            stack_objects: Vec::new(),
            names: Vec::new(),
        };
        match read_unit(
            &dwarf,
            &unit,
            &rows,
            entry_cfa,
            &mut status,
            &mut unit_output,
        ) {
            Ok(()) => {
                output.stack_objects.extend(unit_output.stack_objects);
                output.names.extend(unit_output.names);
            }
            Err(error) => status.errors.push(format!("DWARF entries: {error}")),
        }
    }
    // Reject ambiguous evidence: one name per function+register, one register
    // per function+name. Either collision means the compiler reused the slot
    // or the name, so neither mapping can be trusted as entry evidence.
    output.names = disambiguate_names(output.names, &mut status);
    let objects = &mut output.stack_objects;
    objects.sort_by(|a, b| {
        (
            a.function,
            a.range.start,
            a.range.end,
            a.offset,
            &a.name,
            a.type_name.as_ref(),
        )
            .cmp(&(
                b.function,
                b.range.start,
                b.range.end,
                b.offset,
                &b.name,
                b.type_name.as_ref(),
            ))
    });
    objects.dedup_by(|a, b| {
        a.function == b.function
            && a.range == b.range
            && a.offset == b.offset
            && a.size == b.size
            && a.name == b.name
            && a.type_name == b.type_name
    });
    output
        .names
        .sort_by(|a, b| (a.function, a.register, &a.name).cmp(&(b.function, b.register, &b.name)));
    output
        .names
        .dedup_by(|a, b| a.function == b.function && a.register == b.register && a.name == b.name);
    (output, status)
}

fn section<'a>(file: &object::File<'a>, name: &str) -> object::Result<Cow<'a, [u8]>> {
    // Object handles ELF SHF_COMPRESSED, GNU .zdebug_ and Mach-O names.
    match file.section_by_name(name) {
        Some(section) => section.uncompressed_data(),
        None => Ok(Cow::Borrowed(&[])),
    }
}

fn unwind(file: &object::File<'_>, endian: RunTimeEndian, status: &mut DebugStatus) -> Vec<Cfa> {
    let mut rows = Vec::new();
    for name in [".eh_frame", ".debug_frame"] {
        let Some(s) = file.section_by_name(name) else {
            continue;
        };
        let bytes = match s.uncompressed_data() {
            Ok(bytes) => bytes,
            Err(error) => {
                status.errors.push(format!("{name}: {error}"));
                continue;
            }
        };
        let mut bases = gimli::BaseAddresses::default().set_eh_frame(s.address());
        if let Some(text) = file.section_by_name(".text") {
            bases = bases.set_text(text.address());
        }
        if let Some(got) = file.section_by_name(".got") {
            bases = bases.set_got(got.address());
        }
        let result = if name == ".eh_frame" {
            let mut frame = gimli::EhFrame::new(&bytes, endian);
            frame.set_address_size(if file.is_64() { 8 } else { 4 });
            collect_rows(&frame, &bases, &mut rows)
        } else {
            let mut frame = gimli::DebugFrame::new(&bytes, endian);
            frame.set_address_size(if file.is_64() { 8 } else { 4 });
            collect_rows(&frame, &bases, &mut rows)
        };
        if let Err(error) = result {
            status.errors.push(format!("{name}: {error}"));
        }
    }
    rows
}

fn collect_rows<'a, S: UnwindSection<R<'a>>>(
    section: &S,
    bases: &gimli::BaseAddresses,
    out: &mut Vec<Cfa>,
) -> gimli::Result<()> {
    let mut entries = section.entries(bases);
    let mut context = gimli::UnwindContext::new();
    while let Some(entry) = entries.next()? {
        if let gimli::CieOrFde::Fde(partial) = entry {
            let fde = partial.parse(|s, b, o| s.cie_from_offset(b, o))?;
            let mut table = fde.rows(section, bases, &mut context)?;
            let mut fde_rows = Vec::new();
            while let Some(row) = table.next_row()? {
                if let gimli::CfaRule::RegisterAndOffset { register, offset } = row.cfa() {
                    fde_rows.push(Cfa {
                        range: row.start_address()..row.end_address(),
                        register: *register,
                        offset: *offset,
                    });
                }
            }
            out.extend(fde_rows);
        }
    }
    Ok(())
}

fn intersections(left: &[Range<u64>], right: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut result = Vec::new();
    for a in left {
        for b in right {
            let start = a.start.max(b.start);
            let end = a.end.min(b.end);
            if start < end {
                result.push(start..end);
            }
        }
    }
    result
}

fn die_ranges<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    entry: &gimli::DebuggingInformationEntry<R<'a>>,
) -> gimli::Result<Vec<Range<u64>>> {
    let mut ranges = dwarf.die_ranges(unit, entry)?;
    let mut out = Vec::new();
    while let Some(range) = ranges.next()? {
        if range.begin < range.end {
            out.push(range.begin..range.end);
        }
    }
    Ok(out)
}

fn locations<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    attr: Attr<'a>,
    ranges: &[Range<u64>],
) -> gimli::Result<Vec<Location<'a>>> {
    if let AttributeValue::Exprloc(expression) = attr {
        return Ok(ranges
            .iter()
            .cloned()
            .map(|range| Location { range, expression })
            .collect());
    }
    let mut out = Vec::new();
    if let Some(mut list) = dwarf.attr_locations(unit, attr)? {
        while let Some(location) = list.next()? {
            for range in intersections(
                ranges,
                std::slice::from_ref(&(location.range.begin..location.range.end)),
            ) {
                out.push(Location {
                    range,
                    expression: location.data,
                });
            }
        }
    }
    Ok(out)
}

// Follow declaration/origin links for names and types, never for locations:
// an abstract declaration does not establish a live storage location.
fn inherited<'a>(
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
    name: gimli::DwAt,
    depth: usize,
) -> gimli::Result<Option<Attr<'a>>> {
    if depth > 32 {
        return Ok(None);
    }
    let entry = unit.entry(offset)?;
    if let Some(value) = entry.attr_value(name) {
        return Ok(Some(value));
    }
    for link in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
        if let Some(value) = entry.attr_value(link)
            && let Some(offset) = local_ref(unit, value)
            && let Some(value) = inherited(unit, offset, name, depth + 1)?
        {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

// A variable's declared name: present on the DIE or inherited through
// declaration/origin links, never from a location. Absent or non-string is
// `None`; malformed string references propagate as unit errors, never as
// partial facts.
fn inherited_name<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
) -> gimli::Result<Option<String>> {
    let Some(value) = inherited(unit, offset, gimli::DW_AT_name, 0)? else {
        return Ok(None);
    };
    Ok(Some(
        dwarf
            .attr_string(unit, value)?
            .to_string_lossy()
            .into_owned(),
    ))
}

fn local_ref(unit: &gimli::Unit<R<'_>>, value: Attr<'_>) -> Option<gimli::UnitOffset> {
    match value {
        AttributeValue::UnitRef(offset) => Some(offset),
        AttributeValue::DebugInfoRef(offset) => offset.to_unit_offset(&unit.header),
        _ => None,
    }
}

fn type_size<'a>(
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
    cache: &mut TypeCache,
    depth: usize,
) -> gimli::Result<Option<u64>> {
    if depth > MAX_TYPE_DEPTH {
        return Ok(None);
    }
    if let Some(size) = cache.sizes.get(&offset.0) {
        return Ok(*size);
    }
    // Break recursive aliases without interpreting pointers as pointees.
    cache.sizes.insert(offset.0, None);
    let entry = unit.entry(offset)?;
    let mut size = entry
        .attr_value(gimli::DW_AT_byte_size)
        .and_then(|v| v.udata_value());
    if size.is_none() {
        match entry.tag() {
            gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type => {
                size = Some(u64::from(unit.encoding().address_size));
            }
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type => {
                if let Some(reference) = entry
                    .attr_value(gimli::DW_AT_type)
                    .and_then(|v| local_ref(unit, v))
                {
                    size = type_size(unit, reference, cache, depth + 1)?;
                }
            }
            gimli::DW_TAG_array_type => {
                if let Some(reference) = entry
                    .attr_value(gimli::DW_AT_type)
                    .and_then(|v| local_ref(unit, v))
                {
                    let mut product = type_size(unit, reference, cache, depth + 1)?;
                    if entry.attr_value(gimli::DW_AT_byte_stride).is_some()
                        || entry.attr_value(gimli::DW_AT_bit_stride).is_some()
                    {
                        // Non-contiguous layouts need an explicit byte size;
                        // multiplying element sizes would understate bounds.
                        return Ok(None);
                    }
                    let mut dimensions = 0;
                    let mut tree = unit.entries_tree(Some(offset))?;
                    let root = tree.root()?;
                    let mut children = root.children();
                    while let Some(child) = children.next()? {
                        let subrange = child.entry();
                        if subrange.tag() != gimli::DW_TAG_subrange_type {
                            continue;
                        }
                        if subrange.attr_value(gimli::DW_AT_byte_stride).is_some()
                            || subrange.attr_value(gimli::DW_AT_bit_stride).is_some()
                        {
                            return Ok(None);
                        }
                        dimensions += 1;
                        let count = match subrange.attr_value(gimli::DW_AT_count) {
                            Some(value) => value.udata_value(),
                            None => {
                                let upper =
                                    subrange.attr_value(gimli::DW_AT_upper_bound).and_then(|v| {
                                        v.udata_value()
                                            .map(i128::from)
                                            .or_else(|| v.sdata_value().map(i128::from))
                                    });
                                let lower = subrange
                                    .attr_value(gimli::DW_AT_lower_bound)
                                    .and_then(|v| {
                                        v.udata_value()
                                            .map(i128::from)
                                            .or_else(|| v.sdata_value().map(i128::from))
                                    })
                                    .or_else(|| default_lower_bound(unit));
                                upper
                                    .zip(lower)
                                    .and_then(|(u, l)| u.checked_sub(l)?.checked_add(1))
                                    .and_then(|n| u64::try_from(n).ok())
                            }
                        };
                        product = product.zip(count).and_then(|(a, b)| a.checked_mul(b));
                    }
                    if dimensions > 0 {
                        size = product;
                    }
                }
            }
            _ => {}
        }
    }
    cache.sizes.insert(offset.0, size);
    Ok(size)
}

/// The declared spelling of a variable's type, or a conservative description
/// built only from facts the DIEs state exactly. Supported: base names,
/// `typedef`/qualified aliases (spelled without qualifiers), pointers and
/// references to a representable pointee, arrays with every bound known,
/// aggregates whose members are all representable with known byte offsets,
/// enumerations by name, and `void`. Unsupported is `None`: declarations
/// (`DW_AT_declaration`), bit-fields/bit offsets, stride layouts, missing or
/// dynamic bounds, member offsets that overflow, recursion, depth beyond
/// `MAX_TYPE_DEPTH`, or spellings beyond `MAX_TYPE_LEN`.
fn type_description<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
    cache: &mut TypeCache,
    depth: usize,
) -> gimli::Result<Option<String>> {
    if depth > MAX_TYPE_DEPTH {
        return Ok(None);
    }
    if let Some(cached) = cache.descriptions.get(&offset.0) {
        return Ok(cached.clone());
    }
    // In-progress reads as absent so recursive types terminate as `None`.
    cache.descriptions.insert(offset.0, None);
    let description = describe_type(dwarf, unit, offset, cache, depth)?;
    if description.as_ref().is_some_and(|s| s.len() > MAX_TYPE_LEN) {
        cache.descriptions.insert(offset.0, None);
        return Ok(None);
    }
    cache.descriptions.insert(offset.0, description.clone());
    Ok(description)
}

fn describe_type<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
    cache: &mut TypeCache,
    depth: usize,
) -> gimli::Result<Option<String>> {
    let entry = unit.entry(offset)?;
    if entry.attr_value(gimli::DW_AT_declaration).is_some() {
        return Ok(None);
    }
    let name = || {
        inherited(unit, offset, gimli::DW_AT_name, 0)?
            .map(|value| {
                dwarf
                    .attr_string(unit, value)
                    .map(|s| s.to_string_lossy().into_owned())
            })
            .transpose()
    };
    match entry.tag() {
        gimli::DW_TAG_base_type | gimli::DW_TAG_enumeration_type => Ok(name()?),
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_atomic_type => {
            if let Some(aliased) = entry
                .attr_value(gimli::DW_AT_type)
                .and_then(|value| local_ref(unit, value))
            {
                // Prefer the alias spelling when present (`Row`, `Payload`);
                // anonymous qualifiers fall through to the aliased description.
                if let Some(spelling) = name()?
                    && !spelling.is_empty()
                {
                    return Ok(Some(spelling));
                }
                type_description(dwarf, unit, aliased, cache, depth + 1)
            } else {
                // `void` (`void`, not `void*`) has no `DW_AT_type`.
                Ok(name()?)
            }
        }
        gimli::DW_TAG_pointer_type
        | gimli::DW_TAG_reference_type
        | gimli::DW_TAG_rvalue_reference_type => {
            describe_indirect(dwarf, unit, offset, cache, depth)
        }
        gimli::DW_TAG_array_type => describe_array(dwarf, unit, offset, cache, depth),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type => {
            describe_aggregate(dwarf, unit, offset, cache, depth)
        }
        gimli::DW_TAG_subroutine_type => describe_function(dwarf, unit, offset, cache, depth, ""),
        gimli::DW_TAG_string_type => Ok(name()?),
        _ => Ok(None),
    }
}
// Build indirection from DIE structure, not by appending `*` to a function
// spelling (which incorrectly describes a pointer as a function returning one).
fn describe_indirect<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    mut offset: gimli::UnitOffset,
    cache: &mut TypeCache,
    mut depth: usize,
) -> gimli::Result<Option<String>> {
    let mut operators = Vec::new();
    loop {
        if depth > MAX_TYPE_DEPTH {
            return Ok(None);
        }
        let entry = unit.entry(offset)?;
        let operator = match entry.tag() {
            gimli::DW_TAG_pointer_type => "*",
            gimli::DW_TAG_reference_type => "&",
            gimli::DW_TAG_rvalue_reference_type => "&&",
            gimli::DW_TAG_subroutine_type => {
                let operators: String = operators.iter().rev().copied().collect();
                return describe_function(dwarf, unit, offset, cache, depth, &operators);
            }
            // Arrays and qualified indirection need richer declarators;
            // retain unknown rather than emit misleading C type evidence.
            gimli::DW_TAG_array_type
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type => return Ok(None),
            _ => {
                return Ok(
                    type_description(dwarf, unit, offset, cache, depth)?.map(|target| {
                        let operators: String = operators.iter().rev().copied().collect();
                        format!("{target} {operators}")
                    }),
                );
            }
        };
        operators.push(operator);
        match entry.attr_value(gimli::DW_AT_type) {
            Some(value) => match local_ref(unit, value) {
                Some(next) => offset = next,
                None => return Ok(None),
            },
            None if entry.tag() == gimli::DW_TAG_pointer_type => {
                let operators: String = operators.iter().rev().copied().collect();
                return Ok(Some(format!("void {operators}")));
            }
            None => return Ok(None),
        }
        depth += 1;
    }
}

// `element[N][M]`, rendered only when every bound is statically known.
// `DW_AT_byte_size` alone is not a bound: it cannot distinguish trailing
// padding from element counts. Strided or dynamic layouts are `None`.
fn describe_array<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
    cache: &mut TypeCache,
    depth: usize,
) -> gimli::Result<Option<String>> {
    let entry = unit.entry(offset)?;
    let Some(element) = entry
        .attr_value(gimli::DW_AT_type)
        .and_then(|value| local_ref(unit, value))
    else {
        return Ok(None);
    };
    let element = match type_description(dwarf, unit, element, cache, depth + 1)? {
        Some(element) => element,
        None => return Ok(None),
    };
    if entry.attr_value(gimli::DW_AT_byte_stride).is_some()
        || entry.attr_value(gimli::DW_AT_bit_stride).is_some()
    {
        return Ok(None);
    }
    let mut bounds = Vec::new();
    let mut tree = unit.entries_tree(Some(offset))?;
    let root = tree.root()?;
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let subrange = child.entry();
        if subrange.tag() != gimli::DW_TAG_subrange_type {
            continue;
        }
        if subrange.attr_value(gimli::DW_AT_byte_stride).is_some()
            || subrange.attr_value(gimli::DW_AT_bit_stride).is_some()
        {
            return Ok(None);
        }
        let count = match subrange.attr_value(gimli::DW_AT_count) {
            Some(value) => value.udata_value(),
            None => {
                let upper = subrange.attr_value(gimli::DW_AT_upper_bound).and_then(|v| {
                    v.udata_value()
                        .map(i128::from)
                        .or_else(|| v.sdata_value().map(i128::from))
                });
                let lower = subrange
                    .attr_value(gimli::DW_AT_lower_bound)
                    .and_then(|v| {
                        v.udata_value()
                            .map(i128::from)
                            .or_else(|| v.sdata_value().map(i128::from))
                    })
                    .or_else(|| default_lower_bound(unit));
                match upper.zip(lower) {
                    Some((upper, lower)) => upper
                        .checked_sub(lower)
                        .and_then(|n| n.checked_add(1))
                        .and_then(|n| u64::try_from(n).ok()),
                    None => None,
                }
            }
        };
        let Some(count) = count else {
            return Ok(None);
        };
        bounds.push(count);
    }
    if bounds.is_empty() {
        return Ok(None);
    }
    let mut spelling = element;
    for bound in bounds {
        spelling.push('[');
        spelling.push_str(&bound.to_string());
        spelling.push(']');
        if spelling.len() > MAX_TYPE_LEN {
            return Ok(None);
        }
    }
    Ok(Some(spelling))
}

// `struct Name { member: type @ offset; ... }` (or `class`/`union`), with
// member byte offsets from `DW_AT_data_member_location`. Only plain constant
// offsets qualify; bit-fields, bit offsets, and location expressions that do
// not reduce to a constant are `None`. The spelling mirrors the DIEs exactly
// so evidence readers can match members without guessing layout.
fn describe_aggregate<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
    cache: &mut TypeCache,
    depth: usize,
) -> gimli::Result<Option<String>> {
    let entry = unit.entry(offset)?;
    let keyword = match entry.tag() {
        gimli::DW_TAG_class_type => "class",
        gimli::DW_TAG_union_type => "union",
        _ => "struct",
    };
    let mut spelling = keyword.to_owned();
    if let Some(name) = inherited(unit, offset, gimli::DW_AT_name, 0)?
        .map(|value| {
            dwarf
                .attr_string(unit, value)
                .map(|s| s.to_string_lossy().into_owned())
        })
        .transpose()?
        .filter(|name| !name.is_empty())
    {
        spelling.push(' ');
        spelling.push_str(&name);
    }
    spelling.push_str(" { ");
    let mut members = 0;
    let mut tree = unit.entries_tree(Some(offset))?;
    let root = tree.root()?;
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let member = child.entry();
        if member.tag() != gimli::DW_TAG_member {
            continue;
        }
        if member.attr_value(gimli::DW_AT_bit_size).is_some()
            || member.attr_value(gimli::DW_AT_bit_offset).is_some()
            || member.attr_value(gimli::DW_AT_data_bit_offset).is_some()
        {
            return Ok(None);
        }
        let member_name = member
            .attr_value(gimli::DW_AT_name)
            .map(|value| {
                dwarf
                    .attr_string(unit, value)
                    .map(|s| s.to_string_lossy().into_owned())
            })
            .transpose()?
            .filter(|name| !name.is_empty());
        let Some(member_name) = member_name else {
            return Ok(None);
        };
        let Some(member_type) = member
            .attr_value(gimli::DW_AT_type)
            .and_then(|value| local_ref(unit, value))
        else {
            return Ok(None);
        };
        let member_type = match type_description(dwarf, unit, member_type, cache, depth + 1)? {
            Some(member_type) => member_type,
            None => return Ok(None),
        };
        let Some(at) = member.attr_value(gimli::DW_AT_data_member_location) else {
            return Ok(None);
        };
        let Some(byte_offset) = at
            .udata_value()
            .or_else(|| at.sdata_value().and_then(|n| u64::try_from(n).ok()))
        else {
            return Ok(None);
        };
        if members > 0 {
            spelling.push_str(", ");
        }
        spelling.push_str(&member_name);
        spelling.push_str(": ");
        spelling.push_str(&member_type);
        spelling.push_str(" @ ");
        spelling.push_str(&byte_offset.to_string());
        if spelling.len() > MAX_TYPE_LEN {
            return Ok(None);
        }
        members += 1;
    }
    if members == 0 {
        return Ok(None);
    }
    spelling.push_str(" }");
    Ok(Some(spelling))
}

// `return (params...)`: parameter types in order, `...` for variadics.
fn describe_function<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
    cache: &mut TypeCache,
    depth: usize,
    operators: &str,
) -> gimli::Result<Option<String>> {
    let entry = unit.entry(offset)?;
    let returns = match entry.attr_value(gimli::DW_AT_type) {
        Some(value) => match local_ref(unit, value) {
            Some(reference) => type_description(dwarf, unit, reference, cache, depth + 1)?,
            None => None,
        },
        // DWARF specifies a missing subroutine return type as void.
        None => Some("void".to_owned()),
    };
    let Some(returns) = returns else {
        return Ok(None);
    };
    let mut parameters = Vec::new();
    let mut variadic = false;
    let mut tree = unit.entries_tree(Some(offset))?;
    let root = tree.root()?;
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let parameter = child.entry();
        match parameter.tag() {
            gimli::DW_TAG_formal_parameter => {
                let Some(typed) = parameter
                    .attr_value(gimli::DW_AT_type)
                    .and_then(|value| local_ref(unit, value))
                else {
                    return Ok(None);
                };
                let Some(spelling) = type_description(dwarf, unit, typed, cache, depth + 1)? else {
                    return Ok(None);
                };
                if spelling.is_empty() {
                    return Ok(None);
                }
                parameters.push(spelling);
            }
            gimli::DW_TAG_unspecified_parameters => variadic = true,
            _ => continue,
        }
    }
    let mut text = returns;
    if !operators.is_empty() {
        text.push_str(" (");
        text.push_str(operators);
        text.push(')');
    }
    text.push_str(if operators.is_empty() { " (" } else { "(" });
    for (index, parameter) in parameters.iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        text.push_str(parameter);
        if text.len() > MAX_TYPE_LEN {
            return Ok(None);
        }
    }
    if variadic {
        if !parameters.is_empty() {
            text.push_str(", ");
        }
        text.push_str("...");
    }
    text.push(')');
    Ok(Some(text))
}

fn default_lower_bound(unit: &gimli::Unit<R<'_>>) -> Option<i128> {
    // A missing lower bound is language-dependent, not universally zero.
    let mut entries = unit.entries();
    let root = entries.next_dfs().ok()??;
    match root.attr_value(gimli::DW_AT_language)? {
        AttributeValue::Language(language) => language.default_lower_bound().map(|n| n as i128),
        _ => None,
    }
}

fn read_unit<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    rows: &[Cfa],
    entry_cfa: i64,
    status: &mut DebugStatus,
    output: &mut DebugOutput,
) -> gimli::Result<()> {
    let mut entries = unit.entries();
    let mut parents: Vec<Scope<'a>> = vec![Scope::default()];
    let mut types = TypeCache::default();
    while let Some(entry) = entries.next_dfs()? {
        let level = usize::try_from(entry.depth()).map_err(|_| gimli::Error::AddressOverflow)?;
        parents.truncate(level + 1);
        let mut scope = parents.last().cloned().unwrap_or_default();
        match entry.tag() {
            gimli::DW_TAG_subprogram => {
                let ranges = die_ranges(dwarf, unit, entry)?;
                let function = entry
                    .attr_value(gimli::DW_AT_entry_pc)
                    .or(entry.attr_value(gimli::DW_AT_low_pc))
                    .map(|value| dwarf.attr_address(unit, value))
                    .transpose()?
                    .flatten()
                    .or_else(|| ranges.iter().map(|r| r.start).min());
                scope = Scope {
                    function,
                    ranges,
                    frame: Vec::new(),
                };
                if let Some(frame) = entry.attr_value(gimli::DW_AT_frame_base) {
                    scope.frame = locations(dwarf, unit, frame, &scope.ranges)?;
                }
            }
            gimli::DW_TAG_lexical_block | gimli::DW_TAG_inlined_subroutine => {
                // A range-less lexical block inherits its enclosing scope. An
                // explicitly empty range list, in contrast, has no live PCs.
                if entry.attr_value(gimli::DW_AT_ranges).is_some()
                    || entry.attr_value(gimli::DW_AT_low_pc).is_some()
                {
                    scope.ranges = intersections(&scope.ranges, &die_ranges(dwarf, unit, entry)?);
                }
            }
            gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter => {
                if let (Some(function), Some(location)) =
                    (scope.function, entry.attr_value(gimli::DW_AT_location))
                {
                    let is_parameter = entry.tag() == gimli::DW_TAG_formal_parameter;
                    let mut variable_ranges = scope.ranges.clone();
                    if let Some(start) = entry.attr_value(gimli::DW_AT_start_scope) {
                        if let Some(offset) = start.udata_value() {
                            let first = scope
                                .ranges
                                .iter()
                                .map(|r| r.start)
                                .min()
                                .and_then(|first| first.checked_add(offset));
                            variable_ranges = first
                                .map(|first| {
                                    intersections(
                                        &scope.ranges,
                                        std::slice::from_ref(&(first..u64::MAX)),
                                    )
                                })
                                .unwrap_or_default();
                        } else if let Some(mut ranges) = dwarf.attr_ranges(unit, start)? {
                            let mut declared = Vec::new();
                            while let Some(range) = ranges.next()? {
                                declared.push(range.begin..range.end);
                            }
                            variable_ranges = intersections(&scope.ranges, &declared);
                        } else {
                            variable_ranges.clear();
                            status.unsupported_locations += 1;
                        }
                    }
                    let name: gimli::Result<Option<String>> =
                        inherited_name(dwarf, unit, entry.offset());
                    let reference = inherited(unit, entry.offset(), gimli::DW_AT_type, 0)?
                        .and_then(|value| local_ref(unit, value));
                    let size = match reference {
                        Some(reference) => type_size(unit, reference, &mut types, 0)?,
                        None => None,
                    };
                    let type_name = match reference {
                        Some(reference) => type_description(dwarf, unit, reference, &mut types, 0)?,
                        None => None,
                    };
                    let locations = locations(dwarf, unit, location, &variable_ranges)?;
                    if locations.is_empty() {
                        status.unsupported_locations += 1;
                    }
                    if is_parameter {
                        // Entry registers are precise facts, not liveness: the
                        // range must cover the function entry, and the location
                        // must be exactly one bare register there.
                        let entry_pc = scope.ranges.iter().map(|r| r.start).min();
                        match (&name, entry_pc) {
                            (Ok(Some(parameter)), Some(entry_pc)) if !parameter.is_empty() => {
                                emit_entry_name(
                                    unit.encoding(),
                                    entry_pc,
                                    &locations,
                                    type_name.clone(),
                                    function,
                                    parameter,
                                    status,
                                    output,
                                )?;
                            }
                            _ => {
                                status.unsupported_locations += 1;
                            }
                        }
                    }
                    let name = name?.unwrap_or_default();
                    if let Some(size) = size.filter(|&size| size > 0) {
                        for location in locations {
                            emit_location(
                                unit,
                                &scope,
                                rows,
                                entry_cfa,
                                VariableLocation {
                                    function,
                                    name: &name,
                                    size,
                                    type_name: type_name.clone(),
                                    location,
                                },
                                status,
                                &mut output.stack_objects,
                            )?;
                        }
                    } else {
                        status.unsupported_locations += 1;
                    }
                }
            }
            _ => {}
        }
        parents.push(scope);
    }
    Ok(())
}

struct VariableLocation<'name, 'dwarf> {
    function: u64,
    name: &'name str,
    size: u64,
    type_name: Option<String>,
    location: Location<'dwarf>,
}

// Record a formal parameter's entry register when the location covering the
// function entry is exactly one bare `DW_OP_regN` with no trailing stack
// operations. Every other shape is `unsupported_locations`: memory operands,
// `DW_OP_entry_value` compositions, `DW_OP_stack_value` constants, pieces,
// empty expressions, or no covering range. `DW_OP_entry_value` is rejected
// even around a register because it describes a caller-side computation,
// not a proven live entry register.
#[allow(clippy::too_many_arguments)]
fn emit_entry_name(
    encoding: gimli::Encoding,
    entry_pc: u64,
    locations: &[Location<'_>],
    type_name: Option<String>,
    function: u64,
    name: &str,
    status: &mut DebugStatus,
    output: &mut DebugOutput,
) -> gimli::Result<()> {
    let covering: Vec<&Location<'_>> = locations
        .iter()
        .filter(|location| location.range.contains(&entry_pc))
        .collect();
    let [location] = covering.as_slice() else {
        status.unsupported_locations += 1;
        return Ok(());
    };
    match entry_register(location.expression, encoding)? {
        Some(register) => {
            output.names.push(DebugName {
                function,
                register: register.0,
                name: name.into(),
                type_name,
            });
            Ok(())
        }
        None => {
            status.unsupported_locations += 1;
            Ok(())
        }
    }
}

// The register of a single bare `DW_OP_regN` expression, or `None` for any
// other shape. `Err` only for truncated encodings; every meaningful
// non-register opcode is conservative `None`, matching stack-object policy.
fn entry_register(
    expression: gimli::Expression<R<'_>>,
    encoding: gimli::Encoding,
) -> gimli::Result<Option<gimli::Register>> {
    let mut operations = expression.operations(encoding);
    let Some(operation) = operations.next()? else {
        return Ok(None);
    };
    let register = match operation {
        gimli::Operation::Register { register } => register,
        _ => return Ok(None),
    };
    if operations.next()?.is_some() {
        return Ok(None);
    }
    Ok(Some(register))
}

// Drop ambiguous entry evidence: at most one name per function+register and
// one register per function+name survive. Collisions count each dropped
// entry as an unsupported location so debug-vs-stripped accounting stays
// exact. Deterministic: survivors keep first-sorted order.
fn disambiguate_names(names: Vec<DebugName>, status: &mut DebugStatus) -> Vec<DebugName> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut by_register: BTreeMap<(u64, u16), BTreeSet<String>> = BTreeMap::new();
    let mut by_name: BTreeMap<(u64, String), BTreeSet<u16>> = BTreeMap::new();
    for name in &names {
        by_register
            .entry((name.function, name.register))
            .or_default()
            .insert(name.name.clone());
        by_name
            .entry((name.function, name.name.clone()))
            .or_default()
            .insert(name.register);
    }
    let mut kept = Vec::new();
    let mut seen: BTreeSet<(u64, u16, String)> = BTreeSet::new();
    for name in names {
        let register_ambiguous = by_register
            .get(&(name.function, name.register))
            .is_some_and(|names| names.len() > 1);
        let name_ambiguous = by_name
            .get(&(name.function, name.name.clone()))
            .is_some_and(|registers| registers.len() > 1);
        if register_ambiguous || name_ambiguous {
            status.unsupported_locations += 1;
            continue;
        }
        // Identical duplicates collapse; differing type spellings for the
        // same binding are distinct evidence and both survive.
        if seen.insert((name.function, name.register, name.name.clone())) {
            kept.push(name);
        }
    }
    kept
}

fn emit_location(
    unit: &gimli::Unit<R<'_>>,
    scope: &Scope<'_>,
    rows: &[Cfa],
    entry_cfa: i64,
    variable: VariableLocation<'_, '_>,
    status: &mut DebugStatus,
    objects: &mut Vec<StackObject>,
) -> gimli::Result<()> {
    let VariableLocation {
        function,
        name,
        size,
        type_name,
        location,
    } = variable;
    // The expression can change interpretation at any frame-base or CFA row
    // boundary, including within an otherwise single location-list entry.
    let mut cuts = vec![location.range.start, location.range.end];
    for range in rows
        .iter()
        .map(|r| &r.range)
        .chain(scope.frame.iter().map(|f| &f.range))
    {
        for endpoint in [range.start, range.end] {
            if location.range.start < endpoint && endpoint < location.range.end {
                cuts.push(endpoint);
            }
        }
    }
    cuts.sort_unstable();
    cuts.dedup();
    let mut unsupported = false;
    for endpoints in cuts.windows(2) {
        let pc = endpoints[0];
        let cfa = covering_cfa(rows, pc);
        let mut base = None;
        let mut first_frame = true;
        for frame in scope.frame.iter().filter(|frame| frame.range.contains(&pc)) {
            let offset = expression_offset(
                frame.expression,
                unit.encoding(),
                cfa,
                entry_cfa,
                None,
                true,
            )?;
            if first_frame {
                base = offset;
                first_frame = false;
            } else if base != offset {
                base = None;
                break;
            }
        }
        let offset = expression_offset(
            location.expression,
            unit.encoding(),
            cfa,
            entry_cfa,
            base,
            false,
        )?;
        if let Some(offset) = offset {
            // A declared extent must fit the offset domain as well.
            if i128::from(offset) + i128::from(size) <= i128::from(i64::MAX) {
                objects.push(StackObject {
                    function,
                    range: pc..endpoints[1],
                    name: name.into(),
                    offset,
                    size,
                    type_name: type_name.clone(),
                });
            } else {
                unsupported = true;
            }
        } else {
            unsupported = true;
        }
    }
    if unsupported {
        status.unsupported_locations += 1;
    }
    Ok(())
}

fn covering_cfa(rows: &[Cfa], pc: u64) -> Option<&Cfa> {
    let mut found: Option<&Cfa> = None;
    for row in rows.iter().filter(|row| row.range.contains(&pc)) {
        if let Some(previous) = found {
            if previous.register != row.register || previous.offset != row.offset {
                return None;
            }
        } else {
            found = Some(row);
        }
    }
    found
}

fn expression_offset(
    expression: gimli::Expression<R<'_>>,
    encoding: gimli::Encoding,
    cfa: Option<&Cfa>,
    entry_cfa: i64,
    frame: Option<i64>,
    frame_expression: bool,
) -> gimli::Result<Option<i64>> {
    // A value is either an entry-SP-relative address or an integer constant.
    let mut stack: Vec<(bool, i64)> = Vec::new();
    let mut operations = expression.operations(encoding);
    while let Some(operation) = operations.next()? {
        use gimli::Operation as Op;
        let value = match operation {
            Op::CallFrameCFA => Some((true, entry_cfa)),
            Op::FrameOffset { offset } if !frame_expression => frame
                .and_then(|base| base.checked_add(offset))
                .map(|n| (true, n)),
            Op::Register { register } if frame_expression => cfa
                .filter(|cfa| cfa.register == register)
                .and_then(|cfa| entry_cfa.checked_sub(cfa.offset))
                .map(|n| (true, n)),
            Op::RegisterOffset {
                register,
                offset,
                base_type,
            } if base_type.0 == 0 => cfa
                .filter(|cfa| cfa.register == register)
                .and_then(|cfa| entry_cfa.checked_sub(cfa.offset)?.checked_add(offset))
                .map(|n| (true, n)),
            Op::SignedConstant { value } => Some((false, value)),
            Op::UnsignedConstant { value } => i64::try_from(value).ok().map(|n| (false, n)),
            Op::PlusConstant { value } => {
                let Some((address, n)) = stack.pop() else {
                    return Ok(None);
                };
                i64::try_from(value)
                    .ok()
                    .and_then(|v| n.checked_add(v))
                    .map(|n| (address, n))
            }
            Op::Plus | Op::Minus => {
                let Some((b_address, b)) = stack.pop() else {
                    return Ok(None);
                };
                let Some((a_address, a)) = stack.pop() else {
                    return Ok(None);
                };
                if matches!(operation, Op::Plus) {
                    if a_address && b_address {
                        return Ok(None);
                    }
                    a.checked_add(b).map(|n| (a_address || b_address, n))
                } else {
                    if b_address {
                        return Ok(None);
                    }
                    a.checked_sub(b).map(|n| (a_address, n))
                }
            }
            Op::Nop => continue,
            _ => return Ok(None),
        };
        let Some(value) = value else { return Ok(None) };
        stack.push(value);
    }
    Ok(match stack.as_slice() {
        [(true, offset)] => Some(*offset),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoding() -> gimli::Encoding {
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        }
    }

    fn expression(bytes: &[u8]) -> gimli::Expression<R<'_>> {
        gimli::Expression(EndianSlice::new(bytes, RunTimeEndian::Little))
    }

    #[test]
    fn register_conversion_requires_the_actual_covering_cfa_register() {
        // x86 RBP is entrySP-8 once CFA=RBP+16. AArch64 FP is
        // entrySP-32 once CFA=FP+32: never assume FP equals entrySP.
        for (register, cfa_offset, entry_cfa, expected) in
            [(6, 16, 8, -8), (29, 32, 0, -32), (31, 96, 0, -96)]
        {
            let cfa = Cfa {
                range: 10..20,
                register: gimli::Register(register),
                offset: cfa_offset,
            };
            let bytes = [gimli::DW_OP_reg0.0 + register as u8];
            assert_eq!(
                expression_offset(
                    expression(&bytes),
                    encoding(),
                    Some(&cfa),
                    entry_cfa,
                    None,
                    true
                )
                .unwrap(),
                Some(expected)
            );
            assert_eq!(
                expression_offset(expression(&bytes), encoding(), None, entry_cfa, None, true)
                    .unwrap(),
                None
            );
            let different = Cfa {
                register: gimli::Register(register + 1),
                ..cfa.clone()
            };
            assert_eq!(
                expression_offset(
                    expression(&bytes),
                    encoding(),
                    Some(&different),
                    entry_cfa,
                    None,
                    true
                )
                .unwrap(),
                None
            );
            // The same register expression on a variable means register
            // storage, not an address of a stack variable.
            assert_eq!(
                expression_offset(
                    expression(&bytes),
                    encoding(),
                    Some(&cfa),
                    entry_cfa,
                    None,
                    false
                )
                .unwrap(),
                None
            );
            assert!(covering_cfa(&[cfa], 20).is_none());
        }
    }

    #[test]
    fn cfa_framebase_and_whole_locations_only() {
        let frame = expression_offset(
            expression(&[gimli::DW_OP_call_frame_cfa.0]),
            encoding(),
            None,
            8,
            None,
            true,
        )
        .unwrap();
        // DW_OP_fbreg -32 (signed LEB128), relative to CFA=entrySP+8.
        assert_eq!(
            expression_offset(
                expression(&[gimli::DW_OP_fbreg.0, 0x60]),
                encoding(),
                None,
                8,
                frame,
                false
            )
            .unwrap(),
            Some(-24)
        );
        for bytes in [
            vec![gimli::DW_OP_fbreg.0, 0x60, gimli::DW_OP_piece.0, 4],
            vec![gimli::DW_OP_fbreg.0, 0x60, gimli::DW_OP_stack_value.0],
            vec![gimli::DW_OP_fbreg.0, 0x60, gimli::DW_OP_deref.0],
        ] {
            assert_eq!(
                expression_offset(expression(&bytes), encoding(), None, 8, frame, false).unwrap(),
                None
            );
        }
        assert!(
            expression_offset(
                expression(&[gimli::DW_OP_fbreg.0, 0x80]),
                encoding(),
                None,
                8,
                frame,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn scope_and_location_intersections_exclude_gaps() {
        assert_eq!(
            intersections(&[10..20, 30..40], std::slice::from_ref(&(15..35))),
            vec![15..20, 30..35]
        );
        let rows = [
            Cfa {
                range: 10..20,
                register: gimli::Register(7),
                offset: 8,
            },
            Cfa {
                range: 20..30,
                register: gimli::Register(7),
                offset: 40,
            },
        ];
        // DW_OP_breg7 0 follows the unwind row, not a fixed SP guess.
        let bytes = [gimli::DW_OP_breg0.0 + 7, 0];
        assert_eq!(
            expression_offset(
                expression(&bytes),
                encoding(),
                covering_cfa(&rows, 19),
                8,
                None,
                false
            )
            .unwrap(),
            Some(0)
        );
        assert_eq!(
            expression_offset(
                expression(&bytes),
                encoding(),
                covering_cfa(&rows, 20),
                8,
                None,
                false
            )
            .unwrap(),
            Some(-32)
        );
        assert_eq!(
            expression_offset(
                expression(&bytes),
                encoding(),
                covering_cfa(&rows, 30),
                8,
                None,
                false
            )
            .unwrap(),
            None
        );
        let conflicting = [
            Cfa {
                range: 10..20,
                register: gimli::Register(7),
                offset: 8,
            },
            Cfa {
                range: 10..20,
                register: gimli::Register(7),
                offset: 16,
            },
        ];
        assert!(covering_cfa(&conflicting, 15).is_none());
    }

    #[test]
    fn only_bare_entry_registers_name_parameters() {
        // A single DW_OP_regN qualifies; everything else is explicit unknown.
        for register in [5u16, 31] {
            let op = gimli::DW_OP_reg0.0 + register as u8;
            assert_eq!(
                entry_register(expression(&[op]), encoding()).unwrap(),
                Some(gimli::Register(register))
            );
            // Trailing operations (even a no-op plus) disqualify the fact.
            assert_eq!(
                entry_register(expression(&[op, gimli::DW_OP_nop.0]), encoding()).unwrap(),
                None
            );
            // Memory operands never name entry registers.
            assert_eq!(
                entry_register(
                    expression(&[gimli::DW_OP_breg0.0 + register as u8, 0]),
                    encoding()
                )
                .unwrap(),
                None
            );
        }
        // Empty expressions, constants, CFA computations, stack values, and
        // entry-value wrappers are not entry registers.
        assert_eq!(entry_register(expression(&[]), encoding()).unwrap(), None);
        assert_eq!(
            entry_register(expression(&[gimli::DW_OP_lit0.0]), encoding()).unwrap(),
            None
        );
        assert_eq!(
            entry_register(expression(&[gimli::DW_OP_call_frame_cfa.0]), encoding()).unwrap(),
            None
        );
        assert_eq!(
            entry_register(
                expression(&[gimli::DW_OP_reg5.0, gimli::DW_OP_stack_value.0]),
                encoding()
            )
            .unwrap(),
            None
        );
        assert_eq!(
            entry_register(
                expression(&[gimli::DW_OP_entry_value.0, 1, gimli::DW_OP_reg5.0]),
                encoding()
            )
            .unwrap(),
            None
        );
        assert!(entry_register(expression(&[gimli::DW_OP_fbreg.0]), encoding()).is_err());
    }

    #[test]
    fn ambiguous_entry_evidence_is_dropped() {
        let mut status = DebugStatus::default();
        let names = vec![
            DebugName {
                function: 0x100,
                register: 5,
                name: "x".into(),
                type_name: Some("long".into()),
            },
            DebugName {
                function: 0x100,
                register: 5,
                name: "y".into(),
                type_name: None,
            },
            DebugName {
                function: 0x200,
                register: 5,
                name: "x".into(),
                type_name: None,
            },
            DebugName {
                function: 0x200,
                register: 6,
                name: "x".into(),
                type_name: None,
            },
        ];
        // Both collisions drop every involved entry; nothing is forced.
        let kept = disambiguate_names(names, &mut status);
        assert!(kept.is_empty());
        assert_eq!(status.unsupported_locations, 4);
        let mut status = DebugStatus::default();
        let unique = vec![
            DebugName {
                function: 0x100,
                register: 5,
                name: "x".into(),
                type_name: None,
            },
            DebugName {
                function: 0x100,
                register: 6,
                name: "y".into(),
                type_name: None,
            },
        ];
        assert_eq!(disambiguate_names(unique, &mut status).len(), 2);
        assert_eq!(status.unsupported_locations, 0);
    }
}
