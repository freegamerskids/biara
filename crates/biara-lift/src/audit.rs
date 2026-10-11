//! Checks on calls to well-known imports: nonconstant format strings and
//! writes exceeding declared heap, global, or exact debug stack objects.
//! Frame-boundary checks remain independent: a frame is not an exact buffer,
//! and missing declarations/debug information leave object extent unknown.
//!
//! A value a function was passed (an entry register, or a word it points
//! to) is followed up through the calls that pass it, at most `MAX_DEPTH`
//! calls up: a format string every caller passes as a constant is no
//! finding, and a buffer in a caller's frame is checked against that
//! frame. A function's callers count as all known only if the image's code
//! enters it by direct calls alone: not as the entry point, through a code
//! pointer in data, or through code that takes its address. Calls from
//! other modules to exports are theirs to check; an export nothing in the
//! image calls keeps its findings. Values that come from input are named:
//! `main`'s `argv` and `envp` (`main` as `__libc_start_main` is given it),
//! `getenv` results, and buffers that input calls (`read`, `recv`,
//! `fgets`, ...) fill.

use std::{
    collections::{BTreeSet, HashMap},
    fmt,
};

use crate::{
    Error,
    calls::{Arg, CallSite, CallSites, Callee},
};

#[path = "object.rs"]
pub mod object;

use crate::calls::{SizeRange, size_range};
use object::{ObjectBound, ObjectPointer, ObjectQuery, pointer_facts};

/// What a call to an import does with its arguments (indices into the
/// argument registers).
#[derive(Clone, Copy)]
enum Rule {
    /// Takes a format string.
    Format(usize),
    /// Writes at most `len` bytes to `dst`.
    Bounded { dst: usize, len: usize },
    /// Writes to `dst` with no bound.
    Unbounded(usize),
}

use Rule::{Bounded, Format, Unbounded};

const RULES: &[(&str, &[Rule])] = &[
    ("printf", &[Format(0)]),
    ("vprintf", &[Format(0)]),
    ("fprintf", &[Format(1)]),
    ("vfprintf", &[Format(1)]),
    ("dprintf", &[Format(1)]),
    ("vdprintf", &[Format(1)]),
    ("sprintf", &[Format(1), Unbounded(0)]),
    ("vsprintf", &[Format(1), Unbounded(0)]),
    ("snprintf", &[Format(2), Bounded { dst: 0, len: 1 }]),
    ("vsnprintf", &[Format(2), Bounded { dst: 0, len: 1 }]),
    ("asprintf", &[Format(1)]),
    ("vasprintf", &[Format(1)]),
    ("syslog", &[Format(1)]),
    ("vsyslog", &[Format(1)]),
    ("err", &[Format(1)]),
    ("errx", &[Format(1)]),
    ("verr", &[Format(1)]),
    ("verrx", &[Format(1)]),
    ("warn", &[Format(0)]),
    ("warnx", &[Format(0)]),
    ("vwarn", &[Format(0)]),
    ("vwarnx", &[Format(0)]),
    ("error", &[Format(2)]),
    // UCRT (Windows): the `..._l` locale twin takes the format at the same
    // index; `..._s` behaves the same for its format argument.
    ("__printf_chk", &[Format(1)]),
    ("__vprintf_chk", &[Format(1)]),
    ("__fprintf_chk", &[Format(2)]),
    ("__vfprintf_chk", &[Format(2)]),
    ("__dprintf_chk", &[Format(2)]),
    ("__vdprintf_chk", &[Format(2)]),
    ("__sprintf_chk", &[Format(3)]),
    ("__vsprintf_chk", &[Format(3)]),
    ("__snprintf_chk", &[Format(4), Bounded { dst: 0, len: 1 }]),
    ("__vsnprintf_chk", &[Format(4), Bounded { dst: 0, len: 1 }]),
    ("__asprintf_chk", &[Format(2)]),
    ("__vasprintf_chk", &[Format(2)]),
    ("__syslog_chk", &[Format(2)]),
    ("__vsyslog_chk", &[Format(2)]),
    ("wprintf", &[Format(0)]),
    ("vwprintf", &[Format(0)]),
    ("fwprintf", &[Format(1)]),
    ("vfwprintf", &[Format(1)]),
    ("swprintf", &[Format(2)]),
    ("vswprintf", &[Format(2)]),
    ("_snwprintf", &[Format(2)]),
    ("_vsnwprintf", &[Format(2)]),
    ("_printf_l", &[Format(0)]),
    ("_wprintf_l", &[Format(0)]),
    ("_fprintf_l", &[Format(1)]),
    ("_fwprintf_l", &[Format(1)]),
    ("_sprintf_l", &[Format(1), Unbounded(0)]),
    ("_swprintf_l", &[Format(2)]),
    ("_snprintf", &[Format(2), Bounded { dst: 0, len: 1 }]),
    ("_snprintf_l", &[Format(2), Bounded { dst: 0, len: 1 }]),
    ("_snwprintf_l", &[Format(2)]),
    ("_vsnprintf", &[Format(2), Bounded { dst: 0, len: 1 }]),
    ("_vsnprintf_l", &[Format(2), Bounded { dst: 0, len: 1 }]),
    ("_vsnwprintf_l", &[Format(2)]),
    ("_scprintf", &[Format(0)]),
    ("_scwprintf", &[Format(0)]),
    ("__stdio_common_vfprintf", &[Format(5)]),
    ("__stdio_common_vfwprintf", &[Format(5)]),
    ("__stdio_common_vsprintf", &[Format(6), Unbounded(0)]),
    ("__stdio_common_vswprintf", &[Format(6)]),
    (
        "__stdio_common_vsnprintf_s",
        &[Format(7), Bounded { dst: 0, len: 1 }],
    ),
    ("__stdio_common_vsnwprintf_s", &[Format(7)]),
    ("memcpy", &[Bounded { dst: 0, len: 2 }]),
    ("memmove", &[Bounded { dst: 0, len: 2 }]),
    ("memset", &[Bounded { dst: 0, len: 2 }]),
    ("__memcpy_chk", &[Bounded { dst: 0, len: 2 }]),
    ("__memmove_chk", &[Bounded { dst: 0, len: 2 }]),
    ("__memset_chk", &[Bounded { dst: 0, len: 2 }]),
    ("strncpy", &[Bounded { dst: 0, len: 2 }]),
    ("stpncpy", &[Bounded { dst: 0, len: 2 }]),
    ("__strncpy_chk", &[Bounded { dst: 0, len: 2 }]),
    ("_strncpy_l", &[Bounded { dst: 0, len: 2 }]),
    ("_wcsncpy_l", &[Bounded { dst: 0, len: 2 }]),
    ("_mbsncpy_l", &[Bounded { dst: 0, len: 2 }]),
    ("strcpy_s", &[Bounded { dst: 0, len: 1 }]),
    ("strcat_s", &[Bounded { dst: 0, len: 1 }]),
    ("wcscpy_s", &[Bounded { dst: 0, len: 1 }]),
    ("wcscat_s", &[Bounded { dst: 0, len: 1 }]),
    ("read", &[Bounded { dst: 1, len: 2 }]),
    ("pread", &[Bounded { dst: 1, len: 2 }]),
    ("pread64", &[Bounded { dst: 1, len: 2 }]),
    ("__read_chk", &[Bounded { dst: 1, len: 2 }]),
    ("recv", &[Bounded { dst: 1, len: 2 }]),
    ("recvfrom", &[Bounded { dst: 1, len: 2 }]),
    ("__recv_chk", &[Bounded { dst: 1, len: 2 }]),
    ("fgets", &[Bounded { dst: 0, len: 1 }]),
    ("__fgets_chk", &[Bounded { dst: 0, len: 2 }]),
    ("gets", &[Unbounded(0)]),
    ("strcpy", &[Unbounded(0)]),
    ("stpcpy", &[Unbounded(0)]),
    ("strcat", &[Unbounded(0)]),
];

/// Message catalog lookups: they return their message id or its
/// translation, as constant as the id (`printf(gettext("..."))`). The
/// indices of the message ids.
const TRANSLATIONS: &[(&str, &[usize])] = &[
    ("gettext", &[0]),
    ("dgettext", &[1]),
    ("dcgettext", &[1]),
    ("__dcgettext", &[1]),
    ("ngettext", &[0, 1]),
    ("dngettext", &[1, 2]),
    ("dcngettext", &[1, 2]),
];

/// Versioned names (`memcpy@GLIBC_2.14`) follow the base function.
/// glibc redirects (`__isoc23_strtol`) follow the function they wrap.
fn base(import: &str) -> &str {
    let import = import.split('@').next().unwrap_or(import);
    import.strip_prefix("__isoc23_").unwrap_or(import)
}

/// Argument positions read as NUL-terminated strings (format strings,
/// paths, names, etc.), by import. Written buffers are not strings.
const STRINGS: &[(&str, &[usize])] = &[
    ("printf", &[0]),
    ("vprintf", &[0]),
    ("fprintf", &[1]),
    ("vfprintf", &[1]),
    ("dprintf", &[1]),
    ("vdprintf", &[1]),
    ("sprintf", &[1]),
    ("vsprintf", &[1]),
    ("snprintf", &[2]),
    ("vsnprintf", &[2]),
    ("asprintf", &[1]),
    ("vasprintf", &[1]),
    ("syslog", &[1]),
    ("vsyslog", &[1]),
    ("err", &[1]),
    ("errx", &[1]),
    ("warn", &[0]),
    ("warnx", &[0]),
    ("error", &[2]),
    ("__printf_chk", &[1]),
    ("__fprintf_chk", &[2]),
    ("__sprintf_chk", &[3]),
    ("puts", &[0]),
    ("puts_unlocked", &[0]),
    ("fputs", &[0]),
    ("fputs_unlocked", &[0]),
    ("perror", &[0]),
    ("strcmp", &[0, 1]),
    ("strncmp", &[0, 1]),
    ("strcasecmp", &[0, 1]),
    ("strncasecmp", &[0, 1]),
    ("strchr", &[0]),
    ("strrchr", &[0]),
    ("strstr", &[0, 1]),
    ("strspn", &[0, 1]),
    ("strcspn", &[0, 1]),
    ("strpbrk", &[0, 1]),
    ("strtok", &[0, 1]),
    ("strlen", &[0]),
    ("strnlen", &[0]),
    ("strdup", &[0]),
    ("strndup", &[0]),
    ("strcpy", &[1]),
    ("strcat", &[1]),
    ("strtol", &[0]),
    ("strtoul", &[0]),
    ("strtoll", &[0]),
    ("strtoull", &[0]),
    ("strtod", &[0]),
    ("atoi", &[0]),
    ("atol", &[0]),
    ("atoll", &[0]),
    ("getenv", &[0]),
    ("secure_getenv", &[0]),
    ("system", &[0]),
    ("popen", &[0]),
    ("execl", &[0]),
    ("execlp", &[0]),
    ("execle", &[0]),
    ("execv", &[0]),
    ("execvp", &[0]),
    ("fopen", &[0, 1]),
    ("fopen64", &[0, 1]),
    ("freopen", &[0, 1]),
    ("open", &[0]),
    ("open64", &[0]),
    ("openat", &[1]),
    ("openat64", &[1]),
    ("creat", &[0]),
    ("creat64", &[0]),
    ("unlink", &[0]),
    ("unlinkat", &[1]),
    ("mkdir", &[0]),
    ("mkdirat", &[1]),
    ("rmdir", &[0]),
    ("mkdtemp", &[0]),
    ("mkstemp", &[0]),
    ("chmod", &[0]),
    ("fchmodat", &[1]),
    ("chown", &[0]),
    ("lchown", &[0]),
    ("chdir", &[0]),
    ("chroot", &[0]),
    ("symlink", &[0, 1]),
    ("symlinkat", &[0, 2]),
    ("link", &[0, 1]),
    ("linkat", &[0, 2, 4]),
    ("rename", &[0, 1]),
    ("renameat", &[1, 3]),
    ("readlink", &[0]),
    ("readlinkat", &[1]),
    ("realpath", &[0]),
    ("access", &[0]),
    ("faccessat", &[1]),
    ("stat", &[0]),
    ("lstat", &[0]),
    ("stat64", &[0]),
    ("lstat64", &[0]),
    ("__xstat", &[1]),
    ("__lxstat", &[1]),
    ("__xstat64", &[1]),
    ("__lxstat64", &[1]),
    ("utime", &[0]),
    ("utimes", &[0]),
    ("dlopen", &[0]),
    ("dlsym", &[1]),
    ("setenv", &[0, 1]),
    ("unsetenv", &[0]),
    ("gethostbyname", &[0]),
    ("getaddrinfo", &[0, 1]),
    ("scanf", &[0]),
    ("sscanf", &[1]),
    ("fscanf", &[1]),
    ("__isoc99_scanf", &[0]),
    ("__isoc99_sscanf", &[1]),
    ("__isoc99_fscanf", &[1]),
    ("gettext", &[0]),
    ("dgettext", &[1]),
    ("dcgettext", &[1]),
    ("ngettext", &[0, 1]),
    ("dngettext", &[1, 2]),
    ("dcngettext", &[1, 2]),
];

/// Argument positions `import` reads as NUL-terminated strings; empty if
/// it takes none.
pub fn string_args(import: &str) -> &'static [usize] {
    STRINGS
        .iter()
        .find(|(n, _)| *n == base(import))
        .map_or(&[], |(_, a)| a)
}

fn rules(import: &str) -> &'static [Rule] {
    RULES
        .iter()
        .find(|(n, _)| *n == base(import))
        .map_or(&[], |(_, r)| r)
}
/// Writes longer than this are not a bound: they only come from ranges
/// such as `n != 0`.
const MAX_LEN: u64 = 1 << 32;

/// Arguments the checks know `import` to take; `None` if it has no rules.
pub fn known_arity(import: &str) -> Option<usize> {
    rules(import)
        .iter()
        .map(|r| match *r {
            Format(i) | Unbounded(i) => i + 1,
            Bounded { dst, len } => dst.max(len) + 1,
        })
        .max()
}

/// Imports that fill a buffer with input: the index of the buffer.
const INPUTS: &[(&str, usize)] = &[
    ("read", 1),
    ("pread", 1),
    ("pread64", 1),
    ("__read_chk", 1),
    ("recv", 1),
    ("recvfrom", 1),
    ("__recv_chk", 1),
    ("__recvfrom_chk", 1),
    ("fgets", 0),
    ("fgets_unlocked", 0),
    ("__fgets_chk", 0),
    ("__fgets_unlocked_chk", 0),
    ("gets", 0),
    ("fread", 0),
    ("fread_unlocked", 0),
    ("__fread_chk", 0),
    ("__fread_unlocked_chk", 0),
];

/// Imports that return an environment variable.
const ENVIRONMENT: &[&str] = &["getenv", "secure_getenv"];

/// Calls its first argument (`main`) with `argv` and `envp` in the second
/// and third argument registers.
const START_MAIN: &str = "__libc_start_main";

/// How many calls up a value is followed.
const MAX_DEPTH: usize = 4;

/// Caller paths followed per call site at most.
const MAX_PATHS: usize = 1024;

/// Where an argument comes from, when it is input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// An element of `main`'s `argv`.
    CommandLine,
    /// An element of `main`'s `envp`, or what `getenv` returned.
    Environment,
    /// A buffer the call to `import` at `pc` fills.
    Read { import: String, pc: u64 },
}

impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandLine => f.write_str("the command line"),
            Self::Environment => f.write_str("the environment"),
            Self::Read { import, pc } => write!(f, "input ({import}()@{pc:#x})"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issue {
    /// The format argument is not a constant string in read-only memory
    /// but `value`, in function `at` (as far as it was followed); `input`
    /// if that is known to come from input.
    Format {
        arg: usize,
        value: Arg,
        at: u64,
        input: Option<Input>,
    },
    /// Up to `len` bytes written at function `frame`'s entry stack pointer
    /// minus `below`, which `len` exceeds.
    Overflow { frame: u64, below: u64, len: u64 },
    /// A write without a bound at function `frame`'s entry stack pointer
    /// minus `below`.
    Unbounded { frame: u64, below: u64 },
    /// A write may exceed a declared object, even without crossing its frame.
    ObjectOverflow {
        object: ObjectPointer,
        len: SizeRange,
    },
    /// An unbounded write into an object with an established extent.
    ObjectUnbounded { object: ObjectPointer },
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub site: CallSite,
    pub issue: Issue,
    /// The calls the values were followed up through, from the outermost
    /// caller down to the call of `site`'s caller; empty if `site`'s own
    /// values decide.
    pub path: Vec<CallSite>,
}

impl Finding {
    /// One line: the callee, the issue and the path; `label(f)` names
    /// function `f`.
    pub fn describe(&self, label: &dyn Fn(u64) -> String) -> String {
        let caller = self.site.caller;
        let place = |f: u64| match f == caller {
            true => String::new(),
            false => format!(" in {}", label(f)),
        };
        let mut s = format!("{}: ", self.site.callee);
        s += &match &self.issue {
            Issue::Format {
                arg,
                value,
                at,
                input: Some(input),
            } => format!(
                "format string (argument {arg}) comes from {input}: {value}{}",
                place(*at)
            ),
            Issue::Format { arg, value, at, .. } => format!(
                "format string (argument {arg}) is not constant: {value}{}",
                place(*at)
            ),
            Issue::Overflow { frame, below, len } => format!(
                "writes up to {len:#x} bytes to sp-{below:#x}{}, past {} frame",
                place(*frame),
                if *frame == caller {
                    "the caller's"
                } else {
                    "its"
                }
            ),
            Issue::Unbounded { frame, below } => {
                format!("unbounded write to sp-{below:#x}{}", place(*frame))
            }
            Issue::ObjectOverflow { object, len } => format!(
                "writes [{:#x}, {:#x}] bytes to {:?} at offset {:+#x}, object size {:?}; evidence {:?}",
                len.lo, len.hi, object.origin, object.offset, object.size, object.evidence
            ),
            Issue::ObjectUnbounded { object } => format!(
                "unbounded write to {:?} at offset {:+#x}, object size {:?}; evidence {:?}",
                object.origin, object.offset, object.size, object.evidence
            ),
        };
        if !self.path.is_empty() {
            let calls: Vec<String> = self
                .path
                .iter()
                .map(|c| format!("{:#x} in {}", c.pc, label(c.caller)))
                .collect();
            s += &format!("; via {}", calls.join(", "));
        }
        s
    }
}

/// Findings at the calls to imports in `cfg`'s functions (`sites`, which
/// this extends to the callers it follows values up through).
/// `indirect`: functions the image enters other than by direct calls,
/// code that takes their address aside
/// (`biara_loader::Image::indirect_entries`). `main`: the function the
/// loader calls with `argc`, `argv` and `envp`, if it does so directly
/// (`Image::main`). `read_const(addr, buf)` reads memory the program
/// cannot write (`Image::read_const`).
/// `objects` supplies only declared data-symbol or exact debug-object bounds;
/// returning `None` preserves unknown extent (frame checks still apply).
pub fn audit(
    sites: &mut CallSites,
    indirect: &BTreeSet<u64>,
    main: Option<u64>,
    read_const: &dyn Fn(u64, &mut [u8]) -> bool,
    objects: &dyn Fn(ObjectQuery) -> Option<ObjectBound>,
) -> Result<Vec<Finding>, Error> {
    let cfg = sites.cfg();
    let mut callers: HashMap<u64, BTreeSet<u64>> = HashMap::new();
    for f in cfg.functions.values() {
        for &c in f.calls.iter().chain(&f.tail_calls) {
            callers.entry(c).or_default().insert(f.entry);
        }
    }
    // Entered otherwise too: its callers are not all known.
    let open: BTreeSet<u64> = cfg
        .blocks
        .values()
        .flat_map(|b| b.constants.iter().copied())
        .chain(indirect.iter().copied())
        .filter(|e| cfg.functions.contains_key(e))
        .collect();
    let regs = sites.arg_registers();
    let mut tried = sites.import_callers();
    sites.add(&tried)?;
    loop {
        // Return summaries are loaded before resolution, including summaries
        // referenced by summaries. Never replace an unloaded wrapper by a
        // guessed allocation or buffer size.
        let summaries: BTreeSet<u64> = sites
            .sites()
            .iter()
            .flat_map(|site| site.args.iter())
            .flat_map(|arg| sites.missing_summaries(arg))
            .filter(|f| !tried.contains(f))
            .collect();
        if !summaries.is_empty() {
            sites.add(&summaries)?;
            tried.extend(summaries);
            continue;
        }
        let mut check = Check::new(
            sites,
            &callers,
            &open,
            &tried,
            &regs,
            main,
            ImageFacts {
                read_const,
                objects,
            },
        );
        let findings = check.run();
        let more: BTreeSet<u64> = check
            .wanted
            .iter()
            .filter_map(|f| callers.get(f))
            .flatten()
            .copied()
            .filter(|c| !tried.contains(c))
            .collect();
        if more.is_empty() {
            return Ok(findings);
        }
        sites.add(&more)?;
        tried.extend(more);
    }
}

/// A value at a call site, not a `OneOf`, relative to function `at` (its
/// stack offsets and entry registers are `at`'s).
#[derive(Clone, Debug, PartialEq)]
struct Val {
    arg: Arg,
    at: u64,
    pc: u64,
}

impl Val {
    /// Depends on what the function was called with.
    fn incoming(&self) -> bool {
        fn incoming(arg: &Arg) -> bool {
            match arg {
                Arg::Incoming(_) | Arg::Deref { .. } => true,
                Arg::Offset { base, .. } | Arg::Load { base, .. } => incoming(base),
                Arg::OneOf(values) | Arg::Expr { args: values, .. } => values.iter().any(incoming),
                _ => false,
            }
        }
        incoming(&self.arg)
    }

    fn stack(&self) -> Option<u64> {
        match &self.arg {
            Arg::Stack(o) if *o < 0 => Some(o.unsigned_abs()),
            Arg::Frame { off, .. } if *off < 0 => Some(off.unsigned_abs()),
            _ => None,
        }
    }

    fn frame(&self) -> u64 {
        match &self.arg {
            Arg::Frame { function, .. } => *function,
            _ => self.at,
        }
    }
}

/// The alternatives of `arg` (at a call site in `at`).
fn flatten(arg: &Arg, at: u64, pc: u64) -> Vec<Val> {
    match arg {
        Arg::OneOf(vs) => vs.iter().flat_map(|v| flatten(v, at, pc)).collect(),
        _ => vec![Val {
            arg: arg.clone(),
            at,
            pc,
        }],
    }
}

/// Some arguments of a call site (each as its alternatives), followed up
/// to function `top` through `path` (innermost call first).
struct State<'s> {
    vals: Vec<Vec<Val>>,
    top: u64,
    path: Vec<&'s CallSite>,
}

enum Verdict {
    Constant,
    Input(Input),
    Other,
}

impl Verdict {
    /// The less constant of the two (input before anything else).
    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Input(i), _) | (_, Self::Input(i)) => Self::Input(i),
            (Self::Other, _) | (_, Self::Other) => Self::Other,
            _ => Self::Constant,
        }
    }
}

struct ImageFacts<'a> {
    read_const: &'a dyn Fn(u64, &mut [u8]) -> bool,
    objects: &'a dyn Fn(ObjectQuery) -> Option<ObjectBound>,
}

/// One pass over the recorded call sites.
struct Check<'s, 'cfg> {
    calls: &'s CallSites<'cfg>,
    sites: &'s [CallSite],
    by_pc: HashMap<u64, &'s CallSite>,
    calls_to: HashMap<u64, Vec<&'s CallSite>>,
    callers: &'s HashMap<u64, BTreeSet<u64>>,
    open: &'s BTreeSet<u64>,
    lifted: &'s BTreeSet<u64>,
    regs: &'s [String],
    read_const: &'s dyn Fn(u64, &mut [u8]) -> bool,
    objects: &'s dyn Fn(ObjectQuery) -> Option<ObjectBound>,
    /// Functions `__libc_start_main` calls.
    mains: BTreeSet<u64>,
    /// Buffers input calls fill (as followed up from those calls).
    buffers: Vec<(Val, Input, Option<u64>)>,
    /// Functions whose callers' call sites a value needs.
    wanted: BTreeSet<u64>,
}

impl<'s, 'cfg> Check<'s, 'cfg> {
    fn new(
        calls: &'s CallSites<'cfg>,
        callers: &'s HashMap<u64, BTreeSet<u64>>,
        open: &'s BTreeSet<u64>,
        lifted: &'s BTreeSet<u64>,
        regs: &'s [String],
        loader_main: Option<u64>,
        facts: ImageFacts<'s>,
    ) -> Self {
        let sites = calls.sites();
        let mut calls_to: HashMap<u64, Vec<&CallSite>> = HashMap::new();
        for c in sites {
            if let Callee::Function(f) = c.callee {
                calls_to.entry(f).or_default().push(c);
            }
        }
        let mut mains: BTreeSet<u64> = sites
            .iter()
            .filter(|c| c.import().is_some_and(|i| base(i) == START_MAIN))
            .filter_map(|c| match c.args.first() {
                Some(&Arg::Const(main)) => Some(main),
                _ => None,
            })
            .collect();
        mains.extend(loader_main);
        Self {
            calls,
            sites,
            by_pc: sites.iter().map(|c| (c.pc, c)).collect(),
            calls_to,
            callers,
            open,
            lifted,
            regs,
            read_const: facts.read_const,
            objects: facts.objects,
            mains,
            buffers: Vec::new(),
            wanted: BTreeSet::new(),
        }
    }

    fn run(&mut self) -> Vec<Finding> {
        let sites = self.sites;
        for site in sites {
            let Some((import, &(_, buf))) = site
                .import()
                .and_then(|i| Some(i).zip(INPUTS.iter().find(|(n, _)| *n == base(i))))
            else {
                continue;
            };
            let input = Input::Read {
                import: base(import).to_owned(),
                pc: site.pc,
            };
            let len = rules(import).iter().find_map(|r| match r {
                Bounded { dst, len } if *dst == buf => Some(*len),
                _ => None,
            });
            let args: Vec<usize> = std::iter::once(buf).chain(len).collect();
            let states = self.follow(site, &args, &|s| {
                s.vals[0].iter().any(|v| {
                    v.incoming()
                        || matches!(v.arg, Arg::Stack(_) | Arg::Frame { .. } | Arg::Const(_))
                })
            });
            for s in states {
                let extent = s
                    .vals
                    .get(1)
                    .and_then(|values| {
                        values
                            .iter()
                            .map(|v| size_range(&v.arg).map(|range| range.hi))
                            .collect::<Option<Vec<_>>>()
                    })
                    .and_then(|values| values.into_iter().max())
                    .filter(|n| *n < MAX_LEN);
                for v in &s.vals[0] {
                    self.buffers.push((v.clone(), input.clone(), extent));
                }
            }
        }

        let mut out: Vec<Finding> = Vec::new();
        let mut report = |site: &CallSite, issue: Issue, path: &[&CallSite]| {
            if !out.iter().any(|f| f.site.pc == site.pc && f.issue == issue) {
                out.push(Finding {
                    site: site.clone(),
                    issue,
                    path: path.iter().rev().map(|&c| c.clone()).collect(),
                });
            }
        };
        for site in sites {
            let Some(import) = site.import() else {
                continue;
            };
            for rule in rules(import) {
                match *rule {
                    Format(i) => {
                        let states = self.follow(site, &[i], &|_| true);
                        // The least constant alternative, input first.
                        let mut worst: Option<(&Val, Option<Input>, &State)> = None;
                        for s in &states {
                            for v in &s.vals[0] {
                                match self.verdict(v, 0) {
                                    Verdict::Constant => {}
                                    Verdict::Input(input) => {
                                        if worst.as_ref().is_none_or(|w| w.1.is_none()) {
                                            worst = Some((v, Some(input), s));
                                        }
                                    }
                                    Verdict::Other => {
                                        if worst.is_none() {
                                            worst = Some((v, None, s));
                                        }
                                    }
                                }
                            }
                        }
                        if let Some((v, input, s)) = worst {
                            let issue = Issue::Format {
                                arg: i,
                                value: v.arg.clone(),
                                at: v.at,
                                input,
                            };
                            report(site, issue, &s.path);
                        }
                    }
                    Bounded { dst, len } => {
                        let states = self.follow(site, &[dst, len], &|s| {
                            !s.vals[0].is_empty()
                                && !s.vals[1].is_empty()
                                && s.vals[1]
                                    .iter()
                                    .all(|v| v.incoming() || size_range(&v.arg).is_some())
                        });
                        for s in &states {
                            let Some(len) = s.vals[1]
                                .iter()
                                .map(|v| size_range(&v.arg))
                                .collect::<Option<Vec<SizeRange>>>()
                                .map(|ns| SizeRange {
                                    lo: ns.iter().map(|n| n.lo).min().unwrap_or(0),
                                    hi: ns.iter().map(|n| n.hi).max().unwrap_or(0),
                                })
                            else {
                                continue;
                            };
                            for d in &s.vals[0] {
                                if let Some(below) = d.stack()
                                    && len.hi < MAX_LEN
                                    && len.hi > below
                                {
                                    let issue = Issue::Overflow {
                                        frame: d.frame(),
                                        below,
                                        len: len.hi,
                                    };
                                    report(site, issue, &s.path);
                                }
                                let object = pointer_facts(&d.arg, d.at, d.pc, self.objects);
                                if object.overflows(len) {
                                    report(site, Issue::ObjectOverflow { object, len }, &s.path);
                                }
                            }
                        }
                    }
                    Unbounded(dst) => {
                        let states = self.follow(site, &[dst], &|s| !s.vals[0].is_empty());
                        for s in &states {
                            for d in &s.vals[0] {
                                if let Some(below) = d.stack() {
                                    let issue = Issue::Unbounded {
                                        frame: d.frame(),
                                        below,
                                    };
                                    report(site, issue, &s.path);
                                }
                                let object = pointer_facts(&d.arg, d.at, d.pc, self.objects);
                                if object.size.is_some() {
                                    report(site, Issue::ObjectUnbounded { object }, &s.path);
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Arguments `args` of `site`, followed up through the calls to its
    /// caller, theirs and so on while they depend on what the function was
    /// called with. States `keep` rejects cannot matter and are dropped. A
    /// state stays (as well as being followed up through the callers that
    /// are known) unless its function's callers are all known and
    /// followed.
    fn follow(
        &mut self,
        site: &'s CallSite,
        args: &[usize],
        keep: &dyn Fn(&State) -> bool,
    ) -> Vec<State<'s>> {
        let vals = args
            .iter()
            .map(|&i| {
                let arg = self
                    .calls
                    .resolve_arg(site.args.get(i).unwrap_or(&Arg::Unknown), site.caller);
                flatten(&arg, site.caller, site.pc)
            })
            .collect();
        let mut work = vec![State {
            vals,
            top: site.caller,
            path: Vec::new(),
        }];
        let mut out = Vec::new();
        let mut paths = 0;
        while let Some(s) = work.pop() {
            if !keep(&s) {
                continue;
            }
            if !s
                .vals
                .iter()
                .flatten()
                .any(|v| v.at == s.top && v.incoming())
            {
                out.push(s);
                continue;
            }
            let callers = self.callers.get(&s.top);
            let mut complete = !self.open.contains(&s.top)
                && callers.is_some_and(|c| !c.is_empty())
                && s.path.len() < MAX_DEPTH;
            if s.path.len() < MAX_DEPTH {
                if callers.is_some_and(|cs| cs.iter().any(|c| !self.lifted.contains(c))) {
                    self.wanted.insert(s.top);
                    complete = false;
                }
                for &c in self.calls_to.get(&s.top).map_or(&[][..], Vec::as_slice) {
                    // Recursion: the values from around the cycle stay.
                    if c.caller == s.top || s.path.iter().any(|p| p.caller == c.caller) {
                        complete = false;
                        continue;
                    }
                    if paths == MAX_PATHS {
                        complete = false;
                        break;
                    }
                    paths += 1;
                    let vals = s
                        .vals
                        .iter()
                        .map(|alts| {
                            alts.iter()
                                .flat_map(|v| self.substitute(v, s.top, c))
                                .collect()
                        })
                        .collect();
                    let mut path = s.path.clone();
                    path.push(c);
                    work.push(State {
                        vals,
                        top: c.caller,
                        path,
                    });
                }
            }
            if !complete {
                out.push(s);
            }
        }
        out
    }

    /// `v`, if it is what function `top` was called with, as call `c`
    /// (to `top`) passes it.
    fn substitute(&self, v: &Val, top: u64, c: &CallSite) -> Vec<Val> {
        let unknown = || {
            vec![Val {
                arg: Arg::Unknown,
                at: c.caller,
                pc: c.pc,
            }]
        };
        if v.at != top {
            return vec![v.clone()];
        }
        let passed = |reg: &str| {
            self.regs
                .iter()
                .position(|r| r == reg)
                .and_then(|i| c.args.get(i))
                .map(|a| flatten(&self.calls.resolve_arg(a, c.caller), c.caller, c.pc))
        };
        match &v.arg {
            Arg::Incoming(reg) => passed(reg).unwrap_or_else(unknown),
            Arg::Deref { reg, off } => passed(reg).map_or_else(unknown, |ps| {
                ps.into_iter()
                    .map(|p| match p.arg {
                        Arg::Incoming(reg) => Val {
                            arg: Arg::Deref { reg, off: *off },
                            at: p.at,
                            pc: p.pc,
                        },
                        _ => Val {
                            arg: Arg::Unknown,
                            at: p.at,
                            pc: p.pc,
                        },
                    })
                    .collect()
            }),
            Arg::Offset { base, off } => {
                let base = Val {
                    arg: (**base).clone(),
                    at: v.at,
                    pc: v.pc,
                };
                self.substitute(&base, top, c)
                    .into_iter()
                    .flat_map(|p| flatten(&p.arg.offset(*off), p.at, p.pc))
                    .collect()
            }
            Arg::Load { base, off, bits } => {
                let base = Val {
                    arg: (**base).clone(),
                    at: v.at,
                    pc: v.pc,
                };
                self.substitute(&base, top, c)
                    .into_iter()
                    .map(|p| Val {
                        arg: match p.arg {
                            Arg::Incoming(reg) if *bits == 64 => Arg::Deref { reg, off: *off },
                            arg => Arg::Load {
                                base: Box::new(arg),
                                off: *off,
                                bits: *bits,
                            },
                        },
                        at: p.at,
                        pc: p.pc,
                    })
                    .collect()
            }
            Arg::Expr { .. } => flatten(&self.calls.substitute_arg(&v.arg, top, c), c.caller, c.pc),
            _ => vec![v.clone()],
        }
    }

    /// Whether `v` is a string the program cannot change (a constant in
    /// read-only memory, or a translation of one) or input.
    fn verdict(&self, v: &Val, depth: u32) -> Verdict {
        let buffer = || {
            self.buffers
                .iter()
                .find(|(b, _, extent)| {
                    if b.arg == v.arg && (matches!(v.arg, Arg::Const(_)) || b.at == v.at) {
                        return true;
                    }
                    let delta = match (&b.arg, &v.arg) {
                        (Arg::Const(start), Arg::Const(at)) => at.checked_sub(*start),
                        (Arg::Stack(start), Arg::Stack(at)) if b.at == v.at => {
                            at.checked_sub(*start).and_then(|n| u64::try_from(n).ok())
                        }
                        (
                            Arg::Frame {
                                function: bf,
                                off: start,
                                ..
                            },
                            Arg::Frame {
                                function: vf,
                                off: at,
                                ..
                            },
                        ) if bf == vf => at.checked_sub(*start).and_then(|n| u64::try_from(n).ok()),
                        _ => None,
                    };
                    delta
                        .zip(*extent)
                        .is_some_and(|(delta, extent)| delta < extent)
                })
                .map_or(Verdict::Other, |(_, i, _)| Verdict::Input(i.clone()))
        };
        match &v.arg {
            Arg::Const(a) if (self.read_const)(*a, &mut [0]) => Verdict::Constant,
            Arg::Const(_) | Arg::Stack(_) | Arg::Frame { .. } => buffer(),
            Arg::Offset { base, .. } if depth < 16 => self.verdict(
                &Val {
                    arg: (**base).clone(),
                    at: v.at,
                    pc: v.pc,
                },
                depth + 1,
            ),
            Arg::Returned { import, .. } if ENVIRONMENT.contains(&base(import)) => {
                Verdict::Input(Input::Environment)
            }
            // As constant as its message ids.
            Arg::Returned { import, pc } if depth < 4 => TRANSLATIONS
                .iter()
                .find(|(n, _)| *n == base(import))
                .zip(self.by_pc.get(pc))
                .map_or(Verdict::Other, |((_, ids), call)| {
                    ids.iter()
                        .flat_map(|&i| {
                            let arg = self.calls.resolve_arg(
                                call.args.get(i).unwrap_or(&Arg::Unknown),
                                call.caller,
                            );
                            flatten(&arg, call.caller, call.pc)
                        })
                        .fold(Verdict::Constant, |acc, id| {
                            acc.or(self.verdict(&id, depth + 1))
                        })
                }),
            Arg::Deref { reg, .. } if self.mains.contains(&v.at) => {
                match self.regs.iter().position(|r| r == reg) {
                    Some(1) => Verdict::Input(Input::CommandLine),
                    Some(2) => Verdict::Input(Input::Environment),
                    _ => Verdict::Other,
                }
            }
            Arg::Load { base, .. } if self.mains.contains(&v.at) => match &**base {
                Arg::Incoming(reg) => match self.regs.iter().position(|r| r == reg) {
                    Some(1) => Verdict::Input(Input::CommandLine),
                    Some(2) => Verdict::Input(Input::Environment),
                    _ => Verdict::Other,
                },
                _ => Verdict::Other,
            },
            _ => Verdict::Other,
        }
    }
}
