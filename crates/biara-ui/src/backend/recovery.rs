//! Opening a binary: parse, recover the program on the engine's worker pool, analyse ABIs and
//! build the indexes, reporting each stage as it finishes.
//!
//! This runs on its own thread and talks to the UI only through [`Event`]s, so the window
//! stays responsive for the whole analysis. The image is parsed first and published at once
//! with a symbol-based function list; recovery replaces it when it completes.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
};

use biara_loader::Image;
use biara_tcg::Libtcg;

use super::{
    disasm::Arch,
    program::{Index, Program},
};

/// Wakes the UI thread after an event is queued.
pub type Notify = Arc<dyn Fn() + Send + Sync>;

/// Where recovery is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Loading,
    Recovering,
    Abi,
    Indexing,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Stage::Loading => "Reading image",
            Stage::Recovering => "Recovering control flow",
            Stage::Abi => "Analysing calling conventions",
            Stage::Indexing => "Indexing",
        }
    }
}

/// What the recovery thread tells the UI.
pub enum Event {
    /// The image parsed. `preview` lists what symbols alone say about its functions.
    Opened {
        image: Arc<Image>,
        preview: Arc<Index>,
        arch: Arch,
    },
    Progress {
        stage: Stage,
        functions: usize,
        blocks: usize,
    },
    /// Recovery finished; everything is available.
    Ready(Arc<Program>),
    Failed(String),
}

/// Where the engine keeps its state and which executable its workers run.
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    /// Analysis database; `None` uses the engine's content-addressed user cache, so reopening
    /// a binary resumes where it left off.
    pub database: Option<PathBuf>,
    /// Executable the engine's worker processes run (it must answer `__worker`); `None` is
    /// this process's own executable.
    pub worker_exe: Option<PathBuf>,
    /// Analysis worker processes; `None` picks from the core count and free memory.
    pub workers: Option<usize>,
    /// Analysis memory budget in MiB, shared by the coordinator and the workers; `None` picks
    /// from free memory.
    pub memory_mib: Option<u64>,
}

/// Start opening `path` on a new thread; events arrive on the returned channel.
pub fn open(path: PathBuf, notify: Notify, options: OpenOptions) -> mpsc::Receiver<Event> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("biara-recovery".into())
        .spawn(move || {
            let send = {
                let tx = tx.clone();
                let notify = notify.clone();
                move |event: Event| {
                    let _ = tx.send(event);
                    notify();
                }
            };
            if let Err(e) = run(&path, &options, &send) {
                send(Event::Failed(format!("{e:#}")));
            }
        })
        .expect("spawn recovery thread");
    rx
}

fn run(
    path: &Path,
    options: &OpenOptions,
    send: &(impl Fn(Event) + Clone + Send + 'static),
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    send(Event::Progress {
        stage: Stage::Loading,
        functions: 0,
        blocks: 0,
    });
    let image = Image::load(path).with_context(|| path.display().to_string())?;
    let arch = Arch::from_name(image.arch)
        .with_context(|| format!("{}: no disassembler for this architecture", image.arch))?;
    let image = Arc::new(image);
    send(Event::Opened {
        image: image.clone(),
        preview: Arc::new(Index::preview(&image)),
        arch,
    });

    let libtcg = find_libtcg(image.arch)?;
    let (workers, memory) = budget(options);
    let discovery = biara_cfg::Discovery {
        code: image.code.clone(),
        extents: image.function_extents(),
        data_pointers: image.code_pointers.clone(),
    };
    let entries: Vec<u64> = image.function_starts().into_iter().collect();
    let opts = biara_lift::ResolveOptions {
        cfg: biara_cfg::Options {
            os: image.os,
            imports: image.imports.clone(),
            discovery: Some(discovery),
            function_starts: image.function_starts(),
            ..Default::default()
        },
        ..Default::default()
    };
    send(Event::Progress {
        stage: Stage::Recovering,
        functions: 0,
        blocks: 0,
    });
    let mut session = biara_engine::Session::open(
        biara_engine::Options {
            binary: path.to_owned(),
            libtcg,
            cpu: None,
            database: options.database.clone(),
            workers,
            memory_budget: memory,
            executable: match &options.worker_exe {
                Some(exe) => exe.clone(),
                None => std::env::current_exe()?,
            },
        },
        &entries,
        &opts,
    )?;
    {
        let send = send.clone();
        session.set_progress(Box::new(move |cfg| {
            send(Event::Progress {
                stage: Stage::Recovering,
                functions: cfg.functions.len(),
                blocks: cfg.blocks.len(),
            });
            Ok(())
        }));
    }
    let lib = session.lib();
    let cfg = biara_lift::recover_resolving(
        &mut session,
        &biara_lift::analysis_machine()?,
        &|pc| image.code_at(pc),
        &|addr, buf| image.read_const(addr, buf),
        &entries,
        opts,
    )?;
    session.finish(&cfg)?;
    drop(session);

    send(Event::Progress {
        stage: Stage::Abi,
        functions: cfg.functions.len(),
        blocks: cfg.blocks.len(),
    });
    let abis = biara_abi::analyze_with_workers(&cfg, lib.lock().info(), workers)?;

    send(Event::Progress {
        stage: Stage::Indexing,
        functions: cfg.functions.len(),
        blocks: cfg.blocks.len(),
    });
    let index = Index::build(&image, &cfg, &abis);
    let listing = super::listing::Listing::build(&image, &cfg, &index);
    send(Event::Ready(Arc::new(Program {
        path: path.to_owned(),
        arch,
        image,
        cfg: Arc::new(cfg),
        abis: Arc::new(abis),
        index: Arc::new(index),
        listing,
        lib,
    })));
    Ok(())
}

/// The libtcg for `arch`: `$BIARA_LIBTCG_DIR`, then next to the executable, then the
/// workspace's build output (development).
pub fn find_libtcg(arch: &str) -> anyhow::Result<PathBuf> {
    if let Ok(p) = Libtcg::find(arch) {
        return Ok(p);
    }
    let name = format!("libtcg-{arch}.so");
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_owned))
    {
        dirs.push(dir.clone());
        dirs.push(dir.join("lib"));
    }
    dirs.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.deps/out"));
    dirs.iter()
        .map(|d| d.join(&name))
        .find(|p| p.is_file())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{name} not found; set BIARA_LIBTCG_DIR (scripts/build-libtcg.sh builds it)"
            )
        })
}

/// Worker count and memory budget for the engine: every core but one, bounded by half of the
/// memory that is free (each worker gets at least 1 GiB of the budget's other half).
fn budget(options: &OpenOptions) -> (usize, u64) {
    const GIB: u64 = 1 << 30;
    let cores = std::thread::available_parallelism().map_or(2, |n| n.get());
    let available = available_memory().unwrap_or(8 * GIB);
    let memory = options
        .memory_mib
        .map_or_else(|| (available / 2).clamp(4 * GIB, 32 * GIB), |m| m << 20);
    let by_memory = (memory / 2 / GIB) as usize;
    let workers = options
        .workers
        .unwrap_or_else(|| cores.saturating_sub(1))
        .clamp(1, by_memory.max(1));
    (workers, memory)
}

fn available_memory() -> Option<u64> {
    let info = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb: u64 = info
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kb * 1024)
}
