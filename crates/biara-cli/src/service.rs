//! Provider-neutral jobs. The coordinator runs under RLIMIT_AS plus a Linux
//! RSS watchdog; production deployments MUST additionally confine the job
//! process group in a cgroup (memory.max + pids) — rlimits alone do not cap
//! page-cache, threads, or sibling survivors. Outputs publish only after
//! their footer/database checkpoint is durable. Progress exposes candidates
//! and incremental CFG before ABI or requested C rendering.
use anyhow::{Context, Result, anyhow, bail};
use biara_cfg::{Cfg, ExitKind};
use biara_loader::Image;
use biara_proto::{
    ANALYSIS_TRIPLE, SCHEMA_VERSION,
    annotations::Annotations,
    bundle::{BundleReader, BundleWriter},
    job::{
        AnalysisIndex, CfgBlock, CfgExit, CrossReferences, FunctionEntry, JobSpec, ProgressEvent,
        Stage,
    },
};
use biara_tcg::Libtcg;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, BufRead, Read, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(clap::Args)]
pub(crate) struct WorkerArgs {
    /// JSON job file. Omit or use '-' to read stdin.
    pub job: Option<PathBuf>,
    /// Persistent local working directory. Keep it to inspect or resume failures.
    #[arg(long)]
    pub work_dir: Option<PathBuf>,
}
struct Progress {
    job: String,
    started: Instant,
    sequence: u64,
}
impl Progress {
    fn new(job: &str) -> Self {
        Self {
            job: job.into(),
            started: Instant::now(),
            sequence: 0,
        }
    }
    fn forward(&mut self, mut event: ProgressEvent) -> Result<()> {
        event.job.clone_from(&self.job);
        event.sequence = self.sequence;
        event.elapsed_ms = self
            .started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        self.sequence += 1;
        let mut out = io::stdout().lock();
        serde_json::to_writer(&mut out, &event)?;
        out.write_all(b"\n")?;
        out.flush()?;
        Ok(())
    }
    fn emit(
        &mut self,
        stage: Stage,
        functions: usize,
        blocks: usize,
        address: Option<u64>,
        message: Option<String>,
        data: Option<serde_json::Value>,
    ) -> Result<()> {
        self.forward(ProgressEvent {
            version: SCHEMA_VERSION,
            job: self.job.clone(),
            sequence: 0,
            stage,
            elapsed_ms: 0,
            functions,
            blocks,
            address,
            message,
            data,
        })
    }
}
fn location(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("artifact location must be a file or HTTP URL")?;
    if !matches!(url.scheme(), "file" | "http" | "https") {
        bail!("unsupported artifact URL scheme");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("ambient URL credentials are forbidden");
    }
    Ok(url)
}
fn copy_limited(reader: &mut dyn Read, writer: &mut dyn Write, limit: u64) -> Result<u64> {
    let count = io::copy(&mut reader.take(limit.saturating_add(1)), writer)?;
    if count > limit {
        bail!("artifact exceeds configured input byte limit");
    }
    Ok(count)
}
fn download(
    client: &reqwest::blocking::Client,
    source: &str,
    destination: &Path,
    limit: u64,
) -> Result<()> {
    let url = location(source)?;
    let mut out = File::create(destination)?;
    if url.scheme() == "file" {
        let path = url
            .to_file_path()
            .map_err(|_| anyhow!("invalid file URL"))?;
        copy_limited(&mut File::open(path)?, &mut out, limit)?;
    } else {
        // Range-probe first when the server honors it: a multi-GB resume DB
        // or input must fail before transfer, not after `limit + 1` bytes.
        if let Ok(probe) = client.get(url.clone()).header("Range", "bytes=0-0").send()
            && probe.error_for_status_ref().is_ok()
            && probe.status() == reqwest::StatusCode::PARTIAL_CONTENT
            && let Some(total) = probe
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit('/').next())
                .and_then(|v| v.parse::<u64>().ok())
            && total > limit
        {
            bail!("artifact exceeds input byte limit");
        }
        let mut response = client.get(url).send()?.error_for_status()?;
        if response.content_length().is_some_and(|n| n > limit) {
            bail!("artifact exceeds input byte limit");
        }
        copy_limited(&mut response, &mut out, limit)?;
    }
    out.sync_all()?;
    Ok(())
}
fn upload(client: &reqwest::blocking::Client, source: &Path, destination: &str) -> Result<()> {
    let url = location(destination)?;
    if url.scheme() == "file" {
        let path = url
            .to_file_path()
            .map_err(|_| anyhow!("invalid file URL"))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut temporary = path.as_os_str().to_os_string();
        temporary.push(format!(".{}.tmp", std::process::id()));
        let temporary = PathBuf::from(temporary);
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| -> Result<()> {
            io::copy(&mut File::open(source)?, &mut out)?;
            out.sync_all()?;
            fs::rename(&temporary, &path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    } else {
        let input = File::open(source)?;
        let length = input.metadata()?.len();
        client
            .put(url)
            .body(reqwest::blocking::Body::sized(input, length))
            .send()?
            .error_for_status()?;
        Ok(())
    }
}
pub(crate) fn load_annotations(path: Option<&Path>) -> Result<Annotations> {
    let Some(path) = path else {
        return Ok(Annotations::default());
    };
    let bytes = fs::read(path).with_context(|| path.display().to_string())?;
    let annotations: Annotations = if path.extension().is_some_and(|e| e == "toml") {
        toml::from_str(std::str::from_utf8(&bytes)?)?
    } else {
        serde_json::from_slice(&bytes)?
    };
    annotations.validate().map_err(|e| anyhow!(e.to_string()))?;
    Ok(annotations)
}
fn digest(path: &Path) -> Result<String> {
    let mut hash = blake3::Hasher::new();
    let mut input = File::open(path)?;
    let mut buffer = [0u8; 65536];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash.finalize().to_hex().to_string())
}
/// Cap this coordinator's address space. Callers pass the coordinator share
/// (total/2); the floor is [`biara_proto::MIN_WORKER_BYTES`], matching the
/// engine pool's per-worker share — LLVM's static mapping plus libtcg's JIT
/// reservation abort below ~1 GiB even when resident use is small, and
/// RLIMIT_AS counts mapped pages, not RSS. Production deployments MUST also
/// confine the job in a cgroup; this rlimit never caps page-cache or kills
/// survivors outside the calling process tree.
pub(crate) fn limit_address_space(bytes: u64) -> Result<()> {
    if bytes < biara_proto::MIN_WORKER_BYTES {
        bail!("coordinator address-space budget must be at least 1 GiB");
    }
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        limit.rlim_cur = (bytes as libc::rlim_t).min(limit.rlim_max);
        limit.rlim_max = limit.rlim_cur;
        if unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    #[cfg(not(unix))]
    bail!("memory budgets require Unix resource limits");
    Ok(())
}
/// Linux RSS watchdog over every process in the job's process group — not just the largest worker. Best-effort sampling (100 ms poll, races with fork/exit); the hard enforcement boundary is the deployment's cgroup memory.max, not this monitor. Never claim cgroup confinement here.
#[cfg(target_os = "linux")]
fn group_rss(group: u32) -> Result<u64> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        bail!("cannot determine system page size");
    }
    let mut pages = 0u64;
    let supervisor = std::process::id();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(end) = stat.rfind(')') else {
            continue;
        };
        let mut fields = stat[end + 1..].split_whitespace();
        let pgrp = fields.nth(2).and_then(|f| f.parse::<u32>().ok());
        if pgrp != Some(group) && pid != supervisor {
            continue;
        }
        if let Some(rss) = fields.nth(18).and_then(|f| f.parse::<u64>().ok()) {
            pages = pages.saturating_add(rss);
        }
    }
    Ok(pages.saturating_mul(page as u64))
}
#[cfg(unix)]
fn kill_group(group: u32) {
    unsafe {
        libc::kill(-(group as i32), libc::SIGKILL);
    }
}
struct AnalysisProcess {
    child: std::process::Child,
    armed: bool,
}
impl std::ops::Deref for AnalysisProcess {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.child
    }
}
impl std::ops::DerefMut for AnalysisProcess {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}
impl Drop for AnalysisProcess {
    fn drop(&mut self) {
        if self.armed {
            #[cfg(unix)]
            kill_group(self.child.id());
            #[cfg(not(unix))]
            {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
    }
}

pub(crate) fn worker(args: WorkerArgs) -> Result<()> {
    let job: JobSpec = match args.job.as_deref() {
        Some(path) if path != Path::new("-") => serde_json::from_reader(File::open(path)?)?,
        _ => serde_json::from_reader(io::stdin().lock())?,
    };
    // Pre-run validation must still close the stream with Failed (never an
    // empty stdout): supervisors key cancellation/retry off that terminal
    // event, and a bare process failure carries no job id or sequence.
    let mut progress = Progress::new(&job.id);
    let validated = job.validate().map_err(|e| anyhow!(e)).and_then(|()| {
        for candidate in [&job.input, &job.outputs.bundle, &job.outputs.database]
            .into_iter()
            .chain(job.resume_database.as_ref())
        {
            location(candidate)?;
        }
        Ok(())
    });
    if let Err(error) = validated {
        progress.emit(Stage::Failed, 0, 0, None, Some(error.to_string()), None)?;
        return Err(error);
    }
    let result = run_worker(args, job, &mut progress);
    if let Err(error) = &result {
        progress.emit(Stage::Failed, 0, 0, None, Some(error.to_string()), None)?;
    }
    result
}
fn run_worker(args: WorkerArgs, mut job: JobSpec, progress: &mut Progress) -> Result<()> {
    // The uploader/progress parser is part of the job too. Bound its address
    // space and include it in the RSS watchdog, not just analysis descendants.
    limit_address_space(job.limits.memory_bytes / 2)?;
    job.limits.workers = super::parallelism::resolve(
        NonZeroUsize::new(job.limits.workers),
        job.limits.memory_bytes,
    )?
    .workers();
    let temporary = args.work_dir.is_none();
    let directory = args.work_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!(
            "biara-job-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    });
    fs::create_dir_all(&directory)?;
    let directory = directory.canonicalize()?;
    // Held for the whole job so a second worker cannot reuse the directory
    // and interleave downloads, database writes or progress streams.
    let _lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(directory.join("worker.lock"))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = _lock.as_raw_fd();
        // SAFETY: fd is a live open file; LOCK_EX|LOCK_NB either locks or
        // fails with EWOULDBLOCK, no memory is touched.
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("working directory is already in use");
        }
    }
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(job.limits.wall_seconds))
        .build()?;
    progress.emit(
        Stage::Scan,
        0,
        0,
        None,
        Some("downloading input".into()),
        None,
    )?;
    download(
        &client,
        &job.input,
        &directory.join("input"),
        job.limits.max_input_bytes,
    )?;
    if let Some(resume) = &job.resume_database {
        let compressed = directory.join("resume.zst");
        // A resume DB can legitimately exceed max_input_bytes (108 MB DB for
        // 1.5 MB bash): cap the transfer at the compressed byte count plus
        // headroom for the 64 KiB snapshot hashing overhead, not at the
        // input binary budget.
        let resume_limit = job
            .limits
            .max_input_bytes
            .saturating_mul(8)
            .max(512 * 1024 * 1024);
        download(&client, resume, &compressed, resume_limit)?;
        let mut decoder = zstd::stream::read::Decoder::new(File::open(&compressed)?)?;
        let mut out = File::create(directory.join("analysis.sqlite"))?;
        copy_limited(&mut decoder, &mut out, resume_limit)?;
        out.sync_all()?;
        fs::remove_file(compressed)?;
    }
    fs::write(directory.join("job.json"), serde_json::to_vec(&job)?)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("__service")
        .arg(&directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        // Coordinator gets half; the pool divides the remaining half among
        // its actual worker count. Descendants may only lower this hard cap.
        let cap = job.limits.memory_bytes / 2;
        if cap < biara_proto::MIN_WORKER_BYTES {
            bail!("service memory budget must be at least 2 GiB");
        }
        unsafe {
            command.pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: cap as libc::rlim_t,
                    rlim_max: cap as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    {
        bail!("service worker supervision requires Unix resource limits");
    }
    let mut child = AnalysisProcess {
        child: command.spawn()?,
        armed: true,
    };
    let group = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("worker stdout unavailable"))?;
    let (sender, receiver) = mpsc::sync_channel(16);
    let publisher_client = client.clone();
    let publisher_bundle = directory.join("render.bundle");
    let publisher_destination = job.outputs.bundle.clone();
    let reader = std::thread::spawn(move || {
        for line in io::BufReader::new(stdout).lines() {
            let event = line
                .map_err(anyhow::Error::from)
                .and_then(|line| serde_json::from_str::<ProgressEvent>(&line).map_err(Into::into))
                .and_then(|event| {
                    if event.data.as_ref().is_some_and(|data| {
                        data.get("bundle_ready")
                            .and_then(serde_json::Value::as_bool)
                            == Some(true)
                            || data.get("record").is_some()
                    }) {
                        upload(&publisher_client, &publisher_bundle, &publisher_destination)?;
                    }
                    Ok(event)
                });
            if sender.send(event).is_err() {
                break;
            }
        }
    });
    let mut resource_error = None;
    let mut status = None;
    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => progress.forward(event)?,
            Ok(Err(error)) => {
                resource_error = Some(format!("worker progress publication failed: {error}"));
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(done) = child.try_wait()? {
                    status = Some(done);
                    break;
                }
            }
        }
        if progress.started.elapsed() >= Duration::from_secs(job.limits.wall_seconds) {
            resource_error = Some("wall-clock budget exceeded".into());
            break;
        }
        #[cfg(target_os = "linux")]
        if group_rss(group)? > job.limits.memory_bytes {
            resource_error = Some("aggregate memory budget exceeded".into());
            break;
        }
    }
    if resource_error.is_some() {
        #[cfg(unix)]
        kill_group(group);
        status = Some(child.wait()?);
    }
    // Kill any descendant left behind by a crashed coordinator.
    #[cfg(unix)]
    kill_group(group);
    child.armed = false;
    // Drain whatever the coordinator flushed before the kill (including the
    // early loader index): those events are already durable in render.bundle.
    while let Ok(event) = receiver.try_recv() {
        if let Ok(event) = event {
            progress.forward(event)?;
        }
    }
    drop(receiver);
    reader
        .join()
        .map_err(|_| anyhow!("progress reader panicked"))?;
    progress.emit(
        Stage::Upload,
        0,
        0,
        None,
        Some("publishing resumable database".into()),
        None,
    )?;
    let database = directory.join("analysis.sqlite");
    if database.exists() {
        let snapshot = directory.join("checkpoint.sqlite");
        biara_engine::export_database(&database, &snapshot)?;
        let compressed = directory.join("analysis.sqlite.zst");
        let mut encoder = zstd::stream::write::Encoder::new(File::create(&compressed)?, 3)?;
        io::copy(&mut File::open(&snapshot)?, &mut encoder)?;
        encoder.finish()?.sync_all()?;
        fs::remove_file(&snapshot)?;
        upload(&client, &compressed, &job.outputs.database)?;
    }
    let bundle = directory.join("render.bundle");
    if bundle.exists() {
        upload(&client, &bundle, &job.outputs.bundle)?;
    }
    let success = status.is_some_and(|s| s.success()) && resource_error.is_none();
    if !success {
        let reason =
            resource_error.unwrap_or_else(|| format!("analysis subprocess failed: {:?}", status));
        bail!("{reason}; retained work directory {}", directory.display());
    }
    let artifacts = json!({"bundle_hash":digest(&bundle)?,
        "database_hash":digest(&directory.join("analysis.sqlite.zst"))?});
    if temporary {
        fs::remove_dir_all(directory)?;
    }
    progress.emit(Stage::Complete, 0, 0, None, None, Some(artifacts))?;
    Ok(())
}
fn cfg_block(block: &biara_cfg::BasicBlock) -> CfgBlock {
    CfgBlock {
        address: block.pc(),
        end: block.end(),
        instructions: block.insns.clone(),
        exits: block
            .exits
            .iter()
            .map(|e| {
                let (kind, target, continuation, slot) = match e.kind {
                    ExitKind::Jump(t) => ("jump", Some(t), None, None),
                    ExitKind::Call { target, ret } => ("call", Some(target), Some(ret), None),
                    ExitKind::IndirectCall { ret, slot } => {
                        ("indirect_call", None, Some(ret), slot)
                    }
                    ExitKind::IndirectJump { slot } => ("indirect_jump", None, None, slot),
                    ExitKind::Return => ("return", None, None, None),
                    ExitKind::Syscall { next } => ("syscall", None, Some(next), None),
                };
                CfgExit {
                    kind: kind.into(),
                    target,
                    continuation,
                    slot,
                    op: e.op,
                }
            })
            .collect(),
    }
}
fn name_of(image: &Image, cfg: &Cfg, annotations: &Annotations, address: u64) -> Option<String> {
    annotations
        .functions
        .get(&address)
        .and_then(|f| f.name.clone())
        .or_else(|| image.function_at(address).map(|f| f.name.clone()))
        .or_else(|| cfg.stub_import(address).map(|n| format!("{n}@plt")))
}
fn strings(image: &Image) -> BTreeMap<u64, String> {
    let mut strings = BTreeMap::new();
    for segment in &image.segments {
        if segment.exec {
            continue;
        }
        let bytes = image.data(segment);
        let mut start = 0;
        while start < bytes.len() {
            let mut end = start;
            while end < bytes.len()
                && (bytes[end].is_ascii_graphic()
                    || matches!(bytes[end], b' ' | b'\t' | b'\r' | b'\n'))
            {
                end += 1;
            }
            if end - start >= 4 && end < bytes.len() && bytes[end] == 0 {
                let address = segment.addr + start as u64;
                strings.insert(
                    address,
                    String::from_utf8_lossy(&bytes[start..end]).into_owned(),
                );
            }
            start = end.saturating_add(1);
        }
    }
    strings
}

pub(crate) fn execute(directory: &Path) -> Result<()> {
    let job: JobSpec = serde_json::from_reader(File::open(directory.join("job.json"))?)?;
    job.validate().map_err(|e| anyhow!(e))?;
    let input = directory.join("input");
    let image = Image::load(&input)?;
    let entries: Vec<_> = if job.entries.is_empty() {
        image.function_starts().into_iter().collect()
    } else {
        job.entries.clone()
    };
    if entries.iter().any(|&e| !image.is_code(e)) {
        bail!("entry address outside executable image");
    }
    let mut progress = Progress::new(&job.id);
    progress.emit(Stage::Scan, entries.len(), 0, None, None,
        Some(json!({"candidates":entries.iter().map(|&address| json!({"address":address,"name":image.function_at(address).map(|f|&f.name)})).collect::<Vec<_>>()})))?;
    // First usable artifact even if recovery aborts under its caps: names and
    // code membership are loader facts, not CFG conclusions. Later stages
    // overwrite this record with the recovered index; readers key staleness
    // off `complete`/`issues`, never off presence alone.
    let mut index = AnalysisIndex {
        version: SCHEMA_VERSION,
        binary_hash: digest(&input)?,
        build_hash: digest(&std::env::current_exe()?)?,
        annotation_hash: blake3::hash(&serde_json::to_vec(&job.annotations)?)
            .to_hex()
            .to_string(),
        target_triple: ANALYSIS_TRIPLE.into(),
        arch: image.arch.into(),
        os: image.os.into(),
        functions: entries
            .iter()
            .map(|&address| FunctionEntry {
                address,
                name: image.function_at(address).map(|f| f.name.clone()),
                blocks: Vec::new(),
                calls: Vec::new(),
                returns: false,
            })
            .collect(),
        rendered: Vec::new(),
        complete: false,
        issues: Vec::new(),
    };
    let mut early = BundleWriter::new(File::create(directory.join("render.next"))?)?;
    early.append("index", &index)?;
    early.finish()?.sync_all()?;
    fs::rename(
        directory.join("render.next"),
        directory.join("render.bundle"),
    )?;
    progress.emit(
        Stage::Cfg,
        entries.len(),
        0,
        None,
        Some("candidates indexed".into()),
        Some(json!({"bundle_ready":true})),
    )?;
    let options = biara_lift::ResolveOptions {
        cfg: biara_cfg::Options {
            os: image.os,
            max_blocks: job.limits.max_blocks,
            imports: image.imports.clone(),
            function_starts: image.function_starts(),
            discovery: job.entries.is_empty().then(|| biara_cfg::Discovery {
                code: image.code.clone(),
                extents: image.function_extents(),
                data_pointers: image.code_pointers.clone(),
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    let workers = job.limits.workers;
    let mut session = biara_engine::Session::open(
        biara_engine::Options {
            binary: input.clone(),
            libtcg: Libtcg::find(image.arch)?,
            cpu: None,
            database: Some(directory.join("analysis.sqlite")),
            workers,
            executable: std::env::current_exe()?,
            memory_budget: job.limits.memory_bytes,
        },
        &entries,
        &options,
    )?;
    let job_id = job.id.clone();
    let mut seen = BTreeMap::new();
    session.set_progress(Box::new(move |cfg| {
        let mut changed = Vec::new();
        for (&pc, block) in &cfg.blocks {
            let revision = (block.end(), block.insns.len());
            if seen.get(&pc) != Some(&revision) {
                seen.insert(pc, revision);
                changed.push(cfg_block(block));
            }
            if changed.len() == 64 {
                Progress::new(&job_id)
                    .emit(
                        Stage::Cfg,
                        cfg.functions.len(),
                        cfg.blocks.len(),
                        None,
                        None,
                        Some(json!({"blocks":changed})),
                    )
                    .map_err(|e| biara_engine::Error::Engine(e.to_string()))?;
                changed.clear();
            }
        }
        Progress::new(&job_id)
            .emit(
                Stage::Cfg,
                cfg.functions.len(),
                cfg.blocks.len(),
                None,
                None,
                Some(json!({"blocks":changed})),
            )
            .map_err(|e| biara_engine::Error::Engine(e.to_string()))
    }));
    let machine = biara_lift::analysis_machine()?;
    let cfg = biara_lift::recover_resolving(
        &mut session,
        &machine,
        &|pc| image.code_at(pc),
        &|addr, buf| image.read_const(addr, buf),
        &entries,
        options,
    )?;
    session.finish(&cfg)?;
    let lib = session.lib();
    drop(session);
    progress.emit(
        Stage::Cfg,
        cfg.functions.len(),
        cfg.blocks.len(),
        None,
        Some("recovery committed".into()),
        None,
    )?;
    // Recovery committed: stream the full graph (CFG/xrefs/imports/strings)
    // plus ABI into a staged file in one durable `finish`. Every publication
    // replaces render.bundle atomically, preserving the prior usable footer
    // if recovery, ABI inference, or a lazy render aborts.
    let mut bundle = BundleWriter::new(File::create(directory.join("render.next"))?)?;
    for (&pc, block) in &cfg.blocks {
        bundle.append(&format!("cfg/{pc:x}"), &cfg_block(block))?;
    }
    bundle.append("cfg/targets", &json!({"jump_tables":cfg.jump_tables,"incomplete_jump_tables":cfg.incomplete_jump_tables,"indirect_calls":cfg.indirect_calls}))?;
    let mut xrefs = CrossReferences {
        callers: BTreeMap::new(),
        callees: BTreeMap::new(),
    };
    for (&entry, function) in &cfg.functions {
        let callees: BTreeSet<_> = function
            .calls
            .union(&function.tail_calls)
            .copied()
            .collect();
        for &callee in &callees {
            xrefs.callers.entry(callee).or_default().push(entry);
        }
        xrefs.callees.insert(entry, callees.into_iter().collect());
    }
    bundle.append("xrefs", &xrefs)?;
    bundle.append("imports", &image.imports)?;
    bundle.append("strings", &strings(&image))?;
    progress.emit(
        Stage::Abi,
        cfg.functions.len(),
        cfg.blocks.len(),
        None,
        Some("recovering signatures".into()),
        None,
    )?;
    let guard = lib.lock();
    let mut abis = biara_abi::analyze_with_workers(&cfg, guard.info(), workers)?;
    biara_lift::annotations::apply_abi_annotations(
        &cfg,
        guard.info(),
        &mut abis,
        &job.annotations,
    )?;
    bundle.append("abi", &abis)?;
    index.functions = cfg
        .functions
        .iter()
        .map(|(&address, function)| FunctionEntry {
            address,
            name: name_of(&image, &cfg, &job.annotations, address),
            blocks: function.blocks.iter().copied().collect(),
            calls: function
                .calls
                .union(&function.tail_calls)
                .copied()
                .collect(),
            returns: function.returns,
        })
        .collect();
    index.complete = cfg.issues().next().is_none();
    index.issues = cfg
        .issues()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    bundle.append("index", &index)?;
    bundle.finish()?.sync_all()?;
    fs::rename(
        directory.join("render.next"),
        directory.join("render.bundle"),
    )?;
    progress.emit(
        Stage::Abi,
        cfg.functions.len(),
        cfg.blocks.len(),
        None,
        Some("signatures ready".into()),
        Some(json!({"bundle_ready":true})),
    )?;
    let requested: BTreeSet<_> = job.decompile.iter().copied().collect();
    // Explicit name/signature overrides of non-functions are caller errors:
    // `name_of` would silently ignore them and the prepared module would
    // never reference them, so fail loudly before ABI instead of rendering
    // under a name the bundle index never shows.
    for (&address, function) in &job.annotations.functions {
        if !cfg.functions.contains_key(&address)
            && (function.name.is_some() || function.signature.is_some())
        {
            bail!("annotation address {address:#x} is not a recovered function");
        }
    }
    for &address in &requested {
        if !cfg.functions.contains_key(&address) {
            bail!("requested decompilation address {address:#x} is not a recovered function");
        }
        progress.emit(
            Stage::Decomp,
            cfg.functions.len(),
            cfg.blocks.len(),
            Some(address),
            None,
            None,
        )?;
        let selected = BTreeSet::from([address]);
        let cx = inkwell::context::Context::create();
        let mut prepared = biara_lift::prepare_c_selected(
            &cx,
            &machine,
            guard.info(),
            &cfg,
            &abis,
            &|e| name_of(&image, &cfg, &job.annotations, e),
            "Service analysis",
            &image.data,
            &selected,
        )?;
        prepared.apply_annotations(&job.annotations)?;
        let mut transformed = prepared.transform(
            &machine,
            &|a, b| image.read_const(a, b),
            biara_lift::DecompileOptions::with_workers(NonZeroUsize::new(workers).unwrap()),
        )?;
        transformed.apply_image_debug(&image);
        transformed.apply_annotations(&job.annotations)?;
        // Fully render this function into staged (in-memory) records first.
        // Nothing here touches the committed bundle: if any step below fails,
        // the previously published footer still parses and still serves every
        // earlier body. Only a completely rendered function is publishable.
        let type_facts = transformed.type_facts()?;
        transformed.select_functions(&[address]);
        let mut staged_package = None;
        transformed.visit_functions(&mut |package| {
            if staged_package.is_some() {
                return Err(io::Error::other("unexpected extra function package"));
            }
            staged_package = Some(package);
            Ok(())
        })?;
        let package = staged_package
            .ok_or_else(|| anyhow!("decompilation produced no package for {address:#x}"))?;
        // Calls and audit are constrained to this body and its dependency facts.
        let view = biara_lift::resolution_view(&cfg, &selected);
        let summaries = abis
            .iter()
            .filter(|(e, _)| view.functions.contains_key(e))
            .map(|(&e, abi)| (e, abi.clone()))
            .collect();
        let mut calls =
            biara_lift::CallSites::with_abis(&machine, guard.info(), &view, Some(summaries))?;
        calls.add(&selected)?;
        let findings = biara_lift::audit::audit(
            &mut calls,
            &image.indirect_entries(),
            image.main,
            &|a, b| image.read_const(a, b),
            &|q| super::json::object_bound(&image, q),
        )?;
        let staged_calls: Vec<_> = calls.sites().iter().map(super::json::call).collect();
        let staged_audit: Vec<_> = findings.iter().map(super::json::finding).collect();
        // Durable publish boundary: byte-copy the committed record prefix
        // into `render.next` (bounded buffer, no JSON decode), adopt the
        // prior footer index, append the complete function and updated index,
        // then atomically rename. The CFG payloads never inflate into a JSON
        // tree: O(bundle) disk I/O, O(index + function) memory.
        index.rendered.push(address);
        publish_records(directory, |bundle| {
            bundle.append(&format!("types/{address:x}"), &type_facts)?;
            bundle.append(&format!("decomp/{address:x}"), &package)?;
            bundle.append(&format!("calls/{address:x}"), &staged_calls)?;
            bundle.append(&format!("audit/{address:x}"), &staged_audit)?;
            bundle.append("index", &index)?;
            Ok(())
        })?;
        let bundle_path = directory.join("render.bundle");
        let (offset, length) = BundleReader::new(File::open(&bundle_path)?)?
            .entry_range(&format!("decomp/{address:x}"))
            .ok_or_else(|| anyhow!("published package missing from bundle index"))?;
        progress.emit(
            Stage::Decomp,
            cfg.functions.len(),
            cfg.blocks.len(),
            Some(address),
            Some("function ready".into()),
            Some(json!({"record": format!("decomp/{address:x}"), "offset": offset, "length": length})),
        )?;
    }
    Ok(())
}

/// Atomically extend the committed `render.bundle` through `append`:
/// byte-copy the record prefix, adopt the prior footer index, append the new
/// records, commit a fresh footer, sync, and rename over the old bundle.
/// Prior payloads are never decoded (bounded 128 KiB copy buffer); only the
/// footer index (name -> range) and the new records sit in memory.
fn publish_records(
    directory: &Path,
    append: impl FnOnce(&mut BundleWriter<File>) -> Result<()>,
) -> Result<()> {
    let bundle_path = directory.join("render.bundle");
    let next_path = directory.join("render.next");
    let committed = BundleReader::new(File::open(&bundle_path)?)?;
    let prefix_end = committed.records_end();
    let snapshot = committed.index_snapshot();
    let mut source = File::open(&bundle_path)?;
    let mut next_file = File::create(&next_path)?;
    biara_proto::bundle::copy_prefix(&mut source, &mut next_file, prefix_end)?;
    let mut next = BundleWriter::new(next_file)?;
    for (name, (offset, length)) in snapshot {
        next.adopt(name, offset, length);
    }
    append(&mut next)?;
    next.finish()?.sync_all()?;
    fs::rename(&next_path, &bundle_path)?;
    Ok(())
}
