use crate::{Error, store::digest};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
};

const MAX_FRAME: usize = 256 * 1024 * 1024;
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Config {
    pub binary: PathBuf,
    pub library: PathBuf,
    pub cpu: Option<String>,
    pub binary_hash: String,
    pub library_hash: String,
    pub parent: u32,
}
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Translation {
    pub pc: u64,
    pub base: u64,
    pub length: usize,
    pub max_insns: u32,
}
#[derive(Serialize, Deserialize)]
pub(crate) enum Request {
    Translate(Vec<Translation>),
    Resolve {
        cfg: Vec<u8>,
        entries: BTreeSet<u64>,
        max_entries: u64,
    },
}
#[derive(Serialize, Deserialize)]
pub(crate) enum GuestError {
    Fetch(u64),
    Args(u64),
    Translate(u64, i32),
}
impl GuestError {
    pub fn into_error(self) -> biara_tcg::Error {
        match self {
            Self::Fetch(pc) => biara_tcg::Error::Fetch { pc },
            Self::Args(pc) => biara_tcg::Error::Args { pc },
            Self::Translate(pc, code) => biara_tcg::Error::Translate { pc, code },
        }
    }
}
#[derive(Serialize, Deserialize)]
pub(crate) enum Response {
    Translate(Vec<Result<Vec<u8>, GuestError>>),
    Resolve(biara_lift::ResolutionArtifact),
    Failed(String),
}
fn write_frame<T: Serialize>(output: &mut impl Write, value: &T) -> Result<(), Error> {
    let bytes = postcard::to_stdvec(value)?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::Engine("worker frame exceeds bounded limit".into()));
    }
    output.write_all(&(bytes.len() as u32).to_le_bytes())?;
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}
fn read_frame<T: serde::de::DeserializeOwned>(input: &mut impl Read) -> Result<Option<T>, Error> {
    let mut length = [0; 4];
    let first = input.read(&mut length[..1])?;
    if first == 0 {
        return Ok(None);
    }
    input.read_exact(&mut length[1..])?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(Error::Engine("worker frame exceeds bounded limit".into()));
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    Ok(Some(postcard::from_bytes(&bytes)?))
}

pub fn worker(config: &str) -> Result<(), Error> {
    let config: Config = serde_json::from_str(config)?;
    #[cfg(target_os = "linux")]
    {
        // Drop is not run when the coordinator is killed by a signal. Register
        // before heavy initialization and close the parent-exit startup race.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { libc::getppid() } as u32 != config.parent {
            return Err(Error::Engine(
                "coordinator exited before worker startup".into(),
            ));
        }
    }
    if digest(&config.binary)? != config.binary_hash
        || digest(&config.library)? != config.library_hash
    {
        return Err(Error::Engine(
            "worker binary/library identity changed".into(),
        ));
    }
    // Committed content-addressed snapshots are never replaced or truncated.
    let image = unsafe { biara_loader::Image::map(&config.binary)? };
    let library = biara_tcg::Libtcg::load(&config.library, config.cpu.as_deref())?;
    let mut lib = library.lock();
    let codec = lib.codec();
    let mut input = BufReader::new(std::io::stdin().lock());
    let mut output = BufWriter::new(std::io::stdout().lock());
    while let Some(request) = read_frame::<Request>(&mut input)? {
        let resolved = matches!(&request, Request::Resolve { .. });
        let response = (|| -> Result<Response, Error> {
            match request {
                Request::Translate(requests) => {
                    let mut results = Vec::with_capacity(requests.len());
                    for request in requests {
                        let (code, base) = image.code_at(request.pc).ok_or_else(|| {
                            Error::Engine("worker request outside executable image".into())
                        })?;
                        if base != request.base || code.len() != request.length {
                            return Err(Error::Engine(
                                "worker code window differs from coordinator".into(),
                            ));
                        }
                        let result = match lib.translate(code, base, request.pc, request.max_insns)
                        {
                            Ok(block) => Ok(codec.encode(&block)?),
                            Err(biara_tcg::Error::Fetch { pc }) => Err(GuestError::Fetch(pc)),
                            Err(biara_tcg::Error::Args { pc }) => Err(GuestError::Args(pc)),
                            Err(biara_tcg::Error::Translate { pc, code }) => {
                                Err(GuestError::Translate(pc, code))
                            }
                            Err(error) => return Err(error.into()),
                        };
                        results.push(result);
                    }
                    Ok(Response::Translate(results))
                }
                Request::Resolve {
                    cfg,
                    entries,
                    max_entries,
                } => {
                    let graph = biara_cfg::Cfg::decode(&cfg, &codec)?;
                    // The wire representation is not analysis state. Release
                    // it before constructing the much larger LLVM graph.
                    drop(cfg);
                    let machine = biara_lift::host_machine()?;
                    let artifact = biara_lift::analyze_resolution(
                        &graph,
                        lib.info(),
                        &machine,
                        &|pc, bytes| image.read_const(pc, bytes),
                        &entries,
                        max_entries,
                    )?;
                    Ok(Response::Resolve(artifact))
                }
            }
        })()
        .unwrap_or_else(|error| Response::Failed(error.to_string()));
        write_frame(&mut output, &response)?;
        drop(response);
        if resolved {
            reclaim_resolution_heap();
        }
    }
    Ok(())
}

// Large LLVM jobs leave glibc's arena fragmented: freeing the IR does not
// return its interior pages automatically. Reclaim only at resolver-job
// boundaries, after all request/IR/response allocations have been dropped.
// Translation batches stay on the allocator's fast reuse path.
fn reclaim_resolution_heap() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        if libc::mallinfo2().fordblks >= 64 * 1024 * 1024 {
            libc::malloc_trim(0);
        }
    }
}
struct Process {
    child: Child,
    input: BufWriter<ChildStdin>,
    reader: Option<JoinHandle<()>>,
}
pub(crate) struct Pool {
    processes: Vec<Process>,
    output: mpsc::Receiver<(usize, Result<Response, Error>)>,
}
impl Pool {
    pub fn new(executable: &std::path::Path, config: &Config, count: usize) -> Result<Self, Error> {
        let (sender, output) = mpsc::channel();
        let mut pool = Self {
            processes: Vec::with_capacity(count),
            output,
        };
        let config = serde_json::to_string(config)?;
        for index in 0..count {
            let mut child = Command::new(executable)
                .arg("__worker")
                .arg(&config)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let input = child
                .stdin
                .take()
                .ok_or_else(|| Error::Engine("worker stdin unavailable".into()))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| Error::Engine("worker stdout unavailable".into()))?;
            let sender = sender.clone();
            let reader = thread::spawn(move || {
                let mut input = BufReader::new(stdout);
                loop {
                    match read_frame::<Response>(&mut input) {
                        Ok(Some(response)) => {
                            if sender.send((index, Ok(response))).is_err() {
                                break;
                            }
                        }
                        Ok(None) => {
                            let _ = sender
                                .send((index, Err(Error::Engine("analysis worker exited".into()))));
                            break;
                        }
                        Err(error) => {
                            let _ = sender.send((index, Err(error)));
                            break;
                        }
                    }
                }
            });
            pool.processes.push(Process {
                child,
                input: BufWriter::new(input),
                reader: Some(reader),
            });
        }
        Ok(pool)
    }
    pub fn send(&mut self, index: usize, request: &Request) -> Result<(), Error> {
        write_frame(&mut self.processes[index].input, request)
    }
    pub fn receive(&self) -> Result<(usize, Response), Error> {
        let (index, response) = self
            .output
            .recv()
            .map_err(|_| Error::Engine("worker channel closed".into()))?;
        let response = response?;
        if let Response::Failed(message) = response {
            return Err(Error::Engine(message));
        }
        Ok((index, response))
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        for process in &mut self.processes {
            let _ = process.child.kill();
        }
        for process in &mut self.processes {
            let _ = process.child.wait();
            if let Some(reader) = process.reader.take() {
                let _ = reader.join();
            }
        }
    }
}
