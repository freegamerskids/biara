#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use biara_proto::{
    FunctionPackage,
    bundle::BundleReader,
    job::{AnalysisIndex, ProgressEvent, Stage},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::Path,
    process::{Command, Output, Stdio},
};

fn file_url(path: &Path) -> String {
    format!("file://{}", path.display())
}

fn run_job(
    spec: &Value,
    directory: &Path,
    name: &str,
) -> (Output, Vec<ProgressEvent>, Vec<FunctionPackage>) {
    let path = directory.join(format!("{name}.json"));
    fs::write(&path, serde_json::to_vec(spec).unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_biara"))
        .arg("worker")
        .arg(path)
        .arg("--work-dir")
        .arg(directory.join(name))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let mut stdout = Vec::new();
    let mut events = Vec::new();
    let mut ready_packages = Vec::new();
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        stdout.extend_from_slice(line.as_bytes());
        stdout.push(b'\n');
        let event: ProgressEvent = serde_json::from_str(&line).unwrap();
        if let Some(data) = event.data.as_ref().filter(|d| d.get("record").is_some()) {
            // Consume the externally published byte range as soon as Ready is
            // delivered, not after Complete. A premature Ready or torn upload
            // cannot serve a usable package to this consumer.
            let bundle = reqwest::Url::parse(spec["outputs"]["bundle"].as_str().unwrap())
                .unwrap()
                .to_file_path()
                .unwrap();
            let mut raw = fs::File::open(&bundle).unwrap();
            raw.seek(SeekFrom::Start(data["offset"].as_u64().unwrap()))
                .unwrap();
            let mut payload = vec![0; data["length"].as_u64().unwrap() as usize];
            raw.read_exact(&mut payload).unwrap();
            let package: FunctionPackage = serde_json::from_slice(&payload).unwrap();
            let mut committed = BundleReader::new(fs::File::open(&bundle).unwrap()).unwrap();
            let index: AnalysisIndex = committed.get("index").unwrap();
            assert!(index.rendered.contains(&package.address));
            ready_packages.push(package);
        }
        events.push(event);
    }
    let output = Output {
        status: child.wait().unwrap(),
        stdout,
        stderr: errors.join().unwrap(),
    };
    (output, events, ready_packages)
}

fn build_fixture(directory: &Path) -> (u64, u64, u64) {
    let source = directory.join("input.c");
    fs::write(
        &source,
        "__attribute__((noinline,used)) unsigned long helper(unsigned long a){return a*3+1;}\n__attribute__((noinline,used)) unsigned long selected(unsigned long a,unsigned long b){return helper(a)+2*b;}\n__attribute__((noinline,used)) unsigned long unrequested(unsigned long a){return a^19;}\nint main(void){return (int)(selected(3,4)!=23);}",
    )
    .unwrap();
    let input = directory.join("input");
    let status = Command::new(env!("BIARA_CLANG"))
        .args(["-O2", "-fno-pie", "-no-pie", "-fno-stack-protector"])
        .arg(&source)
        .arg("-o")
        .arg(&input)
        .status()
        .unwrap();
    assert!(status.success());
    let image = biara_loader::Image::load(&input).unwrap();
    let selected = image.symbol("selected").unwrap().addr;
    let unrequested = image.symbol("unrequested").unwrap().addr;
    let helper = image.symbol("helper").unwrap().addr;
    (selected, unrequested, helper)
}

fn base_job(directory: &Path, id: &str, bundle: &Path, database: &Path) -> Value {
    let input = directory.join("input");
    json!({"version":1,"id":id,"input":file_url(&input),
        "outputs":{"bundle":file_url(bundle),"database":file_url(database)},
        "entries":[],"decompile":[],
        "limits":{"memory_bytes":2147483648u64,"wall_seconds":300,"workers":1,"max_blocks":100000,"max_input_bytes":67108864u64}})
}
#[test]
fn worker_resumes_transferred_database_and_renders_only_requested_function() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join("worker-resume");
    // Fresh tree per run: reused work dirs keep stale analysis.sqlite/bundles.
    if directory.exists() {
        fs::remove_dir_all(&directory).unwrap();
    }
    fs::create_dir_all(&directory).unwrap();
    let (selected, unrequested, helper) = build_fixture(&directory);
    let bundle = directory.join("first.bundle");
    let database = directory.join("first.sqlite.zst");
    let job = base_job(&directory, "first", &bundle, &database);
    let (output, first_events, _) = run_job(&job, &directory, "first-host");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        first_events
            .windows(2)
            .all(|w| w[0].sequence < w[1].sequence)
    );
    let scan = first_events
        .iter()
        .position(|e| e.stage == Stage::Scan && e.data.is_some())
        .unwrap();
    let cfg = first_events
        .iter()
        .position(|e| e.stage == Stage::Cfg)
        .unwrap();
    let abi = first_events
        .iter()
        .position(|e| e.stage == Stage::Abi)
        .unwrap();
    assert!(scan < cfg && cfg < abi);
    assert!(!first_events.iter().any(|e| e.stage == Stage::Decomp));
    assert_eq!(first_events.last().unwrap().stage, Stage::Complete);
    let data = first_events.last().unwrap().data.as_ref().unwrap();
    assert_eq!(
        data["bundle_hash"],
        json!(blake3::hash(&fs::read(&bundle).unwrap()).to_hex().as_str())
    );
    assert_eq!(
        data["database_hash"],
        json!(
            blake3::hash(&fs::read(&database).unwrap())
                .to_hex()
                .as_str()
        )
    );
    let mut first = BundleReader::new(fs::File::open(&bundle).unwrap()).unwrap();
    let index: AnalysisIndex = first.get("index").unwrap();
    assert!(index.rendered.is_empty());
    assert!(!index.complete || index.issues.is_empty());
    assert!(index.functions.iter().any(|f| f.address == selected));
    assert!(index.functions.iter().any(|f| f.address == unrequested));
    // `cfg/<addr>` records are independently fetchable by footer byte range.
    let block_addr = index
        .functions
        .iter()
        .find(|f| f.address == selected)
        .and_then(|f| f.blocks.first())
        .copied()
        .unwrap();
    let (offset, length) = first.entry_range(&format!("cfg/{block_addr:x}")).unwrap();
    let mut raw = fs::File::open(&bundle).unwrap();
    raw.seek(SeekFrom::Start(offset)).unwrap();
    let mut payload = vec![0u8; length as usize];
    raw.read_exact(&mut payload).unwrap();
    let ranged: Value = serde_json::from_slice(&payload).unwrap();
    let mut reread = BundleReader::new(fs::File::open(&bundle).unwrap()).unwrap();
    let indexed: Value = reread.get(&format!("cfg/{block_addr:x}")).unwrap();
    assert_eq!(ranged, indexed);

    let second_bundle = directory.join("second.bundle");
    let mut resumed = job.clone();
    resumed["id"] = json!("resumed");
    resumed["resume_database"] = json!(file_url(&database));
    resumed["decompile"] = json!([selected]);
    resumed["outputs"]["bundle"] = json!(file_url(&second_bundle));
    resumed["outputs"]["database"] = json!(file_url(&directory.join("second.sqlite.zst")));
    resumed["annotations"] =
        json!({"version":1,"functions":{selected.to_string():{"name":"renamed"}}});
    let (output, events, ready_packages) = run_job(&resumed, &directory, "second-host");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        events
            .iter()
            .any(|e| e.stage == Stage::Decomp && e.address == Some(selected))
    );
    assert!(
        !events
            .iter()
            .any(|e| e.stage == Stage::Decomp && e.address == Some(unrequested))
    );
    assert_eq!(events.last().unwrap().stage, Stage::Complete);
    let mut second = BundleReader::new(fs::File::open(&second_bundle).unwrap()).unwrap();
    let index: AnalysisIndex = second.get("index").unwrap();
    assert_eq!(index.rendered, vec![selected]);
    let package = ready_packages
        .into_iter()
        .find(|p| p.address == selected)
        .unwrap();
    assert_eq!(package.name, "renamed");
    let calls: Vec<Value> = second.get(&format!("calls/{selected:x}")).unwrap();
    // Exact behavior: the selected body calls `helper` at its guest address
    // (callee is `{"kind":"function","address":…}`, not a name string).
    assert!(
        calls.iter().any(|c| c
            .get("callee")
            .and_then(|v| v.get("address"))
            .and_then(|v| v.as_u64())
            .is_some_and(|a| a == helper)),
        "{}",
        serde_json::to_string_pretty(&calls).unwrap()
    );
    assert!(
        second
            .get::<FunctionPackage>(&format!("decomp/{unrequested:x}"))
            .is_err()
    );
    // Execute the requested, renamed function from its independently fetched
    // package plus the REAL helper body (fetched lazily, not reimplemented):
    // render `helper` itself through a second job over the transferred resume
    // DB, then link both real bodies. If the lazy callee had no real body
    // (undefined reference or dispatch stub), this link fails loudly.
    let helper_bundle = directory.join("helper.bundle");
    let helper_db = directory.join("helper.sqlite.zst");
    let mut helper_job = base_job(&directory, "helper", &helper_bundle, &helper_db);
    helper_job["resume_database"] = json!(file_url(&directory.join("second.sqlite.zst")));
    helper_job["decompile"] = json!([helper]);
    let (output, _, helper_packages) = run_job(&helper_job, &directory, "helper-host");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let helper_package = helper_packages
        .into_iter()
        .find(|p| p.address == helper)
        .unwrap();
    let mut generated = String::from("#include <stdint.h>\n");
    for dependency in package
        .dependencies
        .iter()
        .chain(helper_package.dependencies.iter())
    {
        generated.push_str(&dependency.text);
    }
    generated.push_str(&helper_package.body);
    generated.push_str(&package.body);
    // The oracle is the fixture's own source, compiled alongside: the recovered function must
    // agree with it on a grid of inputs (not with constants worked out by hand).
    generated.push_str(
        "\nstatic unsigned long ref_helper(unsigned long a){return a*3+1;}\n\
         static unsigned long ref_selected(unsigned long a,unsigned long b){return ref_helper(a)+2*b;}\n\
         int main(void){\n\
           for (unsigned long a = 0; a < 40; a++) for (unsigned long b = 0; b < 40; b++)\n\
             if (renamed(a,b) != ref_selected(a,b)) return 1;\n\
           return renamed(3,4) != 18;\n\
         }\n",
    );
    let c = directory.join("recovered.c");
    fs::write(&c, generated).unwrap();
    let executable = directory.join("recovered");
    let output = Command::new(env!("BIARA_CLANG"))
        .arg(&c)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}

#[test]
fn worker_failure_reports_failed_and_still_uploads_resume_database() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join("worker-failure");
    if directory.exists() {
        fs::remove_dir_all(&directory).unwrap();
    }
    fs::create_dir_all(&directory).unwrap();
    let (selected, _, helper) = build_fixture(&directory);
    let bundle = directory.join("failed.bundle");
    let database = directory.join("failed.sqlite.zst");
    let mut job = base_job(&directory, "will-fail", &bundle, &database);
    // Recovery succeeds, then an unknown requested entry aborts decompilation.
    // Both the committed graph and the resumable DB must remain consumable;
    // only the terminal job state is Failed.
    job["decompile"] = json!([selected, 0x1u64]);
    let (output, events, _) = run_job(&job, &directory, "failed-host");
    assert!(!output.status.success());
    assert_eq!(events.last().unwrap().stage, Stage::Failed);
    assert!(!events.iter().any(|e| e.stage == Stage::Complete));
    let mut early = BundleReader::new(fs::File::open(&bundle).unwrap()).unwrap();
    let index: AnalysisIndex = early.get("index").unwrap();
    assert!(index.rendered.is_empty());
    assert!(index.functions.iter().any(|f| f.address == selected));
    let resumed_bundle = directory.join("resumed.bundle");
    let resumed_database = directory.join("resumed.sqlite.zst");
    let mut resumed = base_job(
        &directory,
        "after-failure",
        &resumed_bundle,
        &resumed_database,
    );
    resumed["resume_database"] = json!(file_url(&database));
    let (output, events, _) = run_job(&resumed, &directory, "new-host-after-failure");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(events.last().unwrap().stage, Stage::Complete);
    let mut recovered = BundleReader::new(fs::File::open(resumed_bundle).unwrap()).unwrap();
    let block: biara_proto::job::CfgBlock = recovered.get(&format!("cfg/{selected:x}")).unwrap();
    assert!(
        block
            .exits
            .iter()
            .any(|exit| exit.kind == "call" && exit.target == Some(helper))
    );
}

#[test]
fn worker_rejects_unusable_artifact_locations_before_work() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join("worker-bad-url");
    if directory.exists() {
        fs::remove_dir_all(&directory).unwrap();
    }
    fs::create_dir_all(&directory).unwrap();
    let (selected, _, _) = build_fixture(&directory);
    let bundle = directory.join("bad.bundle");
    let database = directory.join("bad.sqlite.zst");
    let mut job = base_job(&directory, "bad-url", &bundle, &database);
    job["input"] = json!("ftp://example.invalid/binary");
    let (output, events, _) = run_job(&job, &directory, "bad-host");
    assert!(!output.status.success());
    assert_eq!(events.last().unwrap().stage, Stage::Failed);
    assert!(!bundle.exists());
    assert!(!database.exists());

    // Explicit renames of non-functions fail loudly at ABI time rather than
    // rendering silently under a name the bundle index never shows.
    let bundle = directory.join("bad-annotation.bundle");
    let database = directory.join("bad-annotation.sqlite.zst");
    let mut job = base_job(&directory, "bad-annotation", &bundle, &database);
    job["annotations"] = json!({"version":1,"functions":{"1":{"name":"ghost"}}});
    let (output, events, _) = run_job(&job, &directory, "bad-annotation-host");
    assert!(!output.status.success());
    assert_eq!(events.last().unwrap().stage, Stage::Failed);
    let mut retained = BundleReader::new(fs::File::open(&bundle).unwrap()).unwrap();
    let index: AnalysisIndex = retained.get("index").unwrap();
    assert!(index.functions.iter().any(|f| f.address == selected));
    assert!(index.rendered.is_empty());
}
