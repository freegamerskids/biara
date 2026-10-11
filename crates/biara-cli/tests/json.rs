//! Consumers retain numeric addresses, explicit uncertainty and object evidence.
#![cfg(target_os = "linux")]
use biara_loader::Image;
use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};

#[test]
fn structured_reports_preserve_pointer_bounds_and_unknown_edges() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("json-consumer");
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("program.c");
    let binary = dir.join("program");
    fs::write(
        &source,
        r#"
extern void *malloc(unsigned long);
extern void *memcpy(void *, const void *, unsigned long);
extern void free(void *);
__attribute__((noinline,used)) void oversized(void) {
    char *p=malloc(16);
    memcpy(p+8,"123456789",9);
    __asm__ volatile(""::"r"(p):"memory");
    free(p);
}
__attribute__((noinline,used)) void *allocation_wrapper(void) { return malloc(16); }
__attribute__((noinline,used)) void copy_oversized(void *p) { memcpy(p,"12345678901234567",17); }
__attribute__((noinline,used)) void copy_bounded(void *p) { memcpy(p,"abc",3); }
static void (*const writers[])(void *)={copy_oversized,copy_bounded};
__attribute__((noinline,used)) void through_table(unsigned i) {
    void *p=allocation_wrapper();
    writers[i&1](p);
}
__attribute__((noinline,used)) long open_callback(long (*callback)(long)) { return callback(1)+2; }
__attribute__((noinline,used)) void set_field8(void *p) {
    *(volatile unsigned *)(p+8)=3;
}
__attribute__((noinline,used)) unsigned long get_field16(void *p) {
    return *(volatile unsigned long *)(p+16);
}
__attribute__((noinline,used)) unsigned long use_both(void *p) {
    set_field8(p);
    return get_field16(p);
}
int main(void) {
    unsigned long object[4]={0,0,5,0};
    return use_both(object)!=5 || *(unsigned *)((char *)object+8)!=3;
}
"#,
    )
    .unwrap();
    let compiled = Command::new(env!("BIARA_CLANG"))
        .args([
            "-O0",
            "-g",
            "-fno-builtin",
            "-fno-pie",
            "-no-pie",
            "-fuse-ld=bfd",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(Command::new(&binary).status().unwrap().success());
    let image = Image::load(&binary).unwrap();
    let oversized = image.symbol("oversized").unwrap().addr;
    let open = image.symbol("open_callback").unwrap().addr;
    let report = |mode: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_biara"))
            .arg("lift")
            .arg(&binary)
            .args(["--emit", mode, "--format", "json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let cfg = report("cfg");
    let function = cfg["analysis"]["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["address"].as_u64() == Some(open))
        .unwrap();
    let blocks = function["blocks"].as_array().unwrap();
    assert!(
        cfg["completeness"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["kind"] == "unknown_indirect_call" && blocks.contains(&i["address"]))
    );
    let calls = report("calls");
    let copy = calls["analysis"]["calls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["caller"].as_u64() == Some(oversized)
                && c["callee"]["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with("memcpy"))
        })
        .unwrap();
    let object = &copy["arguments"][0]["object_alternatives"][0];
    assert_eq!(object["origin"]["kind"], "allocation_site");
    assert_eq!(object["offset"], 8);
    assert_eq!(object["size"], serde_json::json!({"lo":16,"hi":16}));
    assert_eq!(object["nullable"], true);
    assert!(
        object["evidence"].as_array().unwrap().iter().any(
            |e| e["kind"] == "allocator_arguments" && e["function"].as_u64() == Some(oversized)
        )
    );
    let audit = report("audit");
    let overflow = audit["analysis"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| {
            f["site"]["caller"].as_u64() == Some(oversized)
                && f["issue"]["kind"] == "object_overflow"
        })
        .unwrap();
    assert_eq!(
        overflow["issue"]["length"],
        serde_json::json!({"lo":9,"hi":9})
    );
    assert_eq!(overflow["issue"]["object"]["offset"], 8);
    assert_eq!(
        overflow["issue"]["object"]["size"],
        serde_json::json!({"lo":16,"hi":16})
    );
    let copy_wrapper = image.symbol("copy_oversized").unwrap().addr;
    let dispatcher = image.symbol("through_table").unwrap().addr;
    let indirect = audit["analysis"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| {
            f["site"]["caller"].as_u64() == Some(copy_wrapper)
                && f["issue"]["kind"] == "object_overflow"
        })
        .unwrap();
    assert_eq!(
        indirect["issue"]["object"]["size"],
        serde_json::json!({"lo":16,"hi":16})
    );
    assert_eq!(
        indirect["issue"]["length"],
        serde_json::json!({"lo":17,"hi":17})
    );
    assert!(
        indirect["path"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["caller"].as_u64() == Some(dispatcher)),
        "indirect callees outside the caller batch retain argument provenance"
    );
    let abi = report("abi");
    let function = abi["analysis"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["address"].as_u64() == Some(open))
        .unwrap();
    assert!(
        function["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == if image.arch == "aarch64" { "x0" } else { "rdi" })
    );
    let types = report("types");
    let use_both = image.symbol("use_both").unwrap().addr;
    let binding = types["analysis"]["layouts"]["args"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["function"].as_u64() == Some(use_both) && a["arg"] == 0)
        .unwrap();
    let layout_id = binding["layout"].as_u64().unwrap();
    let layout = types["analysis"]["layouts"]["layouts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"].as_u64() == Some(layout_id))
        .unwrap();
    let fields = layout["fields"].as_array().unwrap();
    assert!(fields.iter().any(|f| f["off"] == 8 && f["bytes"] == 4));
    assert!(fields.iter().any(|f| f["off"] == 16 && f["bytes"] == 8));
    let signature = types["analysis"]["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["function"].as_u64() == Some(use_both))
        .unwrap();
    assert_eq!(
        signature["params"][0],
        serde_json::json!({"Ptr":{"layout":layout_id}})
    );
    // The layout's accessed extent is 24; it must not replace the malloc
    // extent in the independent object-bound/audit records above.
    assert_eq!(layout["size"], 24);
    let failed = Command::new(env!("CARGO_BIN_EXE_biara"))
        .arg("lift")
        .arg(&binary)
        .args(["--emit", "cfg", "--format", "json", "-o", "/dev/full"])
        .output()
        .unwrap();
    assert!(
        !failed.status.success(),
        "buffered JSON sink failure must escape the command"
    );
    let rejected = Command::new(env!("CARGO_BIN_EXE_biara"))
        .arg("lift")
        .arg(&binary)
        .args(["--emit", "llvm", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "raw LLVM is not a structured analysis report"
    );
}
