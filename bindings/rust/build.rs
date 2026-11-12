use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("bindings/rust -> repo root");
    let libdir = root.join("build/lib");
    let inc = root.join("include");
    let src_inc = root.join("src");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-lib=dylib=dislmdb");
    println!("cargo:rustc-link-lib=dylib=z");
    println!("cargo:rustc-link-lib=dylib=pthread");
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", libdir.display());
    } else {
        println!("cargo:rustc-link-lib=dylib=crypto");
        println!("cargo:rustc-link-lib=dylib=uuid");
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", libdir.display());
    }
    println!("cargo:rerun-if-changed={}", inc.join("dislmdb.h").display());
    println!("cargo:rerun-if-changed={}", libdir.join("libdislmdb.dylib").display());
    println!("cargo:rerun-if-changed={}", libdir.join("libdislmdb.so").display());

    // Probe DISLMDB_env_config layout so open() can patch solo defaults / ACL.
    let probe_c = out.join("offset_probe.c");
    let probe_bin = out.join("offset_probe");
    fs::write(
        &probe_c,
        r#"
#include <stddef.h>
#include <stdio.h>
#include "dislmdb.h"
int main(void) {
    printf("pub const ENV_CONFIG_SIZE: usize = %zu;\n", sizeof(DISLMDB_env_config));
    printf("pub const OFFSETOF_MAXDBS: usize = %zu;\n",
           offsetof(DISLMDB_env_config, maxdbs));
    printf("pub const OFFSETOF_ENABLE_ACL: usize = %zu;\n",
           offsetof(DISLMDB_env_config, enable_acl));
    printf("pub const OFFSETOF_LOCAL_PORT: usize = %zu;\n",
           offsetof(DISLMDB_env_config, network.local_port));
    printf("pub const OFFSETOF_CONSENSUS_MECH: usize = %zu;\n",
           offsetof(DISLMDB_env_config, consensus.mechanism));
    printf("pub const CONSENSUS_SOLO: u32 = %u;\n",
           (unsigned)DISLMDB_CONSENSUS_SOLO);
    return 0;
}
"#,
    )
    .expect("write offset probe");

    let status = Command::new("cc")
        .arg(format!("-I{}", inc.display()))
        .arg(format!("-I{}", src_inc.display()))
        .arg("-o")
        .arg(&probe_bin)
        .arg(&probe_c)
        .status()
        .expect("spawn cc for offset probe");
    assert!(status.success(), "offset probe compile failed");

    let output = Command::new(&probe_bin)
        .output()
        .expect("run offset probe");
    assert!(output.status.success(), "offset probe failed");
    fs::write(out.join("offsets.rs"), &output.stdout).expect("write offsets.rs");
}
