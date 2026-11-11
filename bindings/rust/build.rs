fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("bindings/rust -> repo root");
    let libdir = root.join("build/lib");
    let inc = root.join("include");

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
}
