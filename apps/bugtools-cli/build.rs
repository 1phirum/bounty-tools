//! Build script: compile the Go recon engine and stage it for embedding.
//!
//! The `dns-go` engine is stdlib-only, so with `CGO_ENABLED=0` it links into a
//! single static executable. We build it here into `OUT_DIR` and hand its path
//! to the crate via a `rustc-env` var, where `src/embed.rs` bakes the bytes in
//! with `include_bytes!`. The result is one self-contained `bugtools` binary
//! that carries its engine and extracts it on demand.
//!
//! Escape hatches:
//!   * `BUGTOOLS_EMBED_DNS_ENGINE=/path/to/prebuilt` — embed that binary as-is
//!     and skip invoking `go` (useful for CI that builds the engine separately,
//!     or cross-builds where the host `go` can't target the Rust triple).
//!   * `BUGTOOLS_SKIP_ENGINE_EMBED=1` — embed an empty placeholder; the CLI
//!     then falls back to a located/--engine binary at runtime. Lets the crate
//!     build with no Go toolchain present.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let staged = out_dir.join("dns_engine.bin");

    // Explicit prebuilt binary wins.
    if let Ok(prebuilt) = env::var("BUGTOOLS_EMBED_DNS_ENGINE") {
        println!("cargo:rerun-if-env-changed=BUGTOOLS_EMBED_DNS_ENGINE");
        let src = PathBuf::from(&prebuilt);
        if !src.is_file() {
            panic!("BUGTOOLS_EMBED_DNS_ENGINE points to a missing file: {prebuilt}");
        }
        std::fs::copy(&src, &staged).expect("copy prebuilt engine into OUT_DIR");
        emit_env(&staged);
        return;
    }

    // Opt out of embedding entirely (build without a Go toolchain).
    if env::var("BUGTOOLS_SKIP_ENGINE_EMBED").is_ok() {
        println!("cargo:rerun-if-env-changed=BUGTOOLS_SKIP_ENGINE_EMBED");
        std::fs::write(&staged, b"").expect("write empty engine placeholder");
        emit_env(&staged);
        return;
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // apps/bugtools-cli -> repo root -> engines/dns-go
    let engine_dir = manifest
        .join("..")
        .join("..")
        .join("engines")
        .join("dns-go");
    let engine_dir = engine_dir
        .canonicalize()
        .unwrap_or(engine_dir);

    rerun_if_changed(&engine_dir);

    // Match the Go build target to the Rust build target so a cross-compile
    // produces a runnable engine.
    let goos = match env::var("CARGO_CFG_TARGET_OS").ok().as_deref() {
        Some("windows") => "windows",
        Some("macos") => "darwin",
        Some("linux") => "linux",
        Some(other) => Box::leak(other.to_string().into_boxed_str()), // best-effort
        None => "",
    };
    let goarch = match env::var("CARGO_CFG_TARGET_ARCH").ok().as_deref() {
        Some("x86_64") => "amd64",
        Some("aarch64") => "arm64",
        Some("arm") => "arm",
        Some("x86") => "386",
        Some(other) => Box::leak(other.to_string().into_boxed_str()),
        None => "",
    };

    let mut cmd = Command::new("go");
    cmd.current_dir(&engine_dir)
        .env("CGO_ENABLED", "0")
        .arg("build")
        .arg("-trimpath")
        .arg("-ldflags")
        .arg("-s -w")
        .arg("-o")
        .arg(&staged)
        .arg("./cmd/dns");
    if !goos.is_empty() {
        cmd.env("GOOS", goos);
    }
    if !goarch.is_empty() {
        cmd.env("GOARCH", goarch);
    }

    let status = cmd.status();
    match status {
        Ok(s) if s.success() => emit_env(&staged),
        Ok(s) => panic!(
            "go build of the dns engine failed with status {s}.\n\
             Build without embedding by setting BUGTOOLS_SKIP_ENGINE_EMBED=1, \
             or point BUGTOOLS_EMBED_DNS_ENGINE at a prebuilt binary."
        ),
        Err(e) => panic!(
            "could not run `go build` for the dns engine: {e}.\n\
             Install Go, or set BUGTOOLS_SKIP_ENGINE_EMBED=1 to build without it, \
             or set BUGTOOLS_EMBED_DNS_ENGINE to a prebuilt engine binary."
        ),
    }
}

fn emit_env(staged: &Path) {
    // Consumed by src/embed.rs via include_bytes!(env!("BUGTOOLS_DNS_ENGINE_BIN")).
    println!(
        "cargo:rustc-env=BUGTOOLS_DNS_ENGINE_BIN={}",
        staged.display()
    );
}

fn rerun_if_changed(dir: &Path) {
    for sub in ["go.mod", "cmd", "internal", "pkg"] {
        let p = dir.join(sub);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
}
