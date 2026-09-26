//! Embedded Go engine payloads and on-demand extraction.
//!
//! `build.rs` compiles the `dns-go` engine and points `BUGTOOLS_DNS_ENGINE_BIN`
//! at the staged binary, which we bake into this crate here. At runtime the
//! bytes are written to a per-content temp file (once) and that path is handed
//! to [`crate::engine_host::run_job`]. This is what makes `bugtools` a single
//! self-contained executable.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

/// The DNS recon engine, baked in at build time. Empty when the crate was
/// built with `BUGTOOLS_SKIP_ENGINE_EMBED=1`.
pub static DNS_ENGINE: &[u8] = include_bytes!(env!("BUGTOOLS_DNS_ENGINE_BIN"));

/// Write the embedded DNS engine to a stable temp path and return it.
///
/// The filename is tagged with the crate version and a content hash, so
/// distinct builds never collide and an already-extracted, byte-identical
/// engine is reused instead of rewritten.
pub fn extract_dns_engine() -> Result<PathBuf> {
    extract("dns", DNS_ENGINE)
}

fn extract(module: &str, bytes: &[u8]) -> Result<PathBuf> {
    if bytes.is_empty() {
        bail!(
            "this build has no embedded '{module}' engine \
             (built with BUGTOOLS_SKIP_ENGINE_EMBED). \
             Pass --engine <path> or set BUGTOOLS_{}_ENGINE.",
            module.to_uppercase()
        );
    }

    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let name = format!(
        "bugtools-{module}-{ver}-{hash:016x}{suffix}",
        ver = env!("CARGO_PKG_VERSION"),
        hash = fnv1a(bytes),
    );
    let dir = std::env::temp_dir().join("bugtools-engines");
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(&name);

    // Reuse a byte-identical extraction; the content hash in the name makes a
    // matching length a safe signal that it is the same engine.
    let fresh = match std::fs::metadata(&path) {
        Ok(m) => m.len() != bytes.len() as u64,
        Err(_) => true,
    };
    if fresh {
        // Write to a sibling temp file, then rename into place so a concurrent
        // invocation never observes a half-written binary.
        let tmp = dir.join(format!("{name}.{}.part", std::process::id()));
        std::fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
        set_executable(&tmp)?;
        // Rename may lose to a racing process that already produced the final
        // file; that's fine — the target is identical by construction.
        if std::fs::rename(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&tmp);
            if !path.exists() {
                bail!("failed to stage engine at {}", path.display());
            }
        }
    }

    Ok(path)
}

#[cfg(unix)]
fn set_executable(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(path)?.permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(path, perm).with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

/// FNV-1a 64-bit — a tiny dependency-free content tag for the temp filename.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
