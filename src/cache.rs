//! Manifest cache.
//!
//! Hashing a file is a full sequential read of it. For a multi-gigabyte file
//! that is the dominant cost of starting a transfer, and it buys nothing when
//! the file has not changed since last time. The cache keys an entry on
//! everything that would change the digests — canonical path, size, mtime and
//! chunk size — so a stale entry is structurally impossible to hit rather than
//! something we have to detect after the fact.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::proto::Manifest;

/// Bounded so a machine that sends many large files does not accumulate
/// unbounded digests. Oldest entries are dropped first.
const MAX_ENTRIES: usize = 128;

/// Resolve the cache directory. `FX_CACHE_DIR` overrides everything so tests
/// (and anyone with a read-only home) can redirect or disable it.
pub fn dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("FX_CACHE_DIR") {
        return if dir.is_empty() { None } else { Some(PathBuf::from(dir)) };
    }
    #[cfg(target_os = "macos")]
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home).join("Library/Caches/fx"));
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME")
        && !xdg.is_empty()
    {
        return Some(PathBuf::from(xdg).join("fx"));
    }
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".cache/fx"))
}

/// Identity of the content a manifest describes. Any change to the file, or to
/// how it would be chunked, changes this.
pub fn key(path: &Path, file_len: u64, mtime_ns: u64, chunk_size: u32) -> String {
    let mut h = Sha256::new();
    h.update(b"fx-manifest-v1\0");
    h.update(path.to_string_lossy().as_bytes());
    h.update(0u8.to_be_bytes());
    h.update(file_len.to_be_bytes());
    h.update(mtime_ns.to_be_bytes());
    h.update(chunk_size.to_be_bytes());
    hex::encode(h.finalize())
}

/// Modification time as nanoseconds since the epoch, folded to 0 if unknown.
pub fn mtime_ns(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

pub async fn load(dir: &Path, key: &str, file_len: u64, chunk_size: u32) -> Option<Manifest> {
    let path = dir.join(format!("{key}.json"));
    let bytes = tokio::fs::read(&path).await.ok()?;
    let m: Manifest = serde_json::from_slice(&bytes).ok()?;

    // Belt and braces: the key already encodes these, but a corrupt or
    // hand-edited file must not be able to cause a wrong transfer.
    if m.file_len != file_len
        || m.chunk_size != chunk_size
        || m.hashes.len() as u64 != m.chunk_count
        || m.chunk_count != crate::manifest::chunk_count(file_len, chunk_size)
    {
        return None;
    }
    Some(m)
}

pub async fn store(dir: &Path, key: &str, m: &Manifest) -> Result<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("cannot create cache dir {}", dir.display()))?;

    let body = serde_json::to_vec(m)?;
    let final_path = dir.join(format!("{key}.json"));
    let tmp_path = dir.join(format!("{key}.json.tmp"));

    // Write-then-rename so an interrupted store can never leave a half-read
    // manifest where a complete one is expected.
    {
        let mut f = tokio::fs::File::create(&tmp_path).await?;
        f.write_all(&body).await?;
        f.flush().await?;
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e).with_context(|| format!("cannot write {}", final_path.display()));
    }

    prune(dir).await;
    Ok(())
}

async fn prune(dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    let mut files = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".json") {
            continue;
        }
        let Ok(meta) = entry.metadata().await else { continue };
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        files.push((modified, entry.path()));
    }
    if files.len() <= MAX_ENTRIES {
        return;
    }
    files.sort(); // oldest first
    let excess = files.len().saturating_sub(MAX_ENTRIES);
    for (_, path) in files.into_iter().take(excess) {
        let _ = tokio::fs::remove_file(path).await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn key_tracks_every_input() {
        let p = Path::new("/a/b.bin");
        let base = key(p, 100, 1, 4096);
        assert_eq!(base, key(p, 100, 1, 4096), "must be stable");
        assert_ne!(base, key(Path::new("/a/c.bin"), 100, 1, 4096), "path");
        assert_ne!(base, key(p, 101, 1, 4096), "size");
        assert_ne!(base, key(p, 100, 2, 4096), "mtime");
        assert_ne!(base, key(p, 100, 1, 8192), "chunk size");
    }

    #[test]
    fn mtime_is_never_zero_for_a_real_file() {
        let meta = std::fs::metadata("Cargo.toml").expect("Cargo.toml exists");
        assert!(mtime_ns(&meta) > 0);
        assert!(SystemTime::now().duration_since(UNIX_EPOCH).is_ok());
    }
}
