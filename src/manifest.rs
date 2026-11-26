//! Chunking, hashing, and resume-by-content-verification.
//!
//! Resume deliberately keeps no sidecar bookkeeping file: the receiver hashes
//! whatever bytes it already has and asks only for the chunks whose digests
//! don't match. A partial file is therefore self-describing, and there is no
//! state to get out of sync with the data.

use std::path::Path;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};

use crate::proto::{Manifest, chunk_range};

pub fn chunk_count(file_len: u64, chunk_size: u32) -> u64 {
    if file_len == 0 {
        return 0;
    }
    file_len.div_ceil(chunk_size as u64)
}

/// Read the file once, hashing every chunk and the whole file. This is a local
/// sequential read; the bytes cross the network exactly once.
pub async fn build(path: &Path, file_name: String, chunk_size: u32) -> Result<Manifest> {
    let meta = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("cannot stat {}", path.display()))?;
    if meta.is_dir() {
        bail!("{} is a directory; send a file", path.display());
    }
    let file_len = meta.len();
    let n = chunk_count(file_len, chunk_size);

    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("cannot open {}", path.display()))?;

    let mut hashes = Vec::with_capacity(n as usize);
    let mut whole = Sha256::new();
    let mut buf = vec![0u8; chunk_size as usize];
    let mut remaining = file_len;

    while remaining > 0 {
        let want = remaining.min(chunk_size as u64) as usize;
        file.read_exact(&mut buf[..want])
            .await
            .context("file shrank while hashing")?;
        whole.update(&buf[..want]);
        hashes.push(hex::encode(Sha256::digest(&buf[..want])));
        remaining -= want as u64;
    }

    Ok(Manifest {
        file_name,
        file_len,
        chunk_size,
        chunk_count: n,
        hashes,
        file_sha256: hex::encode(whole.finalize()),
        streams: 0, // filled in by the sender once the receiver's Hello arrives
    })
}

/// Return the chunk indices the local partial file does not already have.
///
/// A chunk counts as present only if its bytes are there *and* they hash to the
/// manifest digest, so a partially written or corrupted chunk is refetched
/// rather than trusted.
pub async fn missing_chunks(part: &Path, m: &Manifest) -> Result<Vec<u64>> {
    if m.chunk_count == 0 {
        return Ok(Vec::new());
    }
    let have_len = match tokio::fs::metadata(part).await {
        Ok(meta) if meta.is_file() => meta.len(),
        _ => return Ok((0..m.chunk_count).collect()),
    };

    let mut file = tokio::fs::File::open(part).await?;
    let mut buf = vec![0u8; m.chunk_size as usize];
    let mut missing = Vec::new();

    for idx in 0..m.chunk_count {
        let (start, len) = chunk_range(idx, m.chunk_size as u64, m.file_len);
        // Not even allocated yet, or truncated: definitely missing.
        if have_len < start + len as u64 {
            missing.push(idx);
            continue;
        }
        file.seek(SeekFrom::Start(start)).await?;
        file.read_exact(&mut buf[..len]).await?;
        if hex::encode(Sha256::digest(&buf[..len])) != m.hashes[idx as usize] {
            missing.push(idx);
        }
    }
    Ok(missing)
}

/// Turn an untrusted filename from the peer into something safe to create
/// locally: no path components, no traversal, no control characters, no
/// Windows reserved device names, bounded length.
pub fn sanitize_file_name(raw: &str) -> String {
    let mut name: String = raw
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();

    // Strip anything that could make the name a path component again.
    while name.starts_with('.') {
        name.remove(0);
    }
    let name = name.trim();
    let mut name = name.trim_end_matches(['.', ' ']).to_string();

    if name.is_empty() {
        name = "file".to_string();
    }

    // Windows reserved device names, checked with the extension removed.
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = name.split('.').next().unwrap_or("");
    if RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
        name = format!("_{name}");
    }

    // Keep the name within one filesystem component on every common platform,
    // without ever splitting a UTF-8 sequence.
    if name.len() > 255 {
        const CAP: usize = 255;
        let dot = name.rfind('.').filter(|&d| d > 0);
        match dot {
            // Preserve the extension when it is short enough to be worth it.
            Some(d) if name.len() - d < 200 => {
                let mut keep = CAP - (name.len() - d);
                while keep > 0 && !name.is_char_boundary(keep) {
                    keep -= 1;
                }
                let ext = name[d..].to_string();
                name.truncate(keep);
                name.push_str(&ext);
            }
            _ => {
                let mut end = CAP;
                while end > 0 && !name.is_char_boundary(end) {
                    end -= 1;
                }
                name.truncate(end);
            }
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::sanitize_file_name;

    #[test]
    fn strips_traversal() {
        let n = sanitize_file_name("../../etc/passwd");
        assert!(!n.contains('/'), "got {n}");
        assert!(!n.starts_with('.'), "got {n}");
        assert_eq!(sanitize_file_name(".."), "file");
        assert_eq!(sanitize_file_name("/abs/path.txt"), "_abs_path.txt");
    }

    #[test]
    fn keeps_ordinary_names() {
        assert_eq!(sanitize_file_name("big.iso"), "big.iso");
        assert_eq!(sanitize_file_name("My Report.pdf"), "My Report.pdf");
    }

    #[test]
    fn handles_reserved_and_control() {
        assert_eq!(sanitize_file_name("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_file_name("a\u{7}b.txt"), "a_b.txt");
    }
}
