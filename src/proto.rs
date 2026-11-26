//! Wire protocol: length-prefixed JSON control messages, framed chunk records on
//! data streams. Everything is explicitly big-endian and self-describing so the
//! two ends never have to agree on anything the manifest doesn't carry.

use anyhow::{Result, bail};
use quinn::{ReadExactError, RecvStream, SendStream};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const ALPN: &[u8] = b"fx/1";
pub const PROTO_VERSION: u32 = 1;
pub const DEFAULT_CHUNK: u32 = 4 * 1024 * 1024;
pub const DEFAULT_STREAMS: u32 = 8;

/// Cap on a single control message. The largest is the manifest, which costs
/// ~65 bytes of hex hash per chunk; 64 MiB covers ~1M chunks (4 PiB at 4 MiB).
const MAX_CONTROL_MSG: usize = 64 * 1024 * 1024;

/// Cap on a single chunk header. The body is bounded by the chunk size the
/// manifest declares, which both ends already agreed on.
const MAX_CHUNK_HEADER: usize = 4 * 1024;

#[derive(Serialize, Deserialize, Debug)]
pub struct Hello {
    pub version: u32,
    /// Shared secret handed to the receiver out of band. Only the intended
    /// receiver was given the sender's command line, so this authenticates the
    /// receiver to the sender without a PKI.
    pub token: String,
    /// How many unidirectional data streams the receiver will accept.
    pub streams: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Manifest {
    pub file_name: String,
    pub file_len: u64,
    pub chunk_size: u32,
    pub chunk_count: u64,
    /// SHA-256 of each chunk, hex encoded, in index order.
    pub hashes: Vec<String>,
    /// SHA-256 of the whole file, so the user can cross-check with `shasum`.
    pub file_sha256: String,
    /// Number of unidirectional streams the sender will open for data.
    pub streams: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Want {
    pub chunks: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Done {
    pub ok: bool,
    pub received: u64,
    pub bytes: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Bye {
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChunkHeader {
    pub index: u64,
    pub len: u32,
}

/// How many data streams both ends open for a given `want`.
///
/// `a` and `b` are the two ends' independent caps; taking the minimum means
/// neither side can be made to open more streams than it said it would accept.
pub fn stream_count(want_len: usize, a: u32, b: u32) -> u32 {
    if want_len == 0 {
        return 0;
    }
    (want_len as u32).min(a).min(b).max(1)
}

/// Byte range covered by chunk `idx`.
pub fn chunk_range(idx: u64, chunk_size: u64, file_len: u64) -> (u64, usize) {
    let start = idx * chunk_size;
    let end = (start + chunk_size).min(file_len);
    (start, (end - start) as usize)
}

pub async fn write_msg<T: Serialize>(w: &mut SendStream, msg: &T) -> Result<()> {
    let body = serde_json::to_vec(msg)?;
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    Ok(())
}

/// Read one control message. `Ok(None)` means the peer finished the stream
/// cleanly at a record boundary rather than sending a message.
pub async fn read_msg<T: DeserializeOwned>(r: &mut RecvStream) -> Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(()) => {}
        Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(ReadExactError::FinishedEarly(n)) => bail!("control stream truncated after {n} bytes"),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_CONTROL_MSG {
        bail!("control message of {len} bytes exceeds the {MAX_CONTROL_MSG} byte limit");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(serde_json::from_slice(&body)?))
}

/// Read the next chunk record header. `Ok(None)` means the sender finished the
/// data stream cleanly.
pub async fn read_chunk_header(r: &mut RecvStream) -> Result<Option<ChunkHeader>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(()) => {}
        Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(ReadExactError::FinishedEarly(n)) => bail!("data stream truncated after {n} bytes"),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_CHUNK_HEADER {
        bail!("chunk header of {len} bytes exceeds the {MAX_CHUNK_HEADER} byte limit");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(serde_json::from_slice(&body)?))
}
