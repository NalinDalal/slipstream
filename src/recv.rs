//! Receiver: connects, proves the sender is who they claim to be by comparing
//! the short authentication string, then fetches only the chunks its existing
//! copy is missing.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;

use crate::{manifest, progress, proto, sas, tls};

pub struct RecvOpts {
    pub endpoint: String,
    pub code: String,
    pub token: String,
    pub out: PathBuf,
    pub streams: u32,
    pub timeout: Duration,
}

/// Resolve whatever the sender printed — a single `host:port`, a
/// comma-separated list of candidates, or a name that answers with several
/// addresses — into the set of places worth racing.
async fn resolve_candidates(spec: &str) -> Result<Vec<SocketAddr>> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut problems: Vec<String> = Vec::new();

    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match tokio::net::lookup_host(part).await {
            Ok(addrs) => {
                for addr in addrs {
                    if !out.contains(&addr) {
                        out.push(addr);
                    }
                }
            }
            Err(e) => problems.push(format!("{part}: {e}")),
        }
    }

    if out.is_empty() {
        let detail = if problems.is_empty() {
            String::new()
        } else {
            format!("\n  {}", problems.join("\n  "))
        };
        bail!("no usable address in `{spec}`{detail}");
    }
    Ok(out)
}

/// Bind a socket that can reach both families when the host has IPv6, so a
/// candidate list mixing `1.2.3.4` and `2a00::1` is dialable either way.
fn bind_any() -> Result<std::net::UdpSocket> {
    match std::net::UdpSocket::bind("[::]:0") {
        Ok(s) => Ok(s),
        Err(e) => {
            eprintln!("note: cannot bind [::]:0 ({e}); falling back to IPv4 only");
            std::net::UdpSocket::bind("0.0.0.0:0").context("cannot bind a UDP socket")
        }
    }
}

/// Try every candidate at once and keep the first handshake that completes.
///
/// Racing rather than trying in order means an address that does not route
/// costs nothing instead of a timeout: the working path simply answers first.
/// Losers close their own connection, so nothing is left half-open.
async fn dial(
    endpoint: &quinn::Endpoint,
    addrs: Vec<SocketAddr>,
    timeout: Duration,
) -> Result<quinn::Connection> {
    let (winner_tx, winner_rx) = tokio::sync::oneshot::channel();
    // `oneshot::Sender` is not `Clone`, so each task shares one slot and only
    // the task that wins the compare-exchange takes it.
    let winner_slot = Arc::new(std::sync::Mutex::new(Some(winner_tx)));
    let won = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let errors = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let tried = addrs.len();

    for addr in addrs {
        let endpoint = endpoint.clone();
        let winner_slot = winner_slot.clone();
        let won = won.clone();
        let errors = errors.clone();
        tokio::spawn(async move {
            let outcome = async {
                let conn = endpoint
                    .connect(addr, "fx")
                    .with_context(|| format!("{addr}"))?
                    .await
                    .with_context(|| format!("handshake with {addr} failed"))?;
                Ok::<quinn::Connection, anyhow::Error>(conn)
            }
            .await;

            match outcome {
                Ok(conn) => {
                    let first = won
                        .compare_exchange(
                            false,
                            true,
                            std::sync::atomic::Ordering::SeqCst,
                            std::sync::atomic::Ordering::SeqCst,
                        )
                        .is_ok();
                    if first {
                        let taken = winner_slot.lock().unwrap().take();
                        if let Some(tx) = taken
                            && let Err(conn) = tx.send(conn)
                        {
                            conn.close(quinn::VarInt::from_u32(0), b"superseded");
                        }
                    } else {
                        // Another address already won; release this one so the
                        // sender does not wait for an idle timeout on it.
                        conn.close(quinn::VarInt::from_u32(0), b"another address worked");
                    }
                }
                Err(e) => errors.lock().unwrap().push(format!("{e:#}")),
            }
        });
    }

    let outcome = tokio::time::timeout(timeout, winner_rx).await;
    match outcome {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(_)) | Err(_) => {
            let detail = {
                let errs = errors.lock().unwrap();
                if errs.is_empty() {
                    format!("timed out after {}s", timeout.as_secs())
                } else {
                    errs.join("\n  ")
                }
            };
            bail!("could not reach the sender on any of its {tried} address(es):\n  {detail}")
        }
    }
}

pub async fn run(opts: RecvOpts) -> Result<()> {
    tls::init_crypto_provider();
    if opts.streams == 0 {
        bail!("--streams must be greater than zero");
    }

    let addrs = resolve_candidates(&opts.endpoint).await?;

    let sock = bind_any()?;
    sock.set_nonblocking(true)?;
    let runtime = Arc::new(quinn::TokioRuntime);
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        sock,
        runtime,
    )?;
    endpoint.set_default_client_config(tls::client_config()?);

    let conn = dial(&endpoint, addrs, opts.timeout).await?;
    eprintln!("connected to {}", conn.remote_address());

    // Identity first, data second: nothing is requested until the sender's
    // certificate has been shown to hash to the code we were given.
    verify_sender(&conn, &opts.code)?;

    let outcome = transfer(&conn, &opts).await;
    match &outcome {
        Ok(()) => conn.close(quinn::VarInt::from_u32(0), b"done"),
        Err(e) => conn.close(quinn::VarInt::from_u32(1), format!("{e:#}").as_bytes()),
    }
    // Sweep the candidates that lost the race, if any are still closing.
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    tokio::time::timeout(Duration::from_secs(5), endpoint.wait_idle())
        .await
        .ok();
    outcome
}

fn verify_sender(conn: &quinn::Connection, expected: &str) -> Result<()> {
    let identity = conn
        .peer_identity()
        .context("sender presented no certificate")?;
    let certs = identity
        .downcast_ref::<Vec<quinn::rustls::pki_types::CertificateDer<'static>>>()
        .context("unexpected peer identity type")?;
    let cert = certs.first().context("sender certificate chain is empty")?;

    let actual = sas::code_for(cert.as_ref());
    if !sas::matches(expected, &actual) {
        bail!(
            "verify code mismatch\n  you expected   {}\n  sender sent   {}\n\
             aborting before a single byte is requested — assume this connection is intercepted",
            sas::normalise(expected),
            actual
        );
    }
    eprintln!("sender verified: code {actual} matches");
    Ok(())
}

async fn transfer(conn: &quinn::Connection, opts: &RecvOpts) -> Result<()> {
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;
    proto::write_msg(
        &mut ctrl_send,
        &proto::Hello {
            version: proto::PROTO_VERSION,
            token: opts.token.clone(),
            streams: opts.streams,
        },
    )
    .await?;

    let mut m: proto::Manifest = proto::read_msg(&mut ctrl_recv)
        .await?
        .context("sender sent no manifest")?;
    validate_manifest(&m)?;

    let name = manifest::sanitize_file_name(&m.file_name);
    tokio::fs::create_dir_all(&opts.out)
        .await
        .with_context(|| format!("cannot create {}", opts.out.display()))?;
    let part = opts.out.join(format!(".{name}.fxpart"));
    let final_path = opts.out.join(&name);

    // Resume without bookkeeping: hash what is already on disk and ask only
    // for the chunks that do not match.
    let missing = manifest::missing_chunks(&part, &m).await?;
    let missing_count = missing.len();
    let chunk_size = m.chunk_size as u64;
    let total: u64 = missing
        .iter()
        .map(|&i| proto::chunk_range(i, chunk_size, m.file_len).1 as u64)
        .sum();

    if missing_count == 0 {
        eprintln!("nothing to transfer: {} is already complete", name);
    } else {
        eprintln!(
            "transferring {name}: {} of {} chunks missing ({})",
            missing_count,
            m.chunk_count,
            progress::human(total)
        );
    }

    let file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // Never truncate: the bytes already here are the resume state.
        .truncate(false)
        .open(&part)
        .await
        .with_context(|| format!("cannot open {}", part.display()))?;
    file.set_len(m.file_len).await?;
    let file = Arc::new(Mutex::new(file));

    proto::write_msg(&mut ctrl_send, &proto::Want { chunks: missing }).await?;

    let streams = proto::stream_count(missing_count, opts.streams, m.streams);
    let received = Arc::new(AtomicU64::new(0));
    let progress = (total > 0).then(|| progress::spawn(format!("receiving {name}"), total, received.clone()));

    let hashes = Arc::new(std::mem::take(&mut m.hashes));
    let file_len = m.file_len;
    let (tx, mut rx) = mpsc::channel::<Result<()>>(256);
    let mut set: JoinSet<Result<()>> = JoinSet::new();

    for _ in 0..streams {
        let conn = conn.clone();
        let file = file.clone();
        let hashes = hashes.clone();
        let tx = tx.clone();
        let received = received.clone();

        set.spawn(async move {
            let outcome: Result<()> = async {
                let mut stream = conn.accept_uni().await?;
                let mut buf: Vec<u8> = Vec::new();
                while let Some(header) = proto::read_chunk_header(&mut stream).await? {
                    let idx = header.index;
                    let (start, expected_len) = proto::chunk_range(idx, chunk_size, file_len);
                    if header.len as usize != expected_len {
                        bail!(
                            "chunk {idx} declared {} bytes, manifest says {expected_len}",
                            header.len
                        );
                    }
                    let expected = hashes
                        .get(idx as usize)
                        .with_context(|| format!("chunk {idx} is not in the manifest"))?;

                    buf.resize(expected_len, 0);
                    stream.read_exact(&mut buf).await?;

                    // Verify before writing: corrupt data never reaches the file.
                    if hex::encode(Sha256::digest(&buf)) != *expected {
                        bail!("chunk {idx} failed its digest check");
                    }
                    {
                        let mut f = file.lock().await;
                        f.seek(SeekFrom::Start(start)).await?;
                        f.write_all(&buf).await?;
                    }
                    received.fetch_add(expected_len as u64, Ordering::Relaxed);
                    if tx.send(Ok(())).await.is_err() {
                        break;
                    }
                }
                Ok(())
            }
            .await;

            // Surface the reason over the channel: the collector below only
            // watches for completions, and a silently dropped stream would
            // otherwise look like a plain shortfall.
            if let Err(e) = &outcome {
                let _ = tx.send(Err(anyhow::anyhow!("{e:#}"))).await;
            }
            outcome
        });
    }
    drop(tx);

    let mut got = 0usize;
    let mut failure: Option<anyhow::Error> = None;
    while got < missing_count {
        match rx.recv().await {
            Some(Ok(())) => got += 1,
            Some(Err(e)) => {
                failure = Some(e);
                break;
            }
            None => break,
        }
    }
    set.abort_all();
    drop(set);

    if let Some(e) = failure {
        bail!("{e:#}");
    }
    if got != missing_count {
        bail!("transfer incomplete: received {got} of {missing_count} chunks");
    }

    if let Some(handle) = progress {
        handle.await.ok();
    }

    // Flush and sync before the rename, so a crash cannot leave a truncated
    // file with a completed-looking name.
    {
        let mut f = file.lock().await;
        f.flush().await?;
        f.sync_all()
            .await
            .context("could not flush the received file to disk")?;
    }
    drop(file);

    tokio::fs::rename(&part, &final_path)
        .await
        .with_context(|| format!("cannot finalise {}", final_path.display()))?;

    proto::write_msg(
        &mut ctrl_send,
        &proto::Done {
            ok: true,
            received: got as u64,
            bytes: total,
        },
    )
    .await?;
    match proto::read_msg::<proto::Bye>(&mut ctrl_recv).await? {
        Some(bye) if !bye.ok => bail!(
            "sender reported failure: {}",
            bye.error.unwrap_or_else(|| "unknown".into())
        ),
        _ => {}
    }

    eprintln!("saved {}", final_path.display());
    eprintln!("  size    {}", progress::human(m.file_len));
    eprintln!("  sha256  {}", m.file_sha256);
    Ok(())
}

fn validate_manifest(m: &proto::Manifest) -> Result<()> {
    if m.chunk_size == 0 {
        bail!("sender declared a zero chunk size");
    }
    let expected = manifest::chunk_count(m.file_len, m.chunk_size);
    if m.chunk_count != expected {
        bail!(
            "manifest declares {} chunks but the file size implies {expected}",
            m.chunk_count
        );
    }
    if m.hashes.len() as u64 != m.chunk_count {
        let declared = m.chunk_count;
        bail!(
            "manifest carries {} digests for {declared} chunks",
            m.hashes.len()
        );
    }
    if m.file_name.is_empty() {
        bail!("sender did not name the file");
    }
    if m.file_len > 0 && m.streams == 0 {
        bail!("sender did not agree on any data streams");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepts_a_comma_separated_candidate_list() {
        let addrs = resolve_candidates("127.0.0.1:1234,127.0.0.1:1234,[::1]:1234")
            .await
            .expect("three valid candidates");
        assert_eq!(addrs.len(), 2, "duplicates must collapse: {addrs:?}");
        assert!(addrs.iter().all(|a| a.port() == 1234));
    }

    #[tokio::test]
    async fn accepts_a_single_endpoint() {
        let addrs = resolve_candidates("127.0.0.1:9999").await.expect("one candidate");
        assert_eq!(addrs.len(), 1);
    }

    #[tokio::test]
    async fn rejects_a_list_with_nothing_usable() {
        for spec in ["", "   ", ",,,", "127.0.0.1:notaport"] {
            assert!(
                resolve_candidates(spec).await.is_err(),
                "`{spec}` should not resolve to anything"
            );
        }
    }
}
