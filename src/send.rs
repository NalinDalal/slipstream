//! Sender: binds a UDP socket, learns its public address with STUN, hashes the
//! file into a chunk manifest while waiting, then serves exactly one receiver.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::task::{JoinHandle, JoinSet};

use crate::{cache, manifest, progress, proto, stun, tls};

pub struct SendOpts {
    pub file: PathBuf,
    /// `None` means "pick one": dual-stack `[::]:0` when the OS has IPv6,
    /// plain IPv4 otherwise.
    pub bind: Option<SocketAddr>,
    pub stun: String,
    pub no_stun: bool,
    pub chunk_size: u32,
    pub streams: u32,
    pub token: Option<String>,
}

pub async fn run(opts: SendOpts) -> Result<()> {
    tls::init_crypto_provider();

    let display_path = opts.file.clone();
    let path = tokio::fs::canonicalize(&opts.file)
        .await
        .with_context(|| format!("cannot open {}", opts.file.display()))?;

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("file has no usable UTF-8 name")?
        .to_string();

    let meta = tokio::fs::metadata(&path).await?;
    if meta.is_dir() {
        bail!("{} is a directory; fx sends files, not directories", path.display());
    }
    if opts.chunk_size == 0 {
        bail!("--chunk must be greater than zero");
    }
    if opts.streams == 0 {
        bail!("--streams must be greater than zero");
    }

    // Bind before anything else so the port is known and STUN runs against the
    // very socket QUIC will use, keeping the NAT mapping intact.
    let sock = bind_socket(opts.bind)?;
    sock.set_nonblocking(true)?;

    // Every address a receiver might reach us on, most useful first. The
    // receiver races them, so an address that does not route costs nothing.
    let candidates = gather_candidates(&sock, &opts.stun, opts.no_stun).await;

    let id = tls::generate_identity()?;
    let token = opts
        .token
        .clone()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(random_token);

    // Hash the file in the background: by the time a receiver arrives the
    // manifest is usually ready, so the first byte is not delayed by a full
    // read of the file. A cached manifest for unchanged content skips the
    // read entirely.
    let chunk_size = opts.chunk_size;
    let man_path = path.clone();
    let man_name = file_name.clone();
    let man_streams = opts.streams;
    let man_file_len = meta.len();
    let man_mtime = cache::mtime_ns(&meta);
    let man_key = cache::key(&man_path, man_file_len, man_mtime, chunk_size);
    let man_task: JoinHandle<Result<proto::Manifest>> = tokio::spawn(async move {
        if let Some(dir) = cache::dir()
            && let Some(mut m) = cache::load(&dir, &man_key, man_file_len, chunk_size).await
        {
            eprintln!("manifest cache hit: {} already hashed", man_name);
            m.streams = man_streams;
            return Ok(m);
        }

        let mut m = manifest::build(&man_path, man_name.clone(), chunk_size).await?;
        m.streams = man_streams;

        if let Some(dir) = cache::dir()
            && let Err(e) = cache::store(&dir, &man_key, &m).await
        {
            // A cache failure is never fatal: the manifest is already built.
            eprintln!("warning: could not cache manifest: {e:#}");
        }
        Ok(m)
    });

    print_invite(&display_path, meta.len(), &id.code, &token, &candidates);

    let runtime = Arc::new(quinn::TokioRuntime);
    let server_cfg = tls::server_config(&id)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_cfg),
        sock,
        runtime,
    )?;

    // Serve the first receiver that both completes the handshake and presents a
    // valid Hello. A candidate that never delivers a packet, a half-open
    // handshake, or a scanner that connects and then says nothing must not be
    // able to wedge the sender: every connection gets its own task and a
    // deadline, and the winner is the first one to speak.
    let (conn, hello, mut ctrl_send, mut ctrl_recv) = await_hello(&endpoint, &token).await?;
    eprintln!("receiver connected from {}", conn.remote_address());

    let served = serve(
        &conn,
        &path,
        man_task,
        opts.streams,
        hello,
        &mut ctrl_send,
        &mut ctrl_recv,
    )
    .await;
    match &served {
        Ok(()) => {
            conn.close(quinn::VarInt::from_u32(0), b"done");
        }
        Err(e) => {
            conn.close(quinn::VarInt::from_u32(1), format!("{e:#}").as_bytes());
        }
    }
    // Sweep any connection that raced and lost, then wait for the close to go
    // out. Bounded: a peer that vanished must not delay the exit.
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    tokio::time::timeout(Duration::from_secs(5), endpoint.wait_idle())
        .await
        .ok();
    served
}

async fn serve(
    conn: &quinn::Connection,
    path: &Path,
    man_task: JoinHandle<Result<proto::Manifest>>,
    sender_streams: u32,
    hello: proto::Hello,
    ctrl_send: &mut quinn::SendStream,
    ctrl_recv: &mut quinn::RecvStream,
) -> Result<()> {

    let mut m = man_task.await??;
    m.streams = sender_streams;
    proto::write_msg(ctrl_send, &m).await?;

    let want: proto::Want = proto::read_msg(ctrl_recv)
        .await?
        .context("receiver sent no chunk list")?;
    validate_want(&want, &m)?;

    let chunk_size = m.chunk_size as u64;
    let total: u64 = want
        .chunks
        .iter()
        .map(|&i| proto::chunk_range(i, chunk_size, m.file_len).1 as u64)
        .sum();

    let streams = proto::stream_count(want.chunks.len(), hello.streams, m.streams);
    let sent = Arc::new(AtomicU64::new(0));
    let progress = (total > 0).then(|| {
        progress::spawn(format!("sending {}", m.file_name), total, sent.clone())
    });

    // Each stream task opens its own file description. `try_clone()` would
    // `dup()` the descriptor, which shares a single seek offset across tasks
    // and lets one task's seek land under another's read.
    let base_path = path.to_path_buf();
    let wanted = Arc::new(want.chunks);
    let cursor = Arc::new(AtomicUsize::new(0));

    let mut set: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..streams {
        let conn = conn.clone();
        let wanted = wanted.clone();
        let cursor = cursor.clone();
        let sent = sent.clone();
        let base_path = base_path.clone();
        let file_len = m.file_len;

        set.spawn(async move {
            let mut file =
                tokio::fs::File::from_std(std::fs::File::open(&base_path).map_err(|e| {
                    anyhow::anyhow!("cannot open {} for reading: {e}", base_path.display())
                })?);
            let mut out = conn.open_uni().await?;
            let mut buf: Vec<u8> = Vec::new();
            loop {
                let i = cursor.fetch_add(1, Ordering::Relaxed);
                if i >= wanted.len() {
                    break;
                }
                let idx = wanted[i];
                let (start, len) = proto::chunk_range(idx, chunk_size, file_len);
                file.seek(SeekFrom::Start(start)).await?;
                buf.resize(len, 0);
                file.read_exact(&mut buf).await?;

                let header = serde_json::to_vec(&proto::ChunkHeader {
                    index: idx,
                    len: len as u32,
                })?;
                out.write_all(&(header.len() as u32).to_be_bytes()).await?;
                out.write_all(&header).await?;
                out.write_all(&buf).await?;
                sent.fetch_add(len as u64, Ordering::Relaxed);
            }
            out.finish()?;
            Ok(())
        });
    }

    for task_result in set.join_all().await {
        task_result?;
    }
    if let Some(handle) = progress {
        handle.await.ok();
    }

    let done: proto::Done = proto::read_msg(ctrl_recv)
        .await?
        .context("receiver sent no result")?;
    if !done.ok {
        bail!("receiver reported a failed transfer");
    }

    proto::write_msg(
        ctrl_send,
        &proto::Bye {
            ok: true,
            error: None,
        },
    )
    .await?;
    let _ = ctrl_send.finish();

    eprintln!(
        "received confirmation: {} across {} chunks",
        progress::human(done.bytes),
        done.received
    );
    eprintln!("  sha256   {}", m.file_sha256);
    Ok(())
}

fn validate_want(want: &proto::Want, m: &proto::Manifest) -> Result<()> {
    let mut seen = HashSet::with_capacity(want.chunks.len());
    for &idx in &want.chunks {
        if idx >= m.chunk_count {
            bail!(
                "receiver asked for chunk {idx} but the file has only {}",
                m.chunk_count
            );
        }
        if !seen.insert(idx) {
            bail!("receiver asked for chunk {idx} twice");
        }
    }
    Ok(())
}

/// Bind the port we will serve on. An explicit `--bind` is honoured exactly;
/// otherwise prefer a dual-stack socket so one endpoint reaches IPv4 and IPv6
/// peers alike, falling back to IPv4 on hosts without IPv6.
fn bind_socket(bind: Option<SocketAddr>) -> Result<UdpSocket> {
    if let Some(addr) = bind {
        return UdpSocket::bind(addr).with_context(|| format!("cannot bind {addr}"));
    }
    match UdpSocket::bind("[::]:0") {
        Ok(s) => Ok(s),
        Err(e) => {
            eprintln!("note: cannot bind [::]:0 ({e}); falling back to IPv4 only");
            UdpSocket::bind("0.0.0.0:0").context("cannot bind a UDP socket")
        }
    }
}

/// Every address a receiver might reach this socket on, run off the async
/// runtime because STUN is blocking.
async fn gather_candidates(sock: &UdpSocket, server: &str, no_stun: bool) -> Vec<SocketAddr> {
    let socket = match sock.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warning: cannot reuse socket for address discovery: {e}");
            return Vec::new();
        }
    };
    let server = server.to_string();
    match tokio::task::spawn_blocking(move || candidates(&socket, &server, no_stun)).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: address discovery task failed: {e}");
            Vec::new()
        }
    }
}

/// STUN gives the address a NAT lets the outside world use; the interfaces give
/// the address a neighbour on the same LAN uses (and, for IPv6, the address the
/// internet uses directly — global v6 is not NATed in practice, so it needs no
/// STUN at all). Both are advertised and the receiver races them.
fn candidates(sock: &UdpSocket, server: &str, no_stun: bool) -> Vec<SocketAddr> {
    let local = match sock.local_addr() {
        Ok(a) => a,
        Err(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
    };
    let port = local.port();
    let is_v6_sock = local.is_ipv6();

    let mut out: Vec<SocketAddr> = Vec::new();
    let push = |addr: SocketAddr, out: &mut Vec<SocketAddr>| {
        if !addr.ip().is_unspecified() && !out.contains(&addr) {
            out.push(addr);
        }
    };

    // An explicit `--bind <ip:port>` names the interface to use, so it comes
    // first and the other interfaces are not offered: the user already chose.
    let explicit = !local.ip().is_unspecified();
    if explicit {
        push(local, &mut out);
    }

    // A loopback-bound socket cannot send to the internet, so there is nothing
    // for STUN to discover.
    if !no_stun && !local.ip().is_loopback() {
        match stun::discover(sock, server, Duration::from_secs(2), stun::Family::V4) {
            Ok(mut a) => {
                // STUN reports the mapped address; the port is ours.
                a.set_port(port);
                eprintln!(
                    "public IPv4 {a}, learned via STUN {server} (no file data passes through it)"
                );
                push(a, &mut out);
            }
            Err(e) => eprintln!("warning: IPv4 STUN failed ({e:#})"),
        }
        // A public IPv6 is only worth a STUN query when IPv4 discovery did not
        // already prove the socket reaches the v4 internet; otherwise the
        // interface address below is the same thing without the round trip.
        if is_v6_sock && out.is_empty() {
            match stun::discover(sock, server, Duration::from_secs(2), stun::Family::V6) {
                Ok(mut a) => {
                    a.set_port(port);
                    eprintln!(
                        "public IPv6 {a}, learned via STUN {server} (no file data passes through it)"
                    );
                    push(a, &mut out);
                }
                Err(e) => eprintln!("warning: IPv6 STUN failed ({e:#})"),
            }
        }
    }

    // With no explicit bind, offer every interface address as well: that is
    // what a neighbour on the same LAN dials, and for IPv6 it is what the
    // whole internet dials — global v6 is not NATed in practice, so it needs
    // no STUN round trip at all.
    if !explicit
        && let Ok(ifaces) = if_addrs::get_if_addrs()
    {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            let ip = iface.ip();
            match ip {
                IpAddr::V4(v4) if v4.is_multicast() => continue,
                IpAddr::V6(v6)
                    if v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80 =>
                {
                    // Link-local v6 needs a scope id that a bare address cannot
                    // carry, so it can never be dialled from another machine.
                    continue;
                }
                _ => {}
            }
            // A v4-bound socket cannot send v6 at all.
            if ip.is_ipv6() && !is_v6_sock {
                continue;
            }
            push(SocketAddr::new(ip, port), &mut out);
        }
    }

    if out.is_empty()
        && let Some(ip) = guess_local_ip()
    {
        push(SocketAddr::new(IpAddr::V4(ip), port), &mut out);
    }
    out
}

/// Find this machine's routable IPv4 address without sending a packet: for UDP
/// `connect` only records a peer, so nothing leaves the host.
fn guess_local_ip() -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("1.1.1.1:443").ok()?;
    match probe.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// A connection gets this long to present a valid Hello before it is dropped.
/// Long enough for any real receiver, short enough that a candidate which
/// accepts packets but goes quiet cannot stall the sender.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Accept connections until one completes the handshake *and* sends a Hello we
/// can validate. Each connection is handled on its own task so that a slow or
/// silent one never delays a later candidate that works.
async fn await_hello(
    endpoint: &quinn::Endpoint,
    token: &str,
) -> Result<(quinn::Connection, proto::Hello, quinn::SendStream, quinn::RecvStream)> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut tasks: JoinSet<()> = JoinSet::new();
    let token = token.to_string();

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    bail!("endpoint closed before a receiver connected");
                };
                let tx = tx.clone();
                let token = token.clone();
                tasks.spawn(async move {
                    let outcome: Result<_> = match tokio::time::timeout(
                        HELLO_TIMEOUT,
                        async {
                            let conn = incoming
                                .await
                                .context("receiver failed the handshake")?;
                            let (s, mut r) = conn
                                .accept_bi()
                                .await
                                .context("receiver did not open a control stream")?;
                            let hello: proto::Hello = proto::read_msg(&mut r)
                                .await?
                                .context("receiver sent no hello")?;
                            if hello.version != proto::PROTO_VERSION {
                                bail!(
                                    "protocol mismatch: receiver speaks v{}, this sender speaks v{}",
                                    hello.version,
                                    proto::PROTO_VERSION
                                );
                            }
                            if !constant_time_eq(hello.token.as_bytes(), token.as_bytes()) {
                                bail!("rejected: token mismatch (wrong receiver, or a tampered command line)");
                            }
                            Ok((conn, hello, s, r))
                        },
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => Err(anyhow::anyhow!(
                            "no hello within {}s",
                            HELLO_TIMEOUT.as_secs()
                        )),
                    };

                    match outcome {
                        Ok(item) => {
                            let _ = tx.send(item).await;
                        }
                        Err(e) => eprintln!("dropping a connection: {e:#}"),
                    }
                });
            }
            Some(item) = rx.recv() => {
                tasks.abort_all();
                return Ok(item);
            }
        }
    }
}

fn print_invite(file: &Path, len: u64, code: &str, token: &str, candidates: &[SocketAddr]) {
    eprintln!();
    eprintln!("fx send  {}", file.display());
    eprintln!("  size          {}", progress::human(len));
    eprintln!("  verify code   {code}");
    eprintln!();
    if candidates.is_empty() {
        eprintln!("  no address could be advertised. Re-run with an explicit");
        eprintln!("  --bind <ip:port>, or leave STUN enabled.");
    } else {
        let list = candidates
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        eprintln!("  give the receiver this command:");
        eprintln!();
        eprintln!("    fx recv {list} --code {code} --token {token}");
        if candidates.len() > 1 {
            eprintln!();
            eprintln!(
                "  ({} addresses: IPv4 over the internet, IPv6, then the local network;",
                candidates.len()
            );
            eprintln!("   the receiver tries them all at once and keeps whichever answers)");
        }
    }
    eprintln!();
    eprintln!("waiting for the receiver…");
    eprintln!();
}

fn random_token() -> String {
    let mut buf = [0u8; 24];
    getrandom::fill(&mut buf).expect("no system random number generator");
    hex::encode(buf)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Discovery is off in these tests: `stun.invalid` never resolves, so
    /// anything the tests see comes from the bind and the interfaces alone.
    const NO_STUN: bool = true;

    #[test]
    fn explicit_bind_is_honoured_exactly() {
        let s = UdpSocket::bind("127.0.0.1:0").expect("loopback bind");
        let port = s.local_addr().unwrap().port();
        // An explicit bind names the interface, so no other one is offered —
        // advertising an address the socket is not listening on would only
        // make the receiver waste a race on it.
        assert_eq!(
            candidates(&s, "stun.invalid", NO_STUN),
            vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))]
        );
    }

    #[test]
    fn every_candidate_is_concrete_and_on_our_port() {
        for bind in ["0.0.0.0:0", "127.0.0.1:0", "[::]:0"] {
            let Ok(s) = UdpSocket::bind(bind) else {
                continue; // host without this family
            };
            let port = s.local_addr().unwrap().port();
            for addr in candidates(&s, "stun.invalid", NO_STUN) {
                assert!(
                    !addr.ip().is_unspecified(),
                    "{bind} advertised an unspecified address"
                );
                assert_eq!(addr.port(), port, "{bind} advertised a foreign port");
            }
        }
    }

    #[test]
    fn a_dual_stack_bind_reaches_both_families() {
        let Ok(s) = UdpSocket::bind("[::]:0") else {
            return; // host without IPv6
        };
        let port = s.local_addr().unwrap().port();
        let cands = candidates(&s, "stun.invalid", NO_STUN);
        assert!(!cands.is_empty(), "dual-stack bind produced no candidate");
        assert!(cands.iter().all(|a| a.port() == port));

        // The point of a dual-stack socket is that it does not silently drop
        // one side, but only assert the sides this host actually has.
        let ifaces = if_addrs::get_if_addrs().unwrap_or_default();
        if ifaces
            .iter()
            .any(|i| i.ip().is_ipv4() && !i.is_loopback())
        {
            assert!(
                cands.iter().any(|a| a.is_ipv4()),
                "dual-stack socket dropped its IPv4 side: {cands:?}"
            );
        }
        if ifaces
            .iter()
            .any(|i| i.ip().is_ipv6() && !i.is_loopback() && !i.is_link_local())
        {
            assert!(
                cands.iter().any(|a| a.is_ipv6()),
                "dual-stack socket dropped its IPv6 side: {cands:?}"
            );
        }
    }
}
