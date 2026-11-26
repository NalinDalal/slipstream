# fx

Send one file from one machine to another, **directly** — no server holds the
data, no byte is transferred twice, and the receiver refuses to write anything
until it has proven it is talking to the sender you meant.

```
machine A                                machine B
─────────────────────────────────────────────────────────────
fx send big.iso
  │  hashes the file into a chunk manifest (cached across runs)
  │  binds a dual-stack socket, finds every address it can be
  │  reached on: STUN's public IPv4, its global IPv6, the LAN
  │  prints one command line carrying all of them
  │ ─────────────────────────────────────────────────────►
  │                                    fx recv 203.0.113.7:51820,2a00::7,10.0.0.5 \
  │                                      --code 4f9a-1c22-8e07-b3d5 --token 8f2c…
  │                                        ╲ the receiver races every address
  │ ◄──────────────── QUIC, directly ──────────────────────│
  │   manifest ───────────────────────────────────────────►│
  │   ◄───────────── only the missing chunks ──────────────│
  │   done ◄───────────────────────────────────────────────│
  │
  sha256 printed on both ends, compared by the humans if they want to
```

## Build

```sh
cargo build --release        # → target/release/fx
cargo test                   # unit tests: framing, digests, sanitising, STUN, candidates
scripts/test.sh              # end-to-end: round trip, resume, identity, IPv6, edges
scripts/test.sh 1024         # …with a 1 GiB file for the resume test
```

`scripts/test.sh` builds nothing itself; point it at a binary with
`FX_BIN=./target/debug/fx scripts/test.sh`. It uses `--no-stun` and loopback so
it runs offline and leaves no files behind. To exercise address discovery on
your own network:

```sh
./fx send some.iso            # should print: public IPv4 a.b.c.d:p, learned via STUN …
```

## Use

```sh
# on the machine that has the file
./fx send big.iso
```

```
fx send  /home/you/big.iso
  size          4.7 GiB
  verify code   4f9a-1c22-8e07-b3d5

  give the receiver this command:

    fx recv 203.0.113.7:51820,2a00:4140:7:1::3,192.168.1.20 --code 4f9a-1c22-8e07-b3d5 --token 8f2c3a…

  (3 addresses: IPv4 over the internet, IPv6, then the local network;
   the receiver tries them all at once and keeps whichever answers)

waiting for the receiver…
```

```sh
# on the other machine
./fx recv 203.0.113.7:51820,2a00:4140:7:1::3,192.168.1.20 \
    --code 4f9a-1c22-8e07-b3d5 --token 8f2c3a… --out ~/Downloads
```

```
connected to 203.0.113.7:51820
sender verified: code 4f9a-1c22-8e07-b3d5 matches
transferring big.iso: 1204 of 1204 chunks missing (4.7 GiB)
receiving big.iso: 4.7 GiB / 4.7 GiB  100.0%  412.6 MiB/s
saved /home/you/Downloads/big.iso
  size    4.7 GiB
  sha256 9d3c…
```

### Flags

| send | |
|---|---|
| `--bind <ip:port>` | listen address; defaults to dual-stack `[::]:0`, falling back to `0.0.0.0:0` |
| `--stun <host:port>` | address discovery, default `stun.l.google.com:19302` |
| `--no-stun` | skip discovery (LAN only) |
| `--chunk <bytes>` | verified chunk size, default 4 MiB — also the resume granularity |
| `--streams <n>` | upper bound on concurrent data streams, default 8 |
| `--token <secret>` | fixed receiver secret; random if omitted |

| recv | |
|---|---|
| `<ENDPOINT>` | comma-separated `host:port` candidates from the sender's command line |
| `--code` | **required.** the sender's verify code |
| `--token` | **required.** from the sender's command line |
| `--out <dir>` | destination directory, default `.` |
| `--streams <n>` | upper bound on concurrent data streams, default 8 |
| `--timeout <s>` | how long to race the candidates, default 15 |

---

## How it meets each constraint

| Constraint | How | Where it stops |
|---|---|---|
| **Must not pass through a third party** | QUIC over UDP, opened directly between the two hosts. STUN only *reports* the address the NAT already assigned; no file byte ever touches it. | If both NATs are symmetric, or UDP is blocked, no direct path exists. The tool then advertises the addresses it does have and fails loudly rather than silently relaying. Adding a relay would break this constraint, so it deliberately does not. |
| **Must not double transfer** | Single stream: disk → encryption → wire → decryption → disk. The manifest is hashed once from a local read, then cached — in memory for the session and on disk across runs. | Resume re-reads the *local* partial file to decide what is missing — a local read, not a network transfer. |
| **Must work cross device** | Big-endian length prefixes, explicit `u32`/`u64` widths, no struct dumping. Filenames and metadata travel as JSON, never as raw bytes. | One binary per target triple; `cargo build --release --target …` |
| **Must work outside LAN/proximity** | STUN discovers the sender's public mapping on the very socket QUIC then uses, so the NAT entry survives; the receiver's first QUIC Initial is what punches the hole. IPv6 needs no NAT at all and is advertised straight from the interfaces. | See row 1. Full ICE is not implemented — and without a relay it could not help in the one case that matters. See [Addresses](#addresses). |
| **Must work with other people's setup** | Zero configuration on the receiver: no install, no account, no shared filesystem, no port forwarding — just the one command line. | The receiver does need `fx`. Interoperating with an *arbitrary* existing tool would mean speaking HTTPS or SSH, both of which need a server or their credentials. |
| **Must be fast for large files** | Streaming with bounded buffers (never the whole file in RAM), N multiplexed QUIC streams so one lost packet does not stall the rest, 32 MiB stream receive windows, sequential disk reads. | Measured **~115 MiB/s** end-to-end on loopback *including* a SHA-256 pass on each side. Disk and hashing become the limit before the network does. |
| **Must not be insecure** | TLS 1.3 (QUIC), plus mutual authentication that does not depend on a CA — see below. Every chunk is digest-checked **before** it is written. | Compromised endpoint = game over, as always. |

## Addresses

One `fx send` is often reachable in several ways at once, so it advertises all
of them in a single comma-separated list and the receiver races them:

1. **Public IPv4** — one STUN query, sent on the same socket QUIC will use, so
   the mapping the query creates is the mapping the receiver's Initial arrives
   on. A second query would create a second mapping and be useless.
2. **Global IPv6** — read straight off the interfaces. Global v6 is not NATed
   in practice, so it needs no query and involves no third party at all.
3. **Interface addresses** — what a neighbour on the same LAN dials.

The receiver opens every candidate at once and keeps the first handshake to
complete; the losers close themselves. A candidate that does not route therefore
costs one failed attempt instead of a timeout, which is why a dead address in
the list is harmless. Two machines that share a LAN *and* both have IPv6 simply
use whichever answers first.

`--bind` narrows the list: an explicit address is the only one offered, which
is how you pin an interface (or pin loopback for a test).

### Why this is not ICE

ICE (RFC 8445) gathers candidates on both ends, exchanges them, runs STUN
binding checks between every pair, then nominates one and keeps checking it for
as long as the session lives. `fx` does a deliberate subset:

- candidates are gathered and exchanged — out of band, in the command line, so
  the verify code and the addresses travel together over the same trusted
  channel;
- connectivity is proven by racing real QUIC handshakes rather than by
  pre-flight STUN checks: the Initial packet **is** the connectivity check, and
  it is authenticated by the same handshake that carries the data;
- there is no controlling/controlled role selection, no nominated pair, no
  consent freshness.

What full ICE adds beyond that is the patience to keep trying pairs and the
ability to fall back to a relay when every pair fails. The relay is the part
that matters — and a relay is a third party in the data path, which this tool
refuses to be. Without one, the case ICE would rescue is a symmetric NAT on the
sender's side, and no amount of checking can create a path that does not exist.

## Manifest cache

Hashing a file is a full sequential read of it, which for a large file is the
dominant cost of starting a transfer. The digest list is cached under the
platform cache directory (`~/Library/Caches/fx` on macOS, `$XDG_CACHE_HOME/fx`
elsewhere) and keyed on `(canonical path, size, mtime, chunk size)` — every
input that would change the digests — so an entry for changed content cannot be
hit rather than having to be detected afterwards. The cache holds at most 128
entries. `FX_CACHE_DIR` overrides the location; setting it to an empty string
disables caching entirely.

## Authentication

TLS normally answers "is this the right peer?" with a certificate chain. Here
there is no PKI, so instead:

1. The sender generates an ephemeral self-signed certificate and prints a
   **verify code** — the first 8 bytes of its SHA-256, as `xxxx-xxxx-xxxx-xxxx`.
2. The receiver recomputes that code from the certificate it *actually*
   received over the wire. If they differ, it aborts **before requesting a
   single byte**.
3. The command line also carries a random **token**. The sender checks it on
   the first message, so nobody else who finds the open port can pull the file.

An attacker who terminates TLS on either side produces a different certificate,
hence a different code, hence an aborted transfer. This is the same trust model
as WireGuard's key display: the out-of-band channel the code travels through
(the chat, the email, the phone call) **is** the root of trust. If an attacker
controls that channel entirely, no protocol can help.

Both values are mandatory on `recv` — there is no `--insecure` flag to forget.

## Integrity

The file is split into chunks; the sender hashes each one and sends the digests
in the manifest. The receiver hashes every chunk **as it arrives and before it
writes it** — corrupt data never reaches the file. A chunk whose digest does
not match aborts the transfer rather than being quietly accepted.

`fx` also prints the whole-file SHA-256 on both ends, so you can cross-check
with `shasum -a 256` if you want a second opinion.

## Resume without bookkeeping

There is no sidecar state file to get out of sync with the data. On reconnect
the receiver hashes what is already in the `.part` file and asks only for the
chunks whose digests do not match:

```
first run     transferring blob.bin: 128 of 128 chunks missing (512.0 MiB)
              ← interrupted after 390 MB
second run    transferring blob.bin: 48 of 128 chunks missing (192.0 MiB)
```

80 chunks were skipped, not re-sent. A partially written or corrupted chunk
fails its digest and is refetched. On success the file is `fsync`ed and then
renamed, so a crash can never leave a truncated file with a completed name.

## Threat model

**Assumed attacker:** can observe, drop, reorder and inject packets; can
terminate TLS; does *not* control the out-of-band channel that carries the
verify code and token.

| Attack | Outcome |
|---|---|
| Passive eavesdropper | Sees ciphertext only (TLS 1.3, forward secrecy from ephemeral handshakes). |
| Active MITM terminating TLS | Produces a different certificate → verify code mismatch → **aborted before any data**. |
| Random host scanning the open port | No token → rejected on the first message. |
| Corrupted or forged chunk | Digest mismatch → **never written to disk**. |
| Filename `../../etc/passwd`, `CON`, control characters | Sanitised: separators become `_`, leading dots stripped, reserved device names prefixed, length capped, no path components. |
| Truncated or oversized protocol frame | Length-prefixed with hard caps; anything out of bounds is an error, not a panic. |
| Interrupted transfer | Resumes by content; no state to corrupt. |

**Not defended against:** a compromised sender or receiver machine, and an
attacker who controls the channel the verify code travels over.

## Protocol

One bidirectional control stream (length-prefixed JSON) plus N unidirectional
data streams (framed chunk records), all inside one QUIC connection:

```
receiver ──► Hello   { version, token, streams }
sender   ──► Manifest { file_len, chunk_size, hashes[], file_sha256, streams }
receiver ──► Want    { chunks: [indices it is missing] }
sender   ══► [ChunkHeader { index, len }][bytes]  × N streams, round-robin
receiver ──► Done    { ok, received, bytes }
sender   ──► Bye     { ok }
```

Both ends independently compute the stream count as
`min(len(Want), sender cap, receiver cap)`, so neither can be made to open more
streams than it agreed to accept.

## Layout

| file | role |
|---|---|
| `src/main.rs` | CLI |
| `src/proto.rs` | messages, framing, stream arithmetic |
| `src/manifest.rs` | chunking, hashing, resume scan, filename sanitising |
| `src/cache.rs` | manifest cache, keyed so stale entries cannot be hit |
| `src/send.rs` | sender: bind → discover addresses → hash → serve one receiver |
| `src/recv.rs` | receiver: race candidates → verify → fetch missing → verify → rename |
| `src/tls.rs` | ephemeral identities, QUIC transport tuning |
| `src/sas.rs` | the short verify code |
| `src/stun.rs` | minimal RFC 5389 binding client |
| `src/progress.rs` | one-line stderr progress |

## Known limits

- **A symmetric NAT on the sender's side cannot be traversed.** No direct path
  exists, and the only fix is a relay — a third party in the data path, which
  this tool refuses to be. Cone NATs (the common case) and IPv6 both work.
  IPv6 is the durable answer: it removes the NAT rather than working around it.
- **One receiver per `fx send`.** A second connection is dropped rather than
  served.
- **Link-local IPv6 is not advertised** — it carries a scope id that a bare
  address cannot, so it is never dialled from another machine. A host with only
  link-local v6 falls back to IPv4.
- **Directories are not supported** — files only.
- Every send of an unchanged file after the first reads nothing (see
  [Manifest cache](#manifest-cache)); a changed file is hashed from scratch.
