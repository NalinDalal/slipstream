//! Minimal STUN client (RFC 5389 binding request) used to learn the sender's
//! public ip:port without involving any third party in the data path.
//!
//! STUN only *reports* the address the NAT already assigned; no file bytes ever
//! pass through the STUN server. It is used solely so the receiver knows where
//! to send its first packet, which is what punches the hole.

use std::io::ErrorKind;
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs, UdpSocket,
};
use std::time::Duration;

use anyhow::{Context, Result, bail};

const MAGIC: u32 = 0x2112A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const ATTEMPTS: usize = 3;
const READS_PER_ATTEMPT: usize = 16;

/// Which family of STUN server address to use.
///
/// This is chosen by the caller rather than derived from the socket, because a
/// dual-stack socket can reach servers of both families: what matters is which
/// *public* address we want to learn.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    V4,
    V6,
}

/// Discover the public address `sock` is reachable at, as seen by `server`.
///
/// Temporarily switches the socket to blocking with a read timeout, then
/// restores non-blocking mode, so the socket can be handed straight to QUIC
/// afterwards while keeping the NAT mapping STUN just created. The caller must
/// leave the socket non-blocking when it calls this.
pub fn discover(
    sock: &UdpSocket,
    server: &str,
    timeout: Duration,
    family: Family,
) -> Result<SocketAddr> {
    let want_ipv6 = family == Family::V6;
    let server_addr = server
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve STUN server {server}"))?
        .find(|addr| addr.is_ipv6() == want_ipv6)
        .with_context(|| {
            format!("STUN server {server} has no {family:?} address")
        })?;

    // A dual-stack socket must be given IPv6 destinations in mapped form;
    // handing it a bare `sockaddr_in` is not portable.
    let server_addr = if sock.local_addr()?.is_ipv6() {
        match server_addr {
            SocketAddr::V4(v4) => SocketAddr::V6(SocketAddrV6::new(
                v4.ip().to_ipv6_mapped(),
                v4.port(),
                0,
                0,
            )),
            other => other,
        }
    } else {
        server_addr
    };

    sock.set_nonblocking(false)?;
    sock.set_read_timeout(Some(timeout))?;

    let outcome = exchange(sock, server_addr, server);

    let _ = sock.set_read_timeout(None);
    let _ = sock.set_nonblocking(true);
    outcome
}

fn exchange(sock: &UdpSocket, server_addr: SocketAddr, server: &str) -> Result<SocketAddr> {
    for _ in 0..ATTEMPTS {
        let mut txid = [0u8; 12];
        getrandom::fill(&mut txid).context("no system RNG")?;

        let mut request = Vec::with_capacity(20);
        request.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        request.extend_from_slice(&0u16.to_be_bytes());
        request.extend_from_slice(&MAGIC.to_be_bytes());
        request.extend_from_slice(&txid);
        sock.send_to(&request, server_addr)?;

        let mut buf = [0u8; 1500];
        for _ in 0..READS_PER_ATTEMPT {
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => return Err(e.into()),
            };
            if from.ip() != server_addr.ip() {
                continue;
            }
            if let Some(addr) = parse(&buf[..n], &txid)?.filter(|a| !a.ip().is_unspecified()) {
                return Ok(addr);
            }
        }
    }
    bail!("no response from STUN server {server}")
}

fn parse(msg: &[u8], txid: &[u8; 12]) -> Result<Option<SocketAddr>> {
    if msg.len() < 20 {
        return Ok(None);
    }
    let msg_type = u16::from_be_bytes([msg[0], msg[1]]);
    let msg_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let magic = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);

    if msg_type == BINDING_ERROR {
        bail!("STUN server returned a binding error");
    }
    if msg_type != BINDING_SUCCESS || magic != MAGIC || &msg[8..20] != txid {
        return Ok(None);
    }
    if msg.len() < 20 + msg_len {
        bail!("truncated STUN response");
    }

    let attrs = &msg[20..20 + msg_len];
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[off], attrs[off + 1]]);
        let attr_len = u16::from_be_bytes([attrs[off + 2], attrs[off + 3]]) as usize;
        let start = off + 4;
        if start + attr_len > attrs.len() {
            break;
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS || attr_type == ATTR_MAPPED_ADDRESS {
            let xor = attr_type == ATTR_XOR_MAPPED_ADDRESS;
            if let Some(addr) = parse_address(&attrs[start..start + attr_len], xor, txid) {
                return Ok(Some(addr));
            }
        }
        off = (start + attr_len + 3) & !3; // attributes are padded to 4 bytes
    }
    Ok(None)
}

fn parse_address(value: &[u8], xor: bool, txid: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (MAGIC >> 16) as u16;
    }

    match value[1] {
        0x01 if value.len() >= 8 => {
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&value[4..8]);
            if xor {
                let magic = MAGIC.to_be_bytes();
                for (b, m) in ip.iter_mut().zip(magic) {
                    *b ^= m;
                }
            }
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
        }
        0x02 if value.len() >= 20 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[4..20]);
            if xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC.to_be_bytes());
                mask[4..].copy_from_slice(txid);
                for (b, m) in ip.iter_mut().zip(mask) {
                    *b ^= m;
                }
            }
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                port,
                0,
                0,
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xor_mapped_ipv4() {
        let txid = [7u8; 12];
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&12u16.to_be_bytes()); // 4-byte attr header + 8-byte value
        msg.extend_from_slice(&MAGIC.to_be_bytes());
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.push(0);
        msg.push(0x01); // IPv4
        let port: u16 = 54321;
        msg.extend_from_slice(&(port ^ ((MAGIC >> 16) as u16)).to_be_bytes());
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        for (b, m) in ip.octets().iter().zip(MAGIC.to_be_bytes()) {
            msg.push(*b ^ m);
        }

        let parsed = parse(&msg, &txid).unwrap().unwrap();
        assert_eq!(
            parsed,
            SocketAddr::V4(SocketAddrV4::new(ip, port)),
            "XOR must be undone"
        );
    }

    #[test]
    fn ignores_wrong_transaction_id() {
        let msg = [0x01u8, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42]
            .iter()
            .copied()
            .chain([0u8; 12])
            .collect::<Vec<_>>();
        assert!(parse(&msg, &[9u8; 12]).unwrap().is_none());
    }
}
