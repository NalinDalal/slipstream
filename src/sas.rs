//! The short authentication string the two humans compare out of band.
//!
//! TLS here uses ephemeral self-signed certificates, so ordinary PKI says
//! nothing about *who* the peer is. Instead the sender prints a code derived
//! from its certificate and the receiver recomputes it from the certificate it
//! actually received. If an active attacker terminates the handshake on either
//! side, the two codes differ and the transfer is aborted before any data
//! moves. This is the same trust model as WireGuard's key display.

use sha2::{Digest, Sha256};

/// 4 groups of 4 hex characters = 32 bits. A passive attacker has no chance; an
/// active attacker must forge a code the human will accept, which is 1 in 2^32.
const CODE_BYTES: usize = 8;

pub fn code_for(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    let b = &digest[..CODE_BYTES];
    (0..CODE_BYTES / 2)
        .map(|i| format!("{:02x}{:02x}", b[i * 2], b[i * 2 + 1]))
        .collect::<Vec<_>>()
        .join("-")
}

/// Normalise user input so `4f9a1c22 8e07 b3d5`, `4F9A-1C22-...` and the
/// canonical form all compare equal.
pub fn normalise(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

pub fn matches(expected: &str, actual: &str) -> bool {
    normalise(expected) == normalise(actual)
}

#[cfg(test)]
mod tests {
    use super::{code_for, matches, normalise};

    #[test]
    fn code_is_stable_and_grouped() {
        let c = code_for(b"certificate bytes");
        assert_eq!(c.len(), 19, "{c}");
        assert_eq!(c.matches('-').count(), 3);
        assert_eq!(c, code_for(b"certificate bytes"));
        assert_ne!(c, code_for(b"other certificate bytes"));
    }

    #[test]
    fn comparison_is_whitespace_and_case_tolerant() {
        let c = code_for(b"x");
        assert!(matches(&c, &c.to_uppercase().replace('-', " ")));
        assert!(!matches(&c, "0000-0000-0000-0000"));
        assert_eq!(normalise("Ab-Cd"), "abcd");
    }
}
