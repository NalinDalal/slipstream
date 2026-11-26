//! Ephemeral TLS identities.
//!
//! Each run generates a fresh self-signed certificate. Ordinary PKI cannot say
//! whether the peer is the intended one, so certificate verification is
//! deliberately skipped here and replaced by a human check of the short
//! authentication string in [`crate::sas`] — the receiver refuses to continue
//! unless the certificate it received hashes to the code the sender printed.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use quinn::rustls::{self, DigitallySignedStruct};

/// Must be called once before any TLS config is built.
pub fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    /// Short authentication string the peer must be shown out of band.
    pub code: String,
}

pub fn generate_identity() -> Result<Identity> {
    let key_pair = rcgen::KeyPair::generate()?;
    let params = rcgen::CertificateParams::new(vec!["fx".to_string()])?;
    let cert = params.self_signed(&key_pair)?.der().clone();
    let code = crate::sas::code_for(cert.as_ref());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok(Identity { cert, key, code })
}

/// Transport settings tuned for moving large payloads: big receive windows so
/// the pipe stays full, and enough concurrent streams to hide loss on one
/// stream behind progress on another.
fn transport() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.max_concurrent_uni_streams(64u32.into());
    t.stream_receive_window((32 * 1024 * 1024u32).into());
    t.receive_window((256 * 1024 * 1024u32).into());
    t.send_window(128 * 1024 * 1024);
    t.max_idle_timeout(Some(
        Duration::from_secs(120)
            .try_into()
            .expect("120s fits in a QUIC varint"),
    ));
    t
}

pub fn server_config(id: &Identity) -> Result<quinn::ServerConfig> {
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![id.cert.clone()], id.key.clone_key())?;
    crypto.alpn_protocols = vec![alpn()];

    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    cfg.transport_config(Arc::new(transport()));
    Ok(cfg)
}

pub fn client_config() -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(PinViaCode::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn()];

    let mut cfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    cfg.transport_config(Arc::new(transport()));
    Ok(cfg)
}

fn alpn() -> Vec<u8> {
    crate::proto::ALPN.to_vec()
}

/// Accepts any certificate cryptographically, because authenticity is decided
/// out of band by comparing [`crate::sas`] codes rather than by a CA. Without
/// that comparison this verifier would be insecure, which is why the receiver
/// requires `--code` and checks it before it asks for a single byte.
#[derive(Debug)]
struct PinViaCode(Arc<rustls::crypto::CryptoProvider>);

impl PinViaCode {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for PinViaCode {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
