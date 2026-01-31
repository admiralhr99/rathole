// src/transport/shadowtls.rs
// ShadowTLS: TLS with fake SNI for DPI evasion (no Noise overhead)
// Simpler and faster than ShadowTLS-Noise

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context as AnyhowContext, Result};
use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use super::{AddrMaybeCached, SocketOpts, TcpTransport, Transport};
use crate::config::{ShadowTlsNoiseConfig, TransportConfig};

/// ShadowTLS Transport - TLS with fake SNI, no Noise overhead
pub struct ShadowTlsTransport {
    tcp: TcpTransport,
    config: ShadowTlsNoiseConfig,
    tls_connector: Option<TlsConnector>,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Debug for ShadowTlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowTlsTransport")
            .field("camouflage_domain", &self.config.camouflage_domain)
            .field("skip_cert_verify", &self.config.skip_cert_verify)
            .finish()
    }
}

/// ShadowTLS stream - just TLS over TCP (no Noise)
pub type ShadowTlsStream = TlsStream<TcpStream>;

/// Dummy certificate verifier that accepts any certificate
#[derive(Debug)]
struct NoVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
            tokio_rustls::rustls::SignatureScheme::ED25519,
        ]
    }
}

impl ShadowTlsTransport {
    fn build_tls_client_config(skip_cert_verify: bool) -> Result<TlsConnector> {
        let config = if skip_cert_verify {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        Ok(TlsConnector::from(Arc::new(config)))
    }
}

#[async_trait]
impl Transport for ShadowTlsTransport {
    type Acceptor = TcpListener;
    type RawStream = TcpStream;
    type Stream = ShadowTlsStream;

    fn new(config: &TransportConfig) -> Result<Self> {
        let tcp = TcpTransport::new(config)?;

        let shadowtls_config = config
            .shadowtls_noise
            .as_ref()
            .ok_or_else(|| anyhow!("Missing shadowtls_noise config"))?
            .clone();

        let tls_connector = Self::build_tls_client_config(shadowtls_config.skip_cert_verify).ok();

        let tls_acceptor = if let (Some(cert_path), Some(key_path)) = (
            shadowtls_config.tls_cert.as_ref(),
            shadowtls_config.tls_key.as_ref(),
        ) {
            let cert_pem = std::fs::read(cert_path)
                .with_context(|| format!("Failed to read TLS cert: {}", cert_path))?;
            let key_pem = std::fs::read(key_path)
                .with_context(|| format!("Failed to read TLS key: {}", key_path))?;

            let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
                .filter_map(|r| r.ok())
                .collect();

            let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
                .with_context(|| "Failed to parse private key")?
                .ok_or_else(|| anyhow!("No private key found"))?;

            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .with_context(|| "Failed to build TLS server config")?;

            Some(TlsAcceptor::from(Arc::new(server_config)))
        } else {
            None
        };

        Ok(ShadowTlsTransport {
            tcp,
            config: shadowtls_config,
            tls_connector,
            tls_acceptor,
        })
    }

    fn hint(conn: &Self::Stream, opt: SocketOpts) {
        let tcp_stream = conn.get_ref().0;
        opt.apply(tcp_stream);
    }

    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, addr: T) -> Result<Self::Acceptor> {
        Ok(TcpListener::bind(addr).await?)
    }

    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
        self.tcp
            .accept(a)
            .await
            .with_context(|| "Failed to accept TCP connection")
    }

    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
        tracing::debug!("ShadowTLS: Server accepting connection");

        let acceptor = self
            .tls_acceptor
            .as_ref()
            .ok_or_else(|| anyhow!("TLS acceptor not configured"))?;

        let tls_stream = acceptor
            .accept(conn)
            .await
            .with_context(|| "TLS accept failed")?;

        tracing::debug!("ShadowTLS: TLS handshake complete (server)");

        Ok(TlsStream::Server(tls_stream))
    }

    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream> {
        tracing::debug!("ShadowTLS: Connecting to {}", addr);

        let tcp_stream = self
            .tcp
            .connect(addr)
            .await
            .with_context(|| "Failed to connect TCP")?;

        let connector = self
            .tls_connector
            .as_ref()
            .ok_or_else(|| anyhow!("TLS connector not configured"))?;

        let server_name: ServerName<'static> = self
            .config
            .camouflage_domain
            .clone()
            .try_into()
            .map_err(|_| anyhow!("Invalid camouflage domain"))?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .with_context(|| "TLS handshake failed")?;

        tracing::debug!("ShadowTLS: TLS handshake complete (client)");

        Ok(TlsStream::Client(tls_stream))
    }
}
