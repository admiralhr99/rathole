// src/transport/shadowtls_noise.rs
// ShadowTLS-Noise: Wraps Noise protocol inside TLS handshake to evade DPI
// Mimics legitimate HTTPS connection while tunneling Noise encrypted data

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context as AnyhowContext, Result};
use async_trait::async_trait;
use snowstorm::{Builder as NoiseBuilder, NoiseParams, NoiseStream};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use super::{AddrMaybeCached, SocketOpts, TcpTransport, Transport};
use crate::config::{ShadowTlsNoiseConfig, TransportConfig};

/// ShadowTLS-Noise Transport
/// Wraps Noise protocol inside TLS to evade DPI detection
pub struct ShadowTlsNoiseTransport {
    tcp: TcpTransport,
    config: ShadowTlsNoiseConfig,
    noise_params: NoiseParams,
    local_private_key: Vec<u8>,
    remote_public_key: Option<Vec<u8>>,
    tls_connector: Option<TlsConnector>,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Debug for ShadowTlsNoiseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowTlsNoiseTransport")
            .field("camouflage_domain", &self.config.camouflage_domain)
            .field("noise_pattern", &self.config.noise_pattern)
            .field("skip_cert_verify", &self.config.skip_cert_verify)
            .finish()
    }
}

/// ShadowTLS-Noise stream - Noise over TLS over TCP
pub type ShadowTlsNoiseStream = NoiseStream<TlsStream<TcpStream>>;

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

impl ShadowTlsNoiseTransport {
    fn build_tls_client_config(skip_cert_verify: bool) -> Result<TlsConnector> {
        let config = if skip_cert_verify {
            // Skip certificate verification - allows using fake camouflage domains
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            // Normal certificate verification
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        Ok(TlsConnector::from(Arc::new(config)))
    }

    fn noise_builder(&self) -> NoiseBuilder {
        let builder =
            NoiseBuilder::new(self.noise_params.clone()).local_private_key(&self.local_private_key);
        match &self.remote_public_key {
            Some(key) => builder.remote_public_key(key),
            None => builder,
        }
    }
}

#[async_trait]
impl Transport for ShadowTlsNoiseTransport {
    type Acceptor = TcpListener;
    type RawStream = TcpStream;
    type Stream = ShadowTlsNoiseStream;

    fn new(config: &TransportConfig) -> Result<Self> {
        let tcp = TcpTransport::new(config)?;

        let shadowtls_config = config
            .shadowtls_noise
            .as_ref()
            .ok_or_else(|| anyhow!("Missing shadowtls_noise config"))?
            .clone();

        // Parse Noise parameters
        let noise_params: NoiseParams = shadowtls_config
            .noise_pattern
            .parse()
            .with_context(|| "Invalid Noise pattern")?;

        // Decode remote public key if provided
        let remote_public_key = match &shadowtls_config.remote_public_key {
            Some(key) => Some(
                base64::decode(key).with_context(|| "Failed to decode remote_public_key")?,
            ),
            None => None,
        };

        // Decode or generate local private key
        let builder = NoiseBuilder::new(noise_params.clone());
        let local_private_key = match &shadowtls_config.local_private_key {
            Some(key) => {
                base64::decode(key.as_bytes()).with_context(|| "Failed to decode local_private_key")?
            }
            None => builder.generate_keypair()?.private,
        };

        // Build TLS client connector
        let tls_connector = Self::build_tls_client_config(shadowtls_config.skip_cert_verify).ok();

        // Build TLS server acceptor if certificate is provided
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

        Ok(ShadowTlsNoiseTransport {
            tcp,
            config: shadowtls_config,
            noise_params,
            local_private_key,
            remote_public_key,
            tls_connector,
            tls_acceptor,
        })
    }

    fn hint(conn: &Self::Stream, opt: SocketOpts) {
        // Get the underlying TCP stream through TLS
        let tls_stream = conn.get_inner();
        let tcp_stream = tls_stream.get_ref().0;
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
        tracing::info!("ShadowTLS-Noise: Server accepting connection");

        // Step 1: TLS handshake
        let acceptor = self
            .tls_acceptor
            .as_ref()
            .ok_or_else(|| anyhow!("TLS acceptor not configured - missing tls_cert/tls_key"))?;

        let tls_stream = acceptor
            .accept(conn)
            .await
            .with_context(|| "TLS accept failed")?;

        let tls_stream = TlsStream::Server(tls_stream);

        tracing::debug!("ShadowTLS-Noise: TLS handshake complete (server)");

        // Step 2: Noise handshake over TLS
        let noise_stream = NoiseStream::handshake(tls_stream, self.noise_builder().build_responder()?)
            .await
            .with_context(|| "Failed to do Noise handshake")?;

        tracing::info!("ShadowTLS-Noise: Noise handshake complete (server)");

        Ok(noise_stream)
    }

    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream> {
        tracing::info!("ShadowTLS-Noise: Connecting to {}", addr);

        // Step 1: TCP connection
        let tcp_stream = self
            .tcp
            .connect(addr)
            .await
            .with_context(|| "Failed to connect TCP")?;

        // Step 2: TLS handshake
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

        let tls_stream = TlsStream::Client(tls_stream);

        tracing::debug!("ShadowTLS-Noise: TLS handshake complete (client)");

        // Step 3: Noise handshake over TLS
        let noise_stream = NoiseStream::handshake(tls_stream, self.noise_builder().build_initiator()?)
            .await
            .with_context(|| "Failed to do Noise handshake")?;

        tracing::info!("ShadowTLS-Noise: Noise handshake complete (client)");

        Ok(noise_stream)
    }
}
