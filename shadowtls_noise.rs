// src/transport/shadowtls_noise.rs
// ShadowTLS-Noise: Wraps Noise protocol inside TLS handshake to evade DPI
// Mimics legitimate HTTPS connection while tunneling Noise encrypted data

use anyhow::{Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, ClientConfig, ServerConfig, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use webpki_roots;

use snowstorm::{Builder as NoiseBuilder, NoiseParams, TransportState};

const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_VERSION_1_2: u16 = 0x0303;
const MAX_TLS_RECORD_SIZE: usize = 16384;

/// ShadowTLS-Noise configuration
#[derive(Debug, Clone)]
pub struct ShadowTlsNoiseConfig {
    /// Camouflage domain (e.g., "www.microsoft.com")
    pub camouflage_domain: String,
    /// Noise protocol pattern
    pub noise_pattern: String,
    /// Local Noise private key (base64)
    pub noise_local_key: Option<String>,
    /// Remote Noise public key (base64)  
    pub noise_remote_key: Option<String>,
}

impl Default for ShadowTlsNoiseConfig {
    fn default() -> Self {
        Self {
            camouflage_domain: "www.microsoft.com".to_string(),
            noise_pattern: "Noise_NK_25519_ChaChaPoly_BLAKE2s".to_string(),
            noise_local_key: None,
            noise_remote_key: None,
        }
    }
}

/// Client-side ShadowTLS-Noise stream
pub struct ShadowTlsNoiseClientStream {
    tls_stream: TlsStream<TcpStream>,
    noise_state: TransportState,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
}

impl ShadowTlsNoiseClientStream {
    /// Connect and establish ShadowTLS-Noise tunnel
    pub async fn connect(
        addr: &str,
        config: ShadowTlsNoiseConfig,
    ) -> Result<Self> {
        tracing::info!("ShadowTLS-Noise: Connecting to {}", addr);
        
        // Step 1: TCP connection
        let tcp_stream = TcpStream::connect(addr)
            .await
            .context("Failed to connect TCP")?;
        
        // Step 2: TLS handshake (masquerading as connection to camouflage domain)
        let tls_connector = build_tls_client_config(&config.camouflage_domain)?;
        
        let server_name = ServerName::try_from(config.camouflage_domain.as_str())
            .context("Invalid camouflage domain")?;
        
        let mut tls_stream = tls_connector
            .connect(server_name, tcp_stream)
            .await
            .context("TLS handshake failed")?;
        
        tracing::info!("ShadowTLS-Noise: TLS handshake complete");
        
        // Step 3: Noise handshake (inside TLS ApplicationData)
        let noise_state = perform_noise_client_handshake(
            &mut tls_stream,
            &config,
        ).await?;
        
        tracing::info!("ShadowTLS-Noise: Noise handshake complete");
        
        Ok(Self {
            tls_stream,
            noise_state,
            read_buffer: BytesMut::with_capacity(MAX_TLS_RECORD_SIZE),
            write_buffer: BytesMut::with_capacity(MAX_TLS_RECORD_SIZE),
        })
    }
    
    /// Send encrypted data
    pub async fn write_encrypted(&mut self, data: &[u8]) -> Result<()> {
        // Encrypt with Noise
        let encrypted = self.noise_state.write_message(data)
            .context("Noise encryption failed")?;
        
        // Wrap in TLS ApplicationData record
        self.write_buffer.clear();
        write_tls_record(&mut self.write_buffer, &encrypted);
        
        // Send via TLS
        self.tls_stream.write_all(&self.write_buffer).await?;
        self.tls_stream.flush().await?;
        
        Ok(())
    }
    
    /// Receive encrypted data
    pub async fn read_encrypted(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Read TLS record
        let tls_payload = read_tls_record(&mut self.tls_stream, &mut self.read_buffer).await?;
        
        // Decrypt with Noise
        let plaintext = self.noise_state.read_message(&tls_payload)
            .context("Noise decryption failed")?;
        
        let len = plaintext.len().min(buf.len());
        buf[..len].copy_from_slice(&plaintext[..len]);
        
        Ok(len)
    }
}

/// Server-side ShadowTLS-Noise stream  
pub struct ShadowTlsNoiseServerStream {
    tls_stream: TlsStream<TcpStream>,
    noise_state: TransportState,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
}

impl ShadowTlsNoiseServerStream {
    /// Accept incoming ShadowTLS-Noise connection
    pub async fn accept(
        tcp_stream: TcpStream,
        config: ShadowTlsNoiseConfig,
        tls_config: Arc<ServerConfig>,
    ) -> Result<Self> {
        tracing::info!("ShadowTLS-Noise: Accepting connection");
        
        // Step 1: TLS handshake
        let acceptor = TlsAcceptor::from(tls_config);
        let mut tls_stream = acceptor.accept(tcp_stream).await
            .context("TLS accept failed")?;
        
        tracing::info!("ShadowTLS-Noise: TLS handshake complete");
        
        // Step 2: Noise handshake (inside TLS ApplicationData)
        let noise_state = perform_noise_server_handshake(
            &mut tls_stream,
            &config,
        ).await?;
        
        tracing::info!("ShadowTLS-Noise: Noise handshake complete");
        
        Ok(Self {
            tls_stream,
            noise_state,
            read_buffer: BytesMut::with_capacity(MAX_TLS_RECORD_SIZE),
            write_buffer: BytesMut::with_capacity(MAX_TLS_RECORD_SIZE),
        })
    }
    
    /// Send encrypted data
    pub async fn write_encrypted(&mut self, data: &[u8]) -> Result<()> {
        // Encrypt with Noise
        let encrypted = self.noise_state.write_message(data)
            .context("Noise encryption failed")?;
        
        // Wrap in TLS ApplicationData record
        self.write_buffer.clear();
        write_tls_record(&mut self.write_buffer, &encrypted);
        
        // Send via TLS
        self.tls_stream.write_all(&self.write_buffer).await?;
        self.tls_stream.flush().await?;
        
        Ok(())
    }
    
    /// Receive encrypted data
    pub async fn read_encrypted(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Read TLS record
        let tls_payload = read_tls_record(&mut self.tls_stream, &mut self.read_buffer).await?;
        
        // Decrypt with Noise
        let plaintext = self.noise_state.read_message(&tls_payload)
            .context("Noise decryption failed")?;
        
        let len = plaintext.len().min(buf.len());
        buf[..len].copy_from_slice(&plaintext[..len]);
        
        Ok(len)
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Build TLS client configuration
fn build_tls_client_config(camouflage_domain: &str) -> Result<TlsConnector> {
    let mut root_store = rustls::RootCertStore::empty();
    
    // Add system root certificates
    for cert in webpki_roots::TLS_SERVER_ROOTS.iter() {
        root_store.add(cert).context("Failed to add root cert")?;
    }
    
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Perform Noise client handshake (inside TLS)
async fn perform_noise_client_handshake<S>(
    stream: &mut S,
    config: &ShadowTlsNoiseConfig,
) -> Result<TransportState>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let params: NoiseParams = config.noise_pattern.parse()
        .context("Invalid Noise pattern")?;
    
    let mut noise_builder = NoiseBuilder::new(params);
    
    // Set remote public key if provided (for NK, IK patterns)
    if let Some(ref pubkey_b64) = config.noise_remote_key {
        let pubkey = base64::decode(pubkey_b64)
            .context("Invalid remote public key")?;
        noise_builder = noise_builder.remote_public_key(&pubkey);
    }
    
    // Set local private key if provided
    if let Some(ref privkey_b64) = config.noise_local_key {
        let privkey = base64::decode(privkey_b64)
            .context("Invalid local private key")?;
        noise_builder = noise_builder.local_private_key(&privkey);
    }
    
    let mut noise = noise_builder.build_initiator()?;
    
    // Noise handshake (2-3 messages depending on pattern)
    // Message 1: Client -> Server
    let msg1 = noise.write_message(&[])?;
    write_length_prefixed(stream, &msg1).await?;
    
    // Message 2: Server -> Client
    let msg2 = read_length_prefixed(stream).await?;
    noise.read_message(&msg2)?;
    
    // Check if handshake is complete (XX pattern has 3 messages)
    if !noise.is_handshake_finished() {
        // Message 3: Client -> Server
        let msg3 = noise.write_message(&[])?;
        write_length_prefixed(stream, &msg3).await?;
    }
    
    Ok(noise.into_transport_mode()?)
}

/// Perform Noise server handshake (inside TLS)
async fn perform_noise_server_handshake<S>(
    stream: &mut S,
    config: &ShadowTlsNoiseConfig,
) -> Result<TransportState>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let params: NoiseParams = config.noise_pattern.parse()
        .context("Invalid Noise pattern")?;
    
    let mut noise_builder = NoiseBuilder::new(params);
    
    // Set local private key (server identity)
    if let Some(ref privkey_b64) = config.noise_local_key {
        let privkey = base64::decode(privkey_b64)
            .context("Invalid local private key")?;
        noise_builder = noise_builder.local_private_key(&privkey);
    }
    
    let mut noise = noise_builder.build_responder()?;
    
    // Noise handshake
    // Message 1: Client -> Server
    let msg1 = read_length_prefixed(stream).await?;
    noise.read_message(&msg1)?;
    
    // Message 2: Server -> Client
    let msg2 = noise.write_message(&[])?;
    write_length_prefixed(stream, &msg2).await?;
    
    // Check if handshake is complete
    if !noise.is_handshake_finished() {
        // Message 3: Client -> Server
        let msg3 = read_length_prefixed(stream).await?;
        noise.read_message(&msg3)?;
    }
    
    Ok(noise.into_transport_mode()?)
}

/// Write TLS ApplicationData record
fn write_tls_record(buf: &mut BytesMut, payload: &[u8]) {
    buf.put_u8(TLS_APPLICATION_DATA);  // Content type
    buf.put_u16(TLS_VERSION_1_2);       // TLS 1.2 version
    buf.put_u16(payload.len() as u16);  // Length
    buf.put_slice(payload);             // Payload
}

/// Read TLS ApplicationData record
async fn read_tls_record<S>(
    stream: &mut S,
    buffer: &mut BytesMut,
) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    // Read TLS record header (5 bytes)
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    
    let content_type = header[0];
    let version = u16::from_be_bytes([header[1], header[2]]);
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    
    if content_type != TLS_APPLICATION_DATA {
        return Err(anyhow::anyhow!("Unexpected TLS content type: {}", content_type));
    }
    
    if length > MAX_TLS_RECORD_SIZE {
        return Err(anyhow::anyhow!("TLS record too large: {}", length));
    }
    
    // Read payload
    buffer.clear();
    buffer.resize(length, 0);
    stream.read_exact(&mut buffer[..length]).await?;
    
    Ok(buffer[..length].to_vec())
}

/// Write length-prefixed message (for Noise handshake)
async fn write_length_prefixed<S>(stream: &mut S, data: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let len = data.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Read length-prefixed message (for Noise handshake)
async fn read_length_prefixed<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    
    if len > 65535 {
        return Err(anyhow::anyhow!("Message too large: {}", len));
    }
    
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

// Implement AsyncRead/AsyncWrite traits for easy integration
impl AsyncRead for ShadowTlsNoiseClientStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // Simplified - in production, use proper async polling
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ShadowTlsNoiseClientStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // Simplified - in production, use proper async polling
        std::task::Poll::Ready(Ok(buf.len()))
    }
    
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
