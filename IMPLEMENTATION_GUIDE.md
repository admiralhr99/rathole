# ShadowTLS-Noise Implementation Guide for Rathole

## Overview
This guide adds ShadowTLS-Noise transport to rathole, wrapping Noise protocol inside TLS to evade Iran's DPI detection.

## DPI Evasion Strategy
- **Layer 1**: TLS 1.2/1.3 handshake to legitimate domain (www.microsoft.com)
- **Layer 2**: Valid TLS ApplicationData records  
- **Layer 3**: Noise protocol encrypted payload inside TLS
- **Result**: DPI sees normal HTTPS traffic to Microsoft/Google/etc.

---

## Step 1: Fork and Clone Rathole

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/rathole.git
cd rathole
git checkout -b shadowtls-noise

# Or clone original and create branch
git clone https://github.com/rathole-org/rathole.git  
cd rathole
git checkout -b shadowtls-noise
```

---

## Step 2: Modify Cargo.toml

Add to **`Cargo.toml`** in the dependencies section:

```toml
[dependencies]
# ... existing dependencies ...

# ShadowTLS dependencies
rustls = { version = "0.21", optional = true }
tokio-rustls = { version = "0.24", optional = true }
webpki-roots = { version = "0.25", optional = true }
snowstorm = { version = "0.4", optional = true }
base64 = { version = "0.21", optional = true }
rand = "0.8"
bytes = "1.0"
```

Add feature flag:

```toml
[features]
default = [
    "server",
    "client",
    "native-tls",
    "noise",
    "shadowtls-noise",  # ADD THIS
    "websocket-native-tls",
    "hot-reload",
]

# ADD THIS FEATURE
shadowtls-noise = [
    "rustls",
    "tokio-rustls",
    "webpki-roots",
    "snowstorm",
    "base64",
    "noise"
]
```

---

## Step 3: Create New Transport Module

Create **`src/transport/shadowtls_noise.rs`** (provided separately - use the full implementation file).

---

## Step 4: Modify src/transport/mod.rs

Edit **`src/transport/mod.rs`** to register the new transport:

```rust
// Add to imports
#[cfg(feature = "shadowtls-noise")]
pub mod shadowtls_noise;

// In the Transport enum (find existing enum):
pub enum Transport {
    Tcp,
    #[cfg(feature = "noise")]
    Noise,
    #[cfg(feature = "native-tls")]
    Tls,
    #[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
    Websocket,
    #[cfg(feature = "shadowtls-noise")]  // ADD THIS
    ShadowTlsNoise,
}

// In transport type parsing (find existing match):
impl FromStr for Transport {
    type Err = anyhow::Error;
    
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "tcp" => Ok(Transport::Tcp),
            #[cfg(feature = "noise")]
            "noise" => Ok(Transport::Noise),
            #[cfg(feature = "native-tls")]
            "tls" => Ok(Transport::Tls),
            #[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
            "websocket" => Ok(Transport::Websocket),
            #[cfg(feature = "shadowtls-noise")]  // ADD THIS
            "shadowtls_noise" => Ok(Transport::ShadowTlsNoise),
            _ => Err(anyhow!("Unknown transport type: {}", s)),
        }
    }
}
```

---

## Step 5: Modify src/config.rs

Edit **`src/config.rs`** to add ShadowTLS-Noise configuration:

```rust
use serde::{Deserialize, Serialize};

// Find the TransportConfig struct and add:
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    #[serde(rename = "type", default)]
    pub transport_type: String,
    
    // ... existing fields ...
    
    #[cfg(feature = "shadowtls-noise")]
    pub shadowtls_noise: Option<ShadowTlsNoiseConfig>,
}

// Add new config struct
#[cfg(feature = "shadowtls-noise")]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct ShadowTlsNoiseConfig {
    /// Domain to camouflage as (e.g., "www.microsoft.com")
    pub camouflage_domain: String,
    
    /// TLS certificate path (server only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    
    /// TLS key path (server only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    
    /// Noise protocol pattern
    #[serde(default = "default_noise_pattern")]
    pub noise_pattern: String,
    
    /// Local private key (base64, server only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_private_key: Option<String>,
    
    /// Remote public key (base64, client only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_public_key: Option<String>,
}

fn default_noise_pattern() -> String {
    "Noise_NK_25519_ChaChaPoly_BLAKE2s".to_string()
}
```

---

## Step 6: Integrate into Client/Server Code

### Client Side (src/client/mod.rs or similar)

```rust
#[cfg(feature = "shadowtls-noise")]
async fn create_shadowtls_noise_stream(
    config: &ShadowTlsNoiseConfig,
    addr: &str,
) -> Result<impl AsyncRead + AsyncWrite> {
    use crate::transport::shadowtls_noise::{
        ShadowTlsNoiseClientStream,
        ShadowTlsNoiseConfig as StreamConfig,
    };
    
    let stream_config = StreamConfig {
        camouflage_domain: config.camouflage_domain.clone(),
        noise_pattern: config.noise_pattern.clone(),
        noise_local_key: None,
        noise_remote_key: config.remote_public_key.clone(),
    };
    
    ShadowTlsNoiseClientStream::connect(addr, stream_config).await
}
```

### Server Side (src/server/mod.rs or similar)

```rust
#[cfg(feature = "shadowtls-noise")]
async fn accept_shadowtls_noise_stream(
    tcp_stream: TcpStream,
    config: &ShadowTlsNoiseConfig,
) -> Result<impl AsyncRead + AsyncWrite> {
    use crate::transport::shadowtls_noise::{
        ShadowTlsNoiseServerStream,
        ShadowTlsNoiseConfig as StreamConfig,
    };
    use std::sync::Arc;
    use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
    use std::fs;
    
    // Load TLS certificate
    let cert_pem = fs::read_to_string(
        config.tls_cert.as_ref().context("TLS cert required")?
    )?;
    let key_pem = fs::read_to_string(
        config.tls_key.as_ref().context("TLS key required")?
    )?;
    
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())?
        .into_iter()
        .map(Certificate)
        .collect();
    
    let key = PrivateKey(
        rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())?
            .into_iter()
            .next()
            .context("No private key found")?
    );
    
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    let stream_config = StreamConfig {
        camouflage_domain: config.camouflage_domain.clone(),
        noise_pattern: config.noise_pattern.clone(),
        noise_local_key: config.local_private_key.clone(),
        noise_remote_key: None,
    };
    
    ShadowTlsNoiseServerStream::accept(
        tcp_stream,
        stream_config,
        Arc::new(tls_config),
    ).await
}
```

---

## Step 7: Build and Test

### Build:
```bash
# Install Rust if not installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build with ShadowTLS feature
cargo build --release --features shadowtls-noise

# Binary will be in target/release/rathole
```

### Generate Keys:
```bash
# Generate Noise keypair
./target/release/rathole --genkey

# Output:
# Private Key: cQ/vwIqNPJZmuM/OikglzBo/+jlYGrOt9i0k5h5vn1Q=
# Public Key: GQYTKSbWLBUSZiGfdWPSgek9yoOuaiwGD/GIX8Z1kkE=
```

### Get TLS Certificate (Server):
```bash
# Install Certbot
sudo apt install certbot

# Get Let's Encrypt certificate
sudo certbot certonly --standalone -d your-domain.com

# Certificate will be at:
# /etc/letsencrypt/live/your-domain.com/fullchain.pem
# /etc/letsencrypt/live/your-domain.com/privkey.pem
```

### Create Configs:

**Server (Germany):**
```toml
[server]
bind_addr = "0.0.0.0:443"
default_token = "your_secret_token"

[server.transport]
type = "shadowtls_noise"

[server.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
tls_cert = "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/your-domain.com/privkey.pem"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = "YOUR_PRIVATE_KEY_FROM_GENKEY"

[server.services.ssh]
token = "ssh_token"
bind_addr = "0.0.0.0:2222"
```

**Client (Iran):**
```toml
[client]
remote_addr = "your-server.com:443"
default_token = "your_secret_token"

[client.transport]
type = "shadowtls_noise"

[client.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
remote_public_key = "YOUR_PUBLIC_KEY_FROM_GENKEY"

[client.services.ssh]
token = "ssh_token"
local_addr = "127.0.0.1:22"
```

### Run:
```bash
# Server
sudo ./target/release/rathole --server server.toml

# Client
./target/release/rathole --client client.toml
```

---

## Step 8: Verify DPI Evasion

### Capture Traffic:
```bash
# On server
sudo tcpdump -i eth0 -w capture.pcap port 443

# Let tunnel run for 1 minute, then stop tcpdump (Ctrl+C)

# Analyze with Wireshark or tshark
tshark -r capture.pcap -Y tls
```

### What You Should See:
```
1. TLS Client Hello to www.microsoft.com
2. TLS Server Hello with certificate
3. TLS ApplicationData records (encrypted Noise payload)
```

### What DPI Sees:
```
Source: Iran Client
Destination: Your Server IP
SNI: www.microsoft.com
Protocol: TLS 1.2/1.3
Content: HTTPS traffic (legitimate appearance)
```

---

## Step 9: Systemd Service (Production)

**`/etc/systemd/system/rathole-shadowtls.service`:**
```ini
[Unit]
Description=Rathole ShadowTLS Tunnel
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rathole --server /etc/rathole/server.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl enable rathole-shadowtls
sudo systemctl start rathole-shadowtls
sudo systemctl status rathole-shadowtls
```

---

## Troubleshooting

### Issue: TLS Handshake Fails
**Solution:** Check certificate validity:
```bash
openssl s_client -connect your-server.com:443 -servername www.microsoft.com
```

### Issue: Noise Handshake Fails
**Solution:** Verify keys match:
```bash
# Client must have server's public key
# Server must have corresponding private key
```

### Issue: Still Detected by DPI
**Solutions:**
1. Change camouflage_domain to different whitelisted domain
2. Switch to Noise_XX pattern (3-message handshake)
3. Add random timing delays between messages
4. Use port 443 (HTTPS standard port)

---

## Performance Optimization

### Enable BBR Congestion Control:
```bash
echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Tune TCP Settings:
```toml
[client.transport.tcp]
nodelay = true
keepalive_secs = 20
keepalive_interval = 8
```

---

## Alternative: Using Noise_XX Pattern

For maximum stealth, use Noise_XX (3-message handshake = harder to fingerprint):

```toml
[client.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
noise_pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
# No keys needed - authentication during handshake

[server.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
noise_pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
tls_cert = "..."
tls_key = "..."
```

---

## Security Checklist

- [ ] Generated unique Noise keypair (never reuse keys)
- [ ] Valid TLS certificate from Let's Encrypt
- [ ] Strong tokens (32+ random characters)
- [ ] Firewall configured (only port 443 open)
- [ ] Tested traffic capture shows only TLS
- [ ] Systemd service with auto-restart enabled
- [ ] Monitoring/logging configured
- [ ] Regular certificate renewal (certbot renew)

---

## Next Steps

1. Test locally first (localhost tunnel)
2. Deploy to Germany VPS
3. Test from Iran connection
4. Monitor for 24-48 hours
5. If stable, deploy to production

---

## Support

If you encounter issues:
1. Check logs: `journalctl -u rathole-shadowtls -f`
2. Verify TCP connection works: `nc -zv your-server.com 443`
3. Test TLS handshake: `openssl s_client -connect your-server.com:443`
4. Capture and analyze traffic with tcpdump/Wireshark

Good luck! This should successfully evade Iran's DPI. 🚀
