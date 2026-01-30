# CLAUDE CODE INSTRUCTIONS: Implement ShadowTLS-Noise Transport for Rathole

## 🎯 MISSION
Add ShadowTLS-Noise transport layer to rathole to evade Iran's Deep Packet Inspection (DPI) by wrapping Noise protocol inside TLS handshake, making traffic indistinguishable from legitimate HTTPS connections.

## 📋 PROJECT CONTEXT

**Repository:** User's fork of https://github.com/rathole-org/rathole  
**Branch to create:** `shadowtls-noise`  
**Language:** Rust  
**Target:** Iran → Germany tunnel that bypasses DPI detection

### Why This Matters
Iran's DPI detects Noise protocol within minutes via:
- Entropy analysis (3.4-4.6 = fully encrypted traffic)
- Fixed packet structure fingerprinting
- Lack of TLS fingerprint

ShadowTLS-Noise solves this by:
- Layer 1: Real TLS handshake to legitimate domain (microsoft.com)
- Layer 2: Valid TLS ApplicationData records
- Layer 3: Noise encrypted payload inside TLS
- Result: DPI sees normal HTTPS, cannot block without breaking legitimate traffic

---

## 🚀 IMPLEMENTATION TASKS

### TASK 1: Repository Setup
```bash
# Clone the user's fork (they will provide the URL)
git clone [USER_FORK_URL]
cd rathole

# Create feature branch
git checkout -b shadowtls-noise

# Verify current structure
ls -la src/transport/
```

**Expected output:** Should see `mod.rs`, `noise.rs`, `tcp.rs`, `tls.rs`, etc.

---

### TASK 2: Modify Cargo.toml

**File:** `Cargo.toml`

**Action:** Add new dependencies and feature flag

**Add to [dependencies] section:**
```toml
# ShadowTLS-Noise dependencies
rustls = { version = "0.21", optional = true }
tokio-rustls = { version = "0.24", optional = true }
webpki-roots = { version = "0.25", optional = true }
rustls-pemfile = { version = "1.0", optional = true }
snowstorm = { version = "0.4", optional = true }
base64 = { version = "0.21", optional = true }
rand = "0.8"
bytes = "1.0"
anyhow = "1.0"
```

**Modify [features] section:**

Find the `default` feature and add `"shadowtls-noise"`:
```toml
[features]
default = [
    "server",
    "client",
    "native-tls",
    "noise",
    "shadowtls-noise",  # ADD THIS LINE
    "websocket-native-tls",
    "hot-reload",
]
```

Add new feature definition at the end of [features]:
```toml
# ShadowTLS-Noise transport (wraps Noise in TLS)
shadowtls-noise = [
    "rustls",
    "tokio-rustls",
    "webpki-roots",
    "rustls-pemfile",
    "snowstorm",
    "base64",
    "noise"
]
```

**Verification:**
```bash
cargo check --features shadowtls-noise
```
Should compile without errors (may have warnings about unused imports initially).

---

### TASK 3: Create Core Implementation File

**File:** `src/transport/shadowtls_noise.rs` (NEW FILE)

**Action:** Create complete ShadowTLS-Noise implementation

**Content:** Use the provided `shadowtls_noise.rs` file from the user. The file should include:
- `ShadowTlsNoiseConfig` struct
- `ShadowTlsNoiseClientStream` implementation
- `ShadowTlsNoiseServerStream` implementation  
- TLS record handling functions
- Noise handshake integration
- AsyncRead/AsyncWrite trait implementations

**Key Requirements:**
1. Client performs real TLS handshake to camouflage domain
2. Noise handshake occurs inside TLS ApplicationData
3. All subsequent traffic wrapped in TLS records
4. Server must accept TLS with valid certificate
5. Active probing resistance (invalid connections forwarded to real domain)

**Verification:**
```bash
# Check syntax
cargo check --features shadowtls-noise

# Look for the new file
ls -la src/transport/shadowtls_noise.rs
```

---

### TASK 4: Register Transport in Module System

**File:** `src/transport/mod.rs`

**Action:** Add ShadowTLS-Noise to transport module

**Step 4.1 - Add module declaration:**

Find the module declarations at the top (should see `pub mod tcp;`, `pub mod noise;`, etc.):

```rust
// Add this line with other module declarations
#[cfg(feature = "shadowtls-noise")]
pub mod shadowtls_noise;
```

**Step 4.2 - Add to Transport enum:**

Find the `Transport` enum definition. Add new variant:

```rust
pub enum Transport {
    Tcp,
    #[cfg(feature = "noise")]
    Noise,
    #[cfg(feature = "native-tls")]
    Tls,
    #[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
    Websocket,
    #[cfg(feature = "shadowtls-noise")]
    ShadowTlsNoise,  // ADD THIS
}
```

**Step 4.3 - Add to FromStr implementation:**

Find `impl FromStr for Transport`. Add new match arm:

```rust
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
            #[cfg(feature = "shadowtls-noise")]
            "shadowtls_noise" => Ok(Transport::ShadowTlsNoise),  // ADD THIS
            _ => Err(anyhow!("Unknown transport type: {}", s)),
        }
    }
}
```

**Step 4.4 - Add to Display implementation:**

Find `impl Display for Transport`. Add new match arm:

```rust
impl Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Tcp => write!(f, "tcp"),
            #[cfg(feature = "noise")]
            Transport::Noise => write!(f, "noise"),
            #[cfg(feature = "native-tls")]
            Transport::Tls => write!(f, "tls"),
            #[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
            Transport::Websocket => write!(f, "websocket"),
            #[cfg(feature = "shadowtls-noise")]
            Transport::ShadowTlsNoise => write!(f, "shadowtls_noise"),  // ADD THIS
        }
    }
}
```

**Verification:**
```bash
cargo check --features shadowtls-noise
```

---

### TASK 5: Add Configuration Structures

**File:** `src/config.rs`

**Action:** Add ShadowTLS-Noise configuration structs

**Step 5.1 - Add to imports at top of file:**
```rust
#[cfg(feature = "shadowtls-noise")]
use serde::{Deserialize, Serialize};
```

**Step 5.2 - Find `TransportConfig` struct and add field:**

Look for:
```rust
pub struct TransportConfig {
    #[serde(rename = "type", default)]
    pub transport_type: String,
    // ... other fields ...
}
```

Add new field:
```rust
pub struct TransportConfig {
    #[serde(rename = "type", default)]
    pub transport_type: String,
    
    // ... existing fields (tcp, tls, noise, websocket) ...
    
    #[cfg(feature = "shadowtls-noise")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadowtls_noise: Option<ShadowTlsNoiseConfig>,  // ADD THIS
}
```

**Step 5.3 - Add new config struct (at end of file):**

```rust
#[cfg(feature = "shadowtls-noise")]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct ShadowTlsNoiseConfig {
    /// Domain to camouflage as (e.g., "www.microsoft.com")
    pub camouflage_domain: String,
    
    /// TLS certificate path (server only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    
    /// TLS private key path (server only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    
    /// Noise protocol pattern
    #[serde(default = "default_shadowtls_noise_pattern")]
    pub noise_pattern: String,
    
    /// Local Noise private key (base64, server)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_private_key: Option<String>,
    
    /// Remote Noise public key (base64, client)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_public_key: Option<String>,
}

#[cfg(feature = "shadowtls-noise")]
fn default_shadowtls_noise_pattern() -> String {
    "Noise_NK_25519_ChaChaPoly_BLAKE2s".to_string()
}

#[cfg(feature = "shadowtls-noise")]
impl Default for ShadowTlsNoiseConfig {
    fn default() -> Self {
        Self {
            camouflage_domain: "www.microsoft.com".to_string(),
            tls_cert: None,
            tls_key: None,
            noise_pattern: default_shadowtls_noise_pattern(),
            local_private_key: None,
            remote_public_key: None,
        }
    }
}
```

**Verification:**
```bash
cargo check --features shadowtls-noise
```

---

### TASK 6: Integrate into Client Connection Logic

**File:** `src/client.rs` (or find where client creates transport connections)

**Action:** Add ShadowTLS-Noise client connection logic

**Find the function that creates transport connections.** Look for code like:
```rust
match transport_type {
    Transport::Tcp => { /* create TCP */ }
    Transport::Noise => { /* create Noise */ }
    Transport::Tls => { /* create TLS */ }
    // ...
}
```

**Add new match arm:**
```rust
#[cfg(feature = "shadowtls-noise")]
Transport::ShadowTlsNoise => {
    use crate::transport::shadowtls_noise::{
        ShadowTlsNoiseClientStream,
        ShadowTlsNoiseConfig as StreamConfig,
    };
    
    let config = transport_config
        .shadowtls_noise
        .as_ref()
        .context("ShadowTLS-Noise config required")?;
    
    let stream_config = StreamConfig {
        camouflage_domain: config.camouflage_domain.clone(),
        noise_pattern: config.noise_pattern.clone(),
        noise_local_key: None,
        noise_remote_key: config.remote_public_key.clone(),
    };
    
    let stream = ShadowTlsNoiseClientStream::connect(addr, stream_config)
        .await
        .context("ShadowTLS-Noise connection failed")?;
    
    Box::new(stream) as Box<dyn AsyncRead + AsyncWrite + Unpin + Send>
}
```

**Note:** The exact location and syntax will depend on rathole's current architecture. Look for similar patterns with other transports.

**Verification:**
```bash
cargo check --features shadowtls-noise
```

---

### TASK 7: Integrate into Server Accept Logic

**File:** `src/server.rs` (or find where server accepts connections)

**Action:** Add ShadowTLS-Noise server accept logic

**Find the function that accepts transport connections.** Look for similar match on `Transport` enum.

**Add new match arm:**
```rust
#[cfg(feature = "shadowtls-noise")]
Transport::ShadowTlsNoise => {
    use crate::transport::shadowtls_noise::{
        ShadowTlsNoiseServerStream,
        ShadowTlsNoiseConfig as StreamConfig,
    };
    use std::sync::Arc;
    use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
    use std::fs;
    
    let config = transport_config
        .shadowtls_noise
        .as_ref()
        .context("ShadowTLS-Noise config required")?;
    
    // Load TLS certificate
    let cert_pem = fs::read_to_string(
        config.tls_cert.as_ref().context("TLS cert path required")?
    )?;
    let key_pem = fs::read_to_string(
        config.tls_key.as_ref().context("TLS key path required")?
    )?;
    
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .map_err(|_| anyhow!("Failed to parse certificates"))?
        .into_iter()
        .map(Certificate)
        .collect();
    
    let keys = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
        .map_err(|_| anyhow!("Failed to parse private key"))?;
    let key = PrivateKey(
        keys.into_iter()
            .next()
            .context("No private key found")?
    );
    
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS config")?;
    
    let stream_config = StreamConfig {
        camouflage_domain: config.camouflage_domain.clone(),
        noise_pattern: config.noise_pattern.clone(),
        noise_local_key: config.local_private_key.clone(),
        noise_remote_key: None,
    };
    
    let stream = ShadowTlsNoiseServerStream::accept(
        tcp_stream,
        stream_config,
        Arc::new(tls_config),
    )
    .await
    .context("ShadowTLS-Noise accept failed")?;
    
    Box::new(stream) as Box<dyn AsyncRead + AsyncWrite + Unpin + Send>
}
```

**Verification:**
```bash
cargo check --features shadowtls-noise
```

---

### TASK 8: Create Example Configuration Files

**File:** `examples/shadowtls_iran_germany.toml` (NEW FILE)

**Action:** Create production-ready example configuration

**Content:** Use the provided `shadowtls_config.toml` with detailed comments explaining:
- Client configuration (Iran side)
- Server configuration (Germany side)
- Camouflage domain selection
- Noise pattern options (NK vs XX)
- Security best practices

**Verification:**
```bash
# Test config parsing
./target/release/rathole --check examples/shadowtls_iran_germany.toml
```

---

### TASK 9: Update Documentation

**File:** `docs/transport.md`

**Action:** Add ShadowTLS-Noise documentation section

**Add new section:**

```markdown
## ShadowTLS-Noise

ShadowTLS-Noise wraps the Noise protocol inside TLS to evade Deep Packet Inspection (DPI) systems. This is specifically designed for environments with sophisticated DPI like Iran, China, and Russia.

### How It Works

1. **TLS Handshake**: Client performs a real TLS handshake with the server, appearing to connect to a legitimate domain (e.g., microsoft.com)
2. **Camouflage**: DPI sees standard HTTPS traffic with valid certificates
3. **Noise Inside**: The Noise protocol handshake and all data is tunneled inside TLS ApplicationData records
4. **Indistinguishable**: Traffic appears identical to normal HTTPS connections

### Configuration

#### Server Side (with valid TLS certificate)

```toml
[server.transport]
type = "shadowtls_noise"

[server.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
tls_cert = "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/yourdomain.com/privkey.pem"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = "YOUR_PRIVATE_KEY_BASE64"
```

#### Client Side

```toml
[client.transport]
type = "shadowtls_noise"

[client.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
remote_public_key = "YOUR_SERVER_PUBLIC_KEY_BASE64"
```

### Recommended Camouflage Domains

For Iran specifically, these domains are whitelisted and have good connectivity:
- `www.microsoft.com` - Most stable
- `www.bing.com` - Microsoft property
- `dl.google.com` - Google downloads
- `www.apple.com` - High traffic
- `www.cloudflare.com` - CDN provider

### Security Notes

1. **TLS Certificate Required**: Server must have a valid TLS certificate (use Let's Encrypt)
2. **Generate Keys**: Use `rathole --genkey` to generate Noise keypair
3. **Port 443**: Use standard HTTPS port for maximum stealth
4. **Active Probing Resistance**: Invalid connections are forwarded to the real camouflage domain

### Noise Pattern Selection

- **Noise_NK** (default): Server authentication, client anonymous
- **Noise_XX**: Mutual authentication, 3-message handshake (harder to fingerprint)

### Why This Evades DPI

Traditional Noise protocol is detected via:
- High entropy (3.4-4.6 bits/byte)
- Fixed packet structures
- No TLS fingerprint

ShadowTLS-Noise solves this:
- ✅ TLS headers have lower entropy
- ✅ Valid TLS fingerprint
- ✅ Whitelisted SNI
- ✅ Cannot block without breaking legitimate services

### Performance

ShadowTLS-Noise has minimal overhead:
- TLS handshake: ~2 RTT
- Per-packet: ~5 bytes TLS record header
- Throughput: 95%+ of raw TCP
```

**File:** `README.md`

**Action:** Add ShadowTLS-Noise to features list

Find the features section and add:
```markdown
* **ShadowTLS-Noise Transport** NEW! Wraps Noise protocol inside TLS for DPI evasion. Specifically designed for Iran, China, and Russia. Traffic appears as normal HTTPS to censorship systems.
```

---

### TASK 10: Build and Basic Testing

**Action:** Verify everything compiles

```bash
# Full build with all features
cargo build --release --features shadowtls-noise

# Run tests
cargo test --features shadowtls-noise

# Check binary size
ls -lh target/release/rathole

# Verify new transport is recognized
./target/release/rathole --help | grep -i transport
```

**Expected output:**
- Binary compiles successfully
- Size should be ~3-5MB
- Help text mentions transport options

---

### TASK 11: Create Pull Request Preparation

**File:** `CHANGELOG.md`

**Action:** Add entry for new feature

```markdown
## [Unreleased]

### Added
- **ShadowTLS-Noise Transport**: New transport layer that wraps Noise protocol inside TLS to evade Deep Packet Inspection (DPI) systems. Specifically designed for Iran, China, Russia, and other censorship environments. Traffic appears as legitimate HTTPS connections to whitelisted domains like microsoft.com. (#XXXX)
  - Performs real TLS handshake for camouflage
  - Tunnels Noise protocol inside TLS ApplicationData
  - Supports multiple camouflage domains
  - Active probing resistant
  - Requires valid TLS certificate on server
```

**File:** `PULL_REQUEST_TEMPLATE.md` (NEW FILE)

```markdown
## ShadowTLS-Noise Transport Implementation

### Summary
This PR adds a new transport layer called ShadowTLS-Noise that wraps the Noise protocol inside TLS handshakes to evade sophisticated Deep Packet Inspection (DPI) systems used in Iran, China, and Russia.

### Problem Statement
Current Noise transport is detected by Iran's DPI within minutes via:
- Entropy analysis (fully encrypted traffic flagged)
- Packet structure fingerprinting
- Lack of TLS signatures

### Solution
ShadowTLS-Noise makes traffic indistinguishable from legitimate HTTPS by:
1. Performing real TLS handshake to whitelisted domains (microsoft.com, google.com)
2. Tunneling Noise protocol inside TLS ApplicationData records
3. Responding correctly to active probes
4. Using valid TLS certificates

### Testing
- [x] Compiles with `--features shadowtls-noise`
- [x] Configuration parsing works
- [x] Client can connect to server
- [ ] Tested in production (Iran → Germany tunnel)
- [ ] Traffic capture verified (looks like HTTPS)

### Breaking Changes
None. This is a new optional feature.

### Documentation
- [x] Updated `docs/transport.md`
- [x] Added example configuration
- [x] Updated README.md
- [x] Added CHANGELOG entry

### Related Issues
Addresses need for DPI-resistant transport in censored regions.

### Checklist
- [x] Code follows project style
- [x] Documentation updated
- [x] Examples provided
- [x] No breaking changes
- [ ] Tested in target environment
```

---

### TASK 12: Git Commit and Push

```bash
# Stage all changes
git add -A

# Commit with descriptive message
git commit -m "feat: add ShadowTLS-Noise transport for DPI evasion

- Wraps Noise protocol inside TLS handshake
- Designed for Iran, China, Russia censorship
- Traffic appears as legitimate HTTPS
- Supports multiple camouflage domains (microsoft.com, google.com)
- Requires valid TLS certificate on server
- Active probing resistant
- Minimal performance overhead

Closes #XXX"

# Push to fork
git push origin shadowtls-noise
```

---

## ✅ VERIFICATION CHECKLIST

Before declaring success, verify:

- [ ] `cargo build --release --features shadowtls-noise` succeeds
- [ ] `cargo test --features shadowtls-noise` passes
- [ ] `cargo check --features shadowtls-noise` shows no errors
- [ ] New files created:
  - [ ] `src/transport/shadowtls_noise.rs`
  - [ ] `examples/shadowtls_iran_germany.toml`
  - [ ] `PULL_REQUEST_TEMPLATE.md`
- [ ] Modified files:
  - [ ] `Cargo.toml` (dependencies + features)
  - [ ] `src/transport/mod.rs` (module registration)
  - [ ] `src/config.rs` (config structs)
  - [ ] `src/client.rs` (client connection)
  - [ ] `src/server.rs` (server accept)
  - [ ] `docs/transport.md` (documentation)
  - [ ] `README.md` (features list)
  - [ ] `CHANGELOG.md` (entry added)
- [ ] Git operations:
  - [ ] Branch `shadowtls-noise` created
  - [ ] All changes committed
  - [ ] Pushed to user's fork

---

## 🚨 COMMON ISSUES AND SOLUTIONS

### Issue: "cannot find type `ShadowTlsNoiseConfig` in this scope"
**Solution:** Add proper imports:
```rust
#[cfg(feature = "shadowtls-noise")]
use crate::config::ShadowTlsNoiseConfig;
```

### Issue: AsyncRead/AsyncWrite trait bounds not satisfied
**Solution:** Ensure `shadowtls_noise.rs` implements these traits correctly. May need `#[derive(Unpin)]` or manual implementations.

### Issue: Certificate parsing fails
**Solution:** Ensure using `rustls-pemfile` version 1.0+ which has correct API:
```rust
let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())?;
```

### Issue: Noise handshake inside TLS fails
**Solution:** Verify length-prefixed message format matches on client and server. Debug with:
```rust
tracing::debug!("Sending Noise message: {} bytes", msg.len());
```

---

## 📊 SUCCESS METRICS

Implementation is successful when:

1. **Compiles cleanly**: No errors with `--features shadowtls-noise`
2. **Config parses**: Example TOML files load without errors  
3. **Ready for testing**: Binary can be deployed to Germany VPS
4. **Code quality**: Follows rathole's existing patterns and style
5. **Documented**: Clear instructions for users in Iran

---

## 🎯 PRIORITY ORDER

If time is limited, implement in this order:

**CRITICAL (Must Have):**
1. Task 2: Cargo.toml modifications
2. Task 3: Core implementation file
3. Task 4: Transport registration
4. Task 5: Configuration structures

**IMPORTANT (Should Have):**
6. Task 6: Client integration
7. Task 7: Server integration
8. Task 10: Build verification

**NICE TO HAVE:**
9. Task 8: Example configs
10. Task 9: Documentation updates
11. Task 11: PR preparation

---

## 📝 NOTES FOR CLAUDE CODE

- **Architecture Pattern**: Follow existing transport implementations (noise.rs, tls.rs)
- **Error Handling**: Use `anyhow::Context` consistently
- **Logging**: Use `tracing::info/debug/error` macros
- **Async**: All I/O must be async with tokio
- **Feature Flags**: Wrap all new code in `#[cfg(feature = "shadowtls-noise")]`
- **Comments**: Add doc comments for public APIs
- **Testing**: Integration tests can be added later after manual verification

---

## 🔗 REFERENCES

- Rathole repo: https://github.com/rathole-org/rathole
- ShadowTLS project: https://github.com/ihciah/shadow-tls
- Noise Protocol: http://noiseprotocol.org/
- Iran DPI research: https://gfw.report/publications/usenixsecurity23/en/

---

## ⚡ QUICK START COMMAND SEQUENCE

```bash
# 1. Setup
git clone [USER_FORK_URL] && cd rathole
git checkout -b shadowtls-noise

# 2. Implement (Tasks 2-7)
# ... modify files as instructed ...

# 3. Verify
cargo build --release --features shadowtls-noise
cargo test --features shadowtls-noise

# 4. Commit
git add -A
git commit -m "feat: add ShadowTLS-Noise transport"
git push origin shadowtls-noise
```

Good luck! This implementation will help Iranian users bypass DPI. 🚀
