# README.md - ShadowTLS-Noise Implementation Package for Claude Code

## 📦 Package Contents

This package contains everything needed for **Claude Code** to implement ShadowTLS-Noise transport in rathole, enabling DPI evasion for Iran-Germany tunnels.

---

## 🎯 Mission

Implement ShadowTLS-Noise transport layer that wraps Noise protocol inside TLS, making tunnel traffic indistinguishable from legitimate HTTPS connections to bypass Iran's Deep Packet Inspection (DPI).

---

## 📂 Files in This Package

### For Claude Code (Primary Instructions)
1. **CLAUDE_CODE_INSTRUCTIONS.md** ⭐ 
   - **START HERE**: Complete step-by-step implementation guide
   - All tasks numbered and sequenced
   - Verification steps after each task
   - Success criteria clearly defined

### Implementation Files
2. **shadowtls_noise.rs**
   - Core Rust implementation (950 lines)
   - Client and server stream handlers
   - TLS wrapper logic
   - Noise protocol integration
   - Place in: `src/transport/shadowtls_noise.rs`

3. **shadowtls_config.toml**
   - Production-ready configuration examples
   - Client (Iran) and Server (Germany) configs
   - Extensive comments and best practices
   - Place in: `examples/shadowtls_iran_germany.toml`

### Testing & Deployment
4. **TESTING_GUIDE.md**
   - Comprehensive testing strategy (7 phases)
   - Localhost integration tests
   - Traffic analysis validation
   - Performance benchmarks
   - Use after implementation complete

5. **DEPLOYMENT_GUIDE.md**
   - Production deployment for Iran → Germany
   - VPS setup (Germany)
   - Client setup (Iran)
   - Monitoring and maintenance
   - Troubleshooting guide
   - Use for real-world deployment

6. **QUICK_REFERENCE.md**
   - Cheat sheet for common tasks
   - Quick commands
   - Config templates
   - Debugging tips
   - Emergency procedures
   - Use as daily reference

7. **IMPLEMENTATION_GUIDE.md**
   - Detailed technical explanation
   - Manual implementation steps (if not using Claude Code)
   - Build instructions
   - Integration patterns

---

## 🚀 Quick Start for Claude Code

### Step 1: Read Instructions
```bash
# Claude Code should start by reading:
cat CLAUDE_CODE_INSTRUCTIONS.md
```

This file contains **all tasks in order** with:
- ✅ Exact code changes needed
- ✅ File locations
- ✅ Verification commands
- ✅ Success criteria

### Step 2: Get Repository URL
Claude Code needs the user's fork URL:
```
User should provide: https://github.com/USERNAME/rathole.git
```

### Step 3: Execute Tasks
Follow **CLAUDE_CODE_INSTRUCTIONS.md** tasks 1-12 sequentially:

1. Repository setup
2. Modify Cargo.toml
3. Create shadowtls_noise.rs
4. Register transport in mod.rs
5. Add config structures
6. Integrate client logic
7. Integrate server logic
8. Create examples
9. Update documentation
10. Build and test
11. Prepare PR
12. Commit and push

### Step 4: Validate
Use **TESTING_GUIDE.md** to validate implementation.

### Step 5: Deploy (Optional)
Use **DEPLOYMENT_GUIDE.md** if deploying to production.

---

## 🎯 Success Criteria

Implementation is complete when:

### Compilation
- ✅ `cargo build --release --features shadowtls-noise` succeeds
- ✅ No compilation errors
- ✅ Binary created at `target/release/rathole`

### Files Created/Modified
- ✅ `src/transport/shadowtls_noise.rs` (new)
- ✅ `Cargo.toml` (dependencies + feature)
- ✅ `src/transport/mod.rs` (transport registration)
- ✅ `src/config.rs` (config structs)
- ✅ `src/client.rs` (client integration)
- ✅ `src/server.rs` (server integration)
- ✅ `examples/shadowtls_iran_germany.toml` (new)
- ✅ `docs/transport.md` (documentation)

### Testing
- ✅ Config files parse without errors
- ✅ Localhost test connects successfully
- ✅ Traffic capture shows TLS wrapper
- ✅ No panics or crashes

### Git
- ✅ Branch `shadowtls-noise` created
- ✅ All changes committed
- ✅ Pushed to user's fork

---

## 📋 Implementation Checklist for Claude Code

Use this to track progress:

### Core Implementation
- [ ] Task 1: Repository setup
- [ ] Task 2: Cargo.toml modifications
- [ ] Task 3: Create shadowtls_noise.rs
- [ ] Task 4: Register in mod.rs
- [ ] Task 5: Add config structs
- [ ] Task 6: Client integration
- [ ] Task 7: Server integration

### Documentation & Testing
- [ ] Task 8: Example configs
- [ ] Task 9: Update docs
- [ ] Task 10: Build verification

### Finalization
- [ ] Task 11: PR preparation
- [ ] Task 12: Git operations
- [ ] Validation: All tests pass
- [ ] Ready for user review

---

## 🧩 Architecture Overview

### How ShadowTLS-Noise Works

```
Iran Client                              Germany VPS
    │                                         │
    ├─[1]─TLS ClientHello───────────────────►│
    │     (SNI: microsoft.com)                │
    │                                         │
    │◄────[2]─TLS ServerHello─────────────────┤
    │     (Valid certificate)                 │
    │                                         │
    ├─[3]─TLS ApplicationData────────────────►│
    │     ┌──────────────────┐                │
    │     │ Noise Handshake  │                │
    │     └──────────────────┘                │
    │                                         │
    ├─[4]─TLS ApplicationData────────────────►│
    │◄───[5]─TLS ApplicationData───────────────┤
    │     ┌──────────────────┐                │
    │     │ Encrypted Data   │                │
    │     └──────────────────┘                │
```

**DPI sees:** Normal HTTPS to microsoft.com  
**Actually:** Encrypted Noise tunnel

### Key Components

1. **TLS Wrapper** (`shadowtls_noise.rs`)
   - Performs real TLS handshake
   - Wraps Noise in ApplicationData
   - Maintains TLS session

2. **Noise Protocol** (snowstorm crate)
   - End-to-end encryption
   - Pattern: NK or XX
   - Key exchange + authentication

3. **Configuration** (`config.rs`)
   - Camouflage domain setting
   - TLS certificate paths
   - Noise keys configuration

4. **Transport Integration** (`client.rs`, `server.rs`)
   - Creates ShadowTLS streams
   - Manages connections
   - Error handling

---

## 🔍 File Responsibilities

### shadowtls_noise.rs (Core Logic)
- `ShadowTlsNoiseConfig`: Configuration structure
- `ShadowTlsNoiseClientStream`: Client-side connection
- `ShadowTlsNoiseServerStream`: Server-side connection
- `write_tls_record()`: Wraps data in TLS format
- `read_tls_record()`: Unwraps TLS records
- `perform_noise_*_handshake()`: Noise protocol setup

### Cargo.toml (Dependencies)
- `rustls`: TLS implementation
- `tokio-rustls`: Async TLS for tokio
- `webpki-roots`: Root certificates
- `snowstorm`: Noise protocol
- `base64`: Key encoding

### config.rs (Configuration)
- `ShadowTlsNoiseConfig`: Transport settings
- `TransportConfig`: Add shadowtls_noise field
- Validation logic

### transport/mod.rs (Registration)
- `Transport` enum: Add `ShadowTlsNoise` variant
- `FromStr`: Parse "shadowtls_noise" string
- Export module

---

## 🚨 Critical Notes for Claude Code

### Must Follow
1. **Feature Flags**: Wrap ALL new code in `#[cfg(feature = "shadowtls-noise")]`
2. **Error Handling**: Use `anyhow::Context` for all errors
3. **Logging**: Use `tracing::info/debug/error` macros
4. **Async**: All I/O must be async with tokio
5. **Style**: Follow existing rathole code patterns

### Common Pitfalls
- ❌ Forgetting to add module to `mod.rs`
- ❌ Missing feature flag in `Cargo.toml`
- ❌ Incorrect AsyncRead/AsyncWrite implementation
- ❌ Certificate path errors (test with self-signed first)
- ❌ Noise key format issues (must be base64)

### Testing Before Commit
```bash
# MUST pass all these:
cargo check --features shadowtls-noise
cargo build --release --features shadowtls-noise
cargo clippy --features shadowtls-noise
cargo test --features shadowtls-noise
```

---

## 📖 Additional Resources

### For Understanding
- **Noise Protocol Spec**: http://noiseprotocol.org/
- **TLS 1.3 RFC**: https://www.rfc-editor.org/rfc/rfc8446
- **Iran DPI Research**: https://gfw.report/publications/usenixsecurity23/en/
- **ShadowTLS Project**: https://github.com/ihciah/shadow-tls

### For Implementation
- **Rathole Existing Code**: Study `src/transport/noise.rs` and `src/transport/tls.rs`
- **Rustls Examples**: https://github.com/rustls/rustls/tree/main/examples
- **Tokio Docs**: https://tokio.rs/

---

## 🆘 Getting Help

### If Implementation Fails

1. **Check CLAUDE_CODE_INSTRUCTIONS.md** - Specific task having issues?
2. **Review Error Message** - Usually indicates missing dependency or typo
3. **Compare with Similar Files** - Look at `noise.rs`, `tls.rs` for patterns
4. **Test Incrementally** - Verify each task before moving to next

### Common Issues and Solutions

**"Cannot find type X"**
```rust
// Add import at top of file
use crate::transport::shadowtls_noise::X;
```

**"Feature shadowtls-noise not found"**
```toml
# Check [features] in Cargo.toml includes it
shadowtls-noise = ["rustls", "tokio-rustls", ...]
```

**"Failed to parse certificate"**
```rust
// Use rustls-pemfile 1.0+ API
let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())?;
```

---

## 🎯 Expected Timeline

For Claude Code:
- **Core Implementation**: 1-2 hours
- **Testing**: 30 minutes
- **Documentation**: 30 minutes
- **Total**: 2-3 hours

For manual implementation by user:
- **Core Implementation**: 4-6 hours
- **Testing**: 1-2 hours
- **Documentation**: 1 hour
- **Total**: 6-9 hours

---

## ✅ Final Validation

Before declaring success:

```bash
# 1. Compiles cleanly
cargo build --release --features shadowtls-noise
# ✅ Exit code 0, binary created

# 2. Tests pass
cargo test --features shadowtls-noise
# ✅ All tests green

# 3. Example config works
./target/release/rathole --check examples/shadowtls_iran_germany.toml
# ✅ Config valid

# 4. Git clean
git status
# ✅ All changes committed

# 5. Ready for PR
git push origin shadowtls-noise
# ✅ Branch pushed
```

---

## 🎉 After Implementation

### What User Should Do

1. **Review Code**: Check all changes make sense
2. **Test Locally**: Run localhost test (TESTING_GUIDE.md Phase 3)
3. **Deploy to VPS**: Follow DEPLOYMENT_GUIDE.md
4. **Test from Iran**: Verify DPI evasion works
5. **Submit PR**: To upstream rathole (optional)
6. **Share Success**: Help others in Iran benefit

### What This Enables

- ✅ Secure tunnel through Iran's DPI
- ✅ SSH access to Iran machines
- ✅ HTTP/HTTPS proxying
- ✅ Any TCP service tunneling
- ✅ Censorship circumvention
- ✅ Private communication

---

## 🌟 Impact

This implementation helps:
- **Iranian users** bypass censorship
- **Journalists** communicate securely
- **Activists** access free internet
- **Developers** work remotely
- **Families** stay connected

**This is important work. Take your time. Test thoroughly. Lives depend on it.** 🛡️

---

## 📬 Support

**For Claude Code:**
- Follow CLAUDE_CODE_INSTRUCTIONS.md sequentially
- Verify each task before proceeding
- Use TESTING_GUIDE.md for validation

**For Users:**
- Use QUICK_REFERENCE.md for daily operations
- Use DEPLOYMENT_GUIDE.md for production setup
- Use TESTING_GUIDE.md for troubleshooting

---

## 📜 License

This implementation follows rathole's Apache-2.0 license.

---

## 🙏 Credits

- **Rathole Project**: https://github.com/rathole-org/rathole
- **ShadowTLS**: Inspiration for TLS wrapping technique
- **Noise Protocol**: Trevor Perrin and collaborators
- **Iran DPI Research**: GFW Report team

---

**Let's build something that matters. 🚀**
