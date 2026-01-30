# TESTING_GUIDE.md - ShadowTLS-Noise Validation

## 🧪 Testing Strategy

This guide helps validate the ShadowTLS-Noise implementation at multiple levels.

---

## PHASE 1: Compilation Testing

### Test 1.1: Feature Flag Compilation
```bash
# Build with shadowtls-noise feature
cargo build --release --features shadowtls-noise

# Expected: Successful compilation, no errors
# Binary location: target/release/rathole
```

**Success Criteria:**
- ✅ Exit code 0
- ✅ Binary created
- ✅ No compilation errors
- ⚠️ Warnings are acceptable if they're just unused imports

### Test 1.2: Feature Isolation
```bash
# Build without shadowtls-noise (should still work)
cargo build --release --no-default-features --features server,client,noise

# Expected: Compiles without shadowtls-noise code
```

**Success Criteria:**
- ✅ Compiles successfully
- ✅ Binary size smaller (no TLS/rustls dependencies)

### Test 1.3: Clippy Linting
```bash
cargo clippy --features shadowtls-noise -- -D warnings

# Expected: No warnings or errors
```

**Success Criteria:**
- ✅ No clippy warnings
- ✅ Code follows Rust best practices

---

## PHASE 2: Configuration Parsing Testing

### Test 2.1: Client Config Parsing
Create `test_client.toml`:
```toml
[client]
remote_addr = "test.example.com:443"
default_token = "test_token"

[client.transport]
type = "shadowtls_noise"

[client.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
remote_public_key = "YmFzZTY0X3B1YmtleV9oZXJl"

[client.services.test]
token = "service_token"
local_addr = "127.0.0.1:8080"
```

Test parsing:
```bash
./target/release/rathole --client test_client.toml --dry-run

# Expected: Config loads without errors
```

**Success Criteria:**
- ✅ No parsing errors
- ✅ Transport type recognized as "shadowtls_noise"
- ✅ All config fields present

### Test 2.2: Server Config Parsing
Create `test_server.toml`:
```toml
[server]
bind_addr = "0.0.0.0:443"
default_token = "test_token"

[server.transport]
type = "shadowtls_noise"

[server.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
tls_cert = "/path/to/cert.pem"
tls_key = "/path/to/key.pem"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = "YmFzZTY0X3ByaXZrZXlfaGVyZQ=="

[server.services.test]
token = "service_token"
bind_addr = "0.0.0.0:8080"
```

Test:
```bash
./target/release/rathole --server test_server.toml --dry-run
```

**Success Criteria:**
- ✅ Config loads successfully
- ✅ TLS paths recognized
- ✅ Noise keys parsed

### Test 2.3: Invalid Config Detection
Create `test_invalid.toml`:
```toml
[client]
remote_addr = "test.example.com:443"

[client.transport]
type = "shadowtls_noise"

# Missing required shadowtls_noise config block
```

Test:
```bash
./target/release/rathole --client test_invalid.toml 2>&1 | grep -i "error"

# Expected: Clear error about missing config
```

**Success Criteria:**
- ✅ Exits with error
- ✅ Error message mentions missing config
- ✅ Error is descriptive

---

## PHASE 3: Localhost Integration Testing

### Test 3.1: Generate Test Certificates

**Create self-signed cert for localhost testing:**
```bash
# Generate private key
openssl genrsa -out test_key.pem 2048

# Generate certificate
openssl req -new -x509 -key test_key.pem -out test_cert.pem -days 365 \
  -subj "/CN=localhost"

# Verify
openssl x509 -in test_cert.pem -text -noout
```

### Test 3.2: Generate Noise Keypair
```bash
# Generate keys
./target/release/rathole --genkey > test_keys.txt

# Extract keys
PRIVATE_KEY=$(grep "Private Key:" test_keys.txt | cut -d' ' -f3)
PUBLIC_KEY=$(grep "Public Key:" test_keys.txt | cut -d' ' -f3)

echo "Private: $PRIVATE_KEY"
echo "Public: $PUBLIC_KEY"
```

### Test 3.3: Localhost Server
Create `localhost_server.toml`:
```toml
[server]
bind_addr = "127.0.0.1:8443"
default_token = "test_token_12345"

[server.transport]
type = "shadowtls_noise"

[server.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
tls_cert = "test_cert.pem"
tls_key = "test_key.pem"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = "PASTE_PRIVATE_KEY_HERE"

[server.services.echo]
token = "echo_token"
bind_addr = "127.0.0.1:9000"
```

Start server:
```bash
RUST_LOG=debug ./target/release/rathole --server localhost_server.toml
```

**Expected logs:**
```
INFO rathole: Starting server
INFO rathole::server: Listening on 127.0.0.1:8443
INFO rathole::transport: Using ShadowTLS-Noise transport
DEBUG shadowtls_noise: TLS config loaded
```

### Test 3.4: Localhost Client
Create `localhost_client.toml`:
```toml
[client]
remote_addr = "127.0.0.1:8443"
default_token = "test_token_12345"

[client.transport]
type = "shadowtls_noise"

[client.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
remote_public_key = "PASTE_PUBLIC_KEY_HERE"

[client.services.echo]
token = "echo_token"
local_addr = "127.0.0.1:8080"
```

Start client (in new terminal):
```bash
RUST_LOG=debug ./target/release/rathole --client localhost_client.toml
```

**Expected logs:**
```
INFO rathole: Starting client
INFO rathole::client: Connecting to 127.0.0.1:8443
INFO shadowtls_noise: ShadowTLS-Noise: Connecting
DEBUG shadowtls_noise: TLS handshake complete
DEBUG shadowtls_noise: Noise handshake complete
INFO rathole::client: Connected successfully
```

### Test 3.5: Data Transfer Test
```bash
# Start simple echo server on port 8080 (what client will forward)
nc -l 8080

# In another terminal, connect through tunnel
nc 127.0.0.1 9000

# Type messages and verify they echo through the tunnel
```

**Success Criteria:**
- ✅ Server accepts connection
- ✅ Client connects successfully  
- ✅ TLS handshake completes
- ✅ Noise handshake completes
- ✅ Data flows through tunnel
- ✅ Messages echo correctly

---

## PHASE 4: Network Traffic Validation

### Test 4.1: Capture Traffic
```bash
# Start tcpdump (requires sudo)
sudo tcpdump -i lo -w shadowtls_test.pcap port 8443 &

# Run client/server test (from Test 3.5)
# Let it run for 30 seconds with some data transfer

# Stop tcpdump
sudo killall tcpdump
```

### Test 4.2: Analyze with tshark
```bash
# Verify TLS handshake present
tshark -r shadowtls_test.pcap -Y "ssl.handshake"

# Expected output: ClientHello, ServerHello, Certificate, etc.
```

**Success Criteria:**
- ✅ See TLS ClientHello
- ✅ See TLS ServerHello
- ✅ See Certificate exchange
- ✅ See TLS ApplicationData records
- ❌ Should NOT see raw Noise protocol headers

### Test 4.3: Verify TLS Record Structure
```bash
# Check TLS record format
tshark -r shadowtls_test.pcap -Y "ssl" -T fields \
  -e frame.number \
  -e ssl.record.content_type \
  -e ssl.record.version \
  -e ssl.record.length
```

**Expected output:**
```
1    22    0x0303    XXX     # Handshake
2    22    0x0303    XXX     # Handshake
3    23    0x0303    XXX     # ApplicationData (Noise inside)
4    23    0x0303    XXX     # ApplicationData
...
```

**Success Criteria:**
- ✅ Content type 23 (ApplicationData) for encrypted traffic
- ✅ Version 0x0303 (TLS 1.2)
- ✅ Variable record lengths
- ✅ Proper TLS record structure

### Test 4.4: Entropy Analysis
```bash
# Extract ApplicationData payload
tshark -r shadowtls_test.pcap -Y "ssl.record.content_type == 23" \
  -T fields -e data | xxd -r -p > payload.bin

# Calculate entropy (Python)
python3 << 'EOF'
import math
from collections import Counter

with open('payload.bin', 'rb') as f:
    data = f.read()

freq = Counter(data)
entropy = -sum((count/len(data)) * math.log2(count/len(data)) 
               for count in freq.values())
print(f"Entropy: {entropy:.2f} bits/byte")

# TLS headers should lower overall entropy to ~3.0-3.5
# Pure Noise would be 3.8-4.0
EOF
```

**Success Criteria:**
- ✅ Entropy < 3.5 bits/byte (TLS headers reduce it)
- ✅ Lower than pure Noise protocol (~4.0)

---

## PHASE 5: Error Handling Tests

### Test 5.1: Wrong Noise Keys
Modify client config with wrong public key:
```toml
remote_public_key = "d3JvbmdfcHVibGljX2tleQ=="
```

```bash
./target/release/rathole --client localhost_client.toml 2>&1 | grep -i "error"
```

**Success Criteria:**
- ✅ Connection fails gracefully
- ✅ Error message about handshake failure
- ✅ No panic/crash

### Test 5.2: Missing TLS Certificate
```bash
rm test_cert.pem
./target/release/rathole --server localhost_server.toml
```

**Success Criteria:**
- ✅ Exits with clear error
- ✅ Mentions missing certificate file
- ✅ No cryptic errors

### Test 5.3: Invalid Camouflage Domain
Modify config:
```toml
camouflage_domain = "invalid-domain-12345.com"
```

```bash
./target/release/rathole --client localhost_client.toml
```

**Success Criteria:**
- ✅ Handles DNS resolution failure gracefully
- ⚠️ May timeout but should not crash

### Test 5.4: Port Already in Use
```bash
# Start first server
./target/release/rathole --server localhost_server.toml &

# Try to start second server on same port
./target/release/rathole --server localhost_server.toml
```

**Success Criteria:**
- ✅ Second server exits with "address in use" error
- ✅ First server keeps running

---

## PHASE 6: Performance Testing

### Test 6.1: Throughput Test
```bash
# Start tunnel
./target/release/rathole --server localhost_server.toml &
./target/release/rathole --client localhost_client.toml &

# Use iperf3 through tunnel
# Terminal 1: iperf server on forwarded port
iperf3 -s -p 8080

# Terminal 2: iperf client to tunnel
iperf3 -c 127.0.0.1 -p 9000 -t 30

# Expected: > 500 Mbps on localhost
```

**Success Criteria:**
- ✅ Throughput > 500 Mbps (localhost)
- ✅ Overhead < 10% vs raw TCP
- ✅ No connection drops

### Test 6.2: Latency Test
```bash
# Ping through tunnel
# Terminal 1: Start socat echo server
socat TCP-LISTEN:8080,reuseaddr EXEC:'/bin/cat'

# Terminal 2: Measure round-trip time
time echo "test" | nc 127.0.0.1 9000
```

**Success Criteria:**
- ✅ Latency < 5ms (localhost)
- ✅ Consistent response times

### Test 6.3: Memory Usage
```bash
# Monitor memory
./target/release/rathole --server localhost_server.toml &
SERVER_PID=$!

# Measure
ps aux | grep $SERVER_PID | awk '{print $6}'
# Expected: < 50MB RSS
```

**Success Criteria:**
- ✅ RSS < 50MB for idle server
- ✅ No memory leaks over time

---

## PHASE 7: Real-World Testing Prep

### Test 7.1: Generate Production Configs

**Server (Germany VPS):**
```bash
# Generate Noise keys
./rathole --genkey

# Get Let's Encrypt cert
sudo certbot certonly --standalone -d your-domain.com

# Create config with real values
cat > production_server.toml << 'EOF'
[server]
bind_addr = "0.0.0.0:443"
default_token = "REPLACE_WITH_STRONG_TOKEN"

[server.transport]
type = "shadowtls_noise"

[server.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
tls_cert = "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/your-domain.com/privkey.pem"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = "PASTE_PRIVATE_KEY"

[server.services.ssh]
token = "ssh_service_token"
bind_addr = "0.0.0.0:2222"
EOF
```

**Client (Iran):**
```bash
cat > production_client.toml << 'EOF'
[client]
remote_addr = "your-domain.com:443"
default_token = "SAME_STRONG_TOKEN"

[client.transport]
type = "shadowtls_noise"

[client.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
remote_public_key = "PASTE_PUBLIC_KEY"

[client.services.ssh]
token = "ssh_service_token"
local_addr = "127.0.0.1:22"
EOF
```

### Test 7.2: Dry Run
```bash
# Test configs without starting
./rathole --server production_server.toml --dry-run
./rathole --client production_client.toml --dry-run
```

**Success Criteria:**
- ✅ Both configs parse successfully
- ✅ No warnings about missing fields
- ✅ Ready for deployment

---

## 🎯 TESTING CHECKLIST

Mark each test as you complete it:

### Compilation
- [ ] Test 1.1: Feature flag compilation
- [ ] Test 1.2: Feature isolation
- [ ] Test 1.3: Clippy linting

### Configuration
- [ ] Test 2.1: Client config parsing
- [ ] Test 2.2: Server config parsing
- [ ] Test 2.3: Invalid config detection

### Integration
- [ ] Test 3.1: Generate test certificates
- [ ] Test 3.2: Generate Noise keypair
- [ ] Test 3.3: Localhost server
- [ ] Test 3.4: Localhost client
- [ ] Test 3.5: Data transfer test

### Traffic Analysis
- [ ] Test 4.1: Capture traffic
- [ ] Test 4.2: Analyze with tshark
- [ ] Test 4.3: Verify TLS record structure
- [ ] Test 4.4: Entropy analysis

### Error Handling
- [ ] Test 5.1: Wrong Noise keys
- [ ] Test 5.2: Missing TLS certificate
- [ ] Test 5.3: Invalid camouflage domain
- [ ] Test 5.4: Port already in use

### Performance
- [ ] Test 6.1: Throughput test
- [ ] Test 6.2: Latency test
- [ ] Test 6.3: Memory usage

### Production Prep
- [ ] Test 7.1: Generate production configs
- [ ] Test 7.2: Dry run

---

## 📊 TEST RESULTS TEMPLATE

Use this template to document results:

```markdown
## Test Results - ShadowTLS-Noise Implementation

**Date:** YYYY-MM-DD
**Tester:** Your Name
**Branch:** shadowtls-noise
**Commit:** [commit hash]

### Summary
- Total Tests: X
- Passed: X
- Failed: X
- Skipped: X

### Phase 1: Compilation
- [PASS/FAIL] Feature flag compilation
- [PASS/FAIL] Feature isolation
- [PASS/FAIL] Clippy linting

### Phase 2: Configuration
- [PASS/FAIL] Client config parsing
- [PASS/FAIL] Server config parsing
- [PASS/FAIL] Invalid config detection

### Phase 3: Integration
- [PASS/FAIL] Localhost server
- [PASS/FAIL] Localhost client
- [PASS/FAIL] Data transfer
  - Throughput: XXX Mbps
  - Latency: XXX ms

### Phase 4: Traffic Analysis
- [PASS/FAIL] TLS handshake verified
- [PASS/FAIL] Proper record structure
- [PASS/FAIL] Entropy analysis
  - Measured entropy: X.XX bits/byte

### Phase 5: Error Handling
- [PASS/FAIL] All error cases handled gracefully

### Phase 6: Performance
- Throughput: XXX Mbps
- Latency: XXX ms
- Memory: XXX MB

### Issues Found
1. [Issue description]
2. [Issue description]

### Recommendations
- [Recommendation]
- [Recommendation]

### Ready for Production?
[YES/NO] - Reason
```

---

## 🚨 FAILURE CRITERIA

Implementation should be considered incomplete if:

- ❌ Doesn't compile with `--features shadowtls-noise`
- ❌ Localhost test fails to establish connection
- ❌ Traffic capture shows non-TLS traffic
- ❌ Entropy > 4.0 bits/byte (no TLS benefit)
- ❌ Panics or crashes on error conditions
- ❌ Memory leaks detected

---

## ✅ SUCCESS CRITERIA

Implementation is production-ready when:

- ✅ All Phase 1-5 tests pass
- ✅ Phase 6 performance acceptable (>500 Mbps, <10ms)
- ✅ Traffic capture confirms TLS wrapper
- ✅ Entropy reduced compared to plain Noise
- ✅ Error handling is graceful
- ✅ No memory leaks
- ✅ Production configs validated

---

## 📝 NOTES

- **Testing Environment**: Tests assume localhost. Real DPI testing requires deployment in Iran.
- **Certificates**: Self-signed certs work for testing, but production REQUIRES Let's Encrypt.
- **Performance**: Localhost performance won't match WAN performance. Expect 10-50 Mbps over internet.
- **DPI Evasion**: Cannot fully test without actual Iran connection. Traffic analysis is best proxy.

Good luck with testing! 🧪
