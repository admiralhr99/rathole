# QUICK_REFERENCE.md - ShadowTLS-Noise Cheat Sheet

## 🚀 Quick Commands

### Build
```bash
# Full build with feature
cargo build --release --features shadowtls-noise

# Check compilation
cargo check --features shadowtls-noise

# Run tests
cargo test --features shadowtls-noise
```

### Key Generation
```bash
# Generate Noise keypair
./rathole --genkey

# Output format:
# Private Key: <base64_string>  → Goes to SERVER
# Public Key: <base64_string>   → Goes to CLIENT
```

### Certificate (Server Only)
```bash
# Get Let's Encrypt certificate
sudo certbot certonly --standalone -d your-domain.com

# Paths:
# Cert: /etc/letsencrypt/live/your-domain.com/fullchain.pem
# Key:  /etc/letsencrypt/live/your-domain.com/privkey.pem
```

### Run
```bash
# Server
./rathole --server server.toml

# Client
./rathole --client client.toml

# With logging
RUST_LOG=debug ./rathole --server server.toml
```

---

## 📝 Minimal Configs

### Server (Germany)
```toml
[server]
bind_addr = "0.0.0.0:443"
default_token = "secret_token_here"

[server.transport]
type = "shadowtls_noise"

[server.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
tls_cert = "/path/to/cert.pem"
tls_key = "/path/to/key.pem"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = "server_private_key_base64"

[server.services.ssh]
token = "ssh_token"
bind_addr = "0.0.0.0:2222"
```

### Client (Iran)
```toml
[client]
remote_addr = "your-domain.com:443"
default_token = "secret_token_here"

[client.transport]
type = "shadowtls_noise"

[client.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
remote_public_key = "server_public_key_base64"

[client.services.ssh]
token = "ssh_token"
local_addr = "127.0.0.1:22"
```

---

## 🔍 Debugging

### Check Logs
```bash
# Server
journalctl -u rathole -f

# Client
journalctl -u rathole-client -f

# Show errors only
journalctl -u rathole -p err
```

### Network Testing
```bash
# Test TLS handshake
openssl s_client -connect your-domain.com:443 -servername www.microsoft.com

# Capture traffic
sudo tcpdump -i eth0 -w test.pcap port 443

# Analyze
tshark -r test.pcap -Y tls
```

### Common Issues
```bash
# Port in use
netstat -tulpn | grep 443

# Certificate invalid
openssl x509 -in /path/to/cert.pem -text -noout -dates

# Config syntax
./rathole --check config.toml
```

---

## 📊 File Locations

### Modified Files
```
rathole/
├── Cargo.toml                    [MODIFIED]
├── src/
│   ├── config.rs                 [MODIFIED]
│   ├── client.rs                 [MODIFIED]
│   ├── server.rs                 [MODIFIED]
│   └── transport/
│       ├── mod.rs                [MODIFIED]
│       └── shadowtls_noise.rs    [NEW]
├── docs/
│   └── transport.md              [MODIFIED]
├── examples/
│   └── shadowtls_config.toml     [NEW]
└── README.md                     [MODIFIED]
```

---

## 🎯 Noise Patterns

### Noise_NK (Default - Recommended)
```toml
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"

Server: local_private_key = "..."
Client: remote_public_key = "..."
```
- ✅ Server authenticated
- ✅ Client anonymous
- ✅ 2-message handshake (faster)

### Noise_XX (Alternative - More Stealth)
```toml
noise_pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s"

# No keys needed - mutual auth during handshake
```
- ✅ Mutual authentication
- ✅ 3-message handshake (harder to fingerprint)
- ⚠️ Slightly slower

---

## 🌍 Camouflage Domains for Iran

### Recommended (Whitelisted)
1. `www.microsoft.com` - Best stability ⭐
2. `www.bing.com` - Microsoft property
3. `dl.google.com` - Google downloads
4. `www.apple.com` - High traffic
5. `www.cloudflare.com` - CDN provider

### Test Before Using
```bash
# From Iran, test connectivity
curl -I https://www.microsoft.com
ping www.microsoft.com
```

---

## ⚡ Performance Tuning

### Server Side
```bash
# Enable BBR
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
```

### Config Tuning
```toml
[client.transport.tcp]
nodelay = true           # Low latency
keepalive_secs = 20      # Connection health
keepalive_interval = 8   # Fast detection

[client]
heartbeat_timeout = 40   # Application-level keepalive
retry_interval = 1       # Quick reconnect
```

---

## 🔒 Security Best Practices

### Token Generation
```bash
# Generate strong token
openssl rand -hex 32
```

### Key Storage
```bash
# Never commit keys to git
echo "*.pem" >> .gitignore
echo "*_key*" >> .gitignore

# Secure permissions
chmod 600 /etc/rathole/server.toml
chmod 600 ~/.config/rathole/client.toml
```

### Certificate Renewal
```bash
# Auto-renewal (already setup with certbot)
certbot renew --dry-run

# Restart service after renewal
cat > /etc/letsencrypt/renewal-hooks/deploy/rathole.sh << 'EOF'
#!/bin/bash
systemctl restart rathole
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/rathole.sh
```

---

## 📈 Monitoring

### Check Service Status
```bash
# Server
systemctl status rathole

# Client
systemctl status rathole-client

# Resource usage
htop -p $(pgrep rathole)
```

### Traffic Statistics
```bash
# Connections
netstat -antp | grep rathole

# Bandwidth (install iftop)
sudo iftop -i eth0 -f "port 443"
```

---

## 🆘 Emergency Procedures

### Server Down
```bash
# Check service
systemctl status rathole

# View recent errors
journalctl -u rathole --since "10 minutes ago" -p err

# Restart
systemctl restart rathole

# If persistent, check:
# 1. Certificate validity
# 2. Port availability
# 3. Disk space
```

### Client Can't Connect
```bash
# Test DNS
nslookup your-domain.com

# Test connectivity
telnet your-domain.com 443

# Test TLS
openssl s_client -connect your-domain.com:443

# Check client logs
journalctl -u rathole-client --since "5 minutes ago"
```

### Suspected DPI Blocking
```bash
# Change camouflage domain
sed -i 's/www.microsoft.com/www.bing.com/' /etc/rathole/server.toml
sed -i 's/www.microsoft.com/www.bing.com/' /etc/rathole/client.toml

# Restart both sides
systemctl restart rathole         # Server
systemctl restart rathole-client  # Client
```

---

## 📱 Systemd Service Templates

### Server Service
```ini
[Unit]
Description=Rathole ShadowTLS Server
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

### Client Service
```ini
[Unit]
Description=Rathole ShadowTLS Client
After=network-online.target

[Service]
Type=simple
User=YOUR_USER
ExecStart=/usr/local/bin/rathole --client /etc/rathole/client.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## 🧪 Testing Checklist

- [ ] Compiles: `cargo build --release --features shadowtls-noise`
- [ ] Config loads: `./rathole --check config.toml`
- [ ] Server starts: `systemctl status rathole`
- [ ] Client connects: Check logs for "Connection established"
- [ ] Data flows: Test SSH/HTTP through tunnel
- [ ] TLS visible: `tcpdump` shows proper TLS handshake
- [ ] Survives restart: Reconnects automatically
- [ ] Certificate valid: Check expiry date

---

## 💡 Pro Tips

1. **Always test locally first** - Use localhost before deploying
2. **Backup keys** - Store Noise keys securely
3. **Monitor logs** - Set up log aggregation
4. **Use port 443** - Standard HTTPS port is less suspicious
5. **Keep it updated** - Follow rathole releases
6. **Have backup VPS** - In case primary gets blocked
7. **Rotate tokens** - Change every few months
8. **Test from Iran** - VPN to Iran to test before deployment

---

## 📚 Resources

- Rathole Docs: https://github.com/rathole-org/rathole
- Noise Protocol: http://noiseprotocol.org/
- Let's Encrypt: https://letsencrypt.org/
- Iran DPI Research: https://gfw.report/

---

## 🎬 One-Liner Setups

### Server Setup (Germany)
```bash
curl -fsSL https://sh.rustup.rs | sh && \
git clone YOUR_FORK_URL && cd rathole && \
cargo build --release --features shadowtls-noise && \
sudo cp target/release/rathole /usr/local/bin/ && \
sudo certbot certonly --standalone -d your-domain.com && \
./rathole --genkey
```

### Client Setup (Iran)
```bash
# Copy binary, create config, start service
./rathole --client client.toml
```

---

**Remember:** This is CRITICAL INFRASTRUCTURE for people in Iran. Test thoroughly! 🛡️
