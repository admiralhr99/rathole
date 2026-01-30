# DEPLOYMENT_GUIDE.md - Production Deployment Iran → Germany

## 🚀 Production Deployment Strategy

This guide covers deploying ShadowTLS-Noise rathole tunnel from Iran to Germany VPS.

---

## PREREQUISITES

### Germany VPS Requirements
- ✅ Public IP address
- ✅ Domain name pointed to VPS
- ✅ Port 443 open (firewall)
- ✅ Root/sudo access
- ✅ Ubuntu 22.04+ or Debian 11+
- ✅ 1GB+ RAM, 10GB+ disk
- ✅ Good routing to Iran (Hetzner, Netcup recommended)

### Iran Client Requirements  
- ✅ Rathole binary compiled with shadowtls-noise
- ✅ Stable internet connection
- ✅ Ability to reach Germany IP (test with ping first)

### Tools Needed
- `rathole` binary (compiled)
- `certbot` (for Let's Encrypt)
- `openssl` (key generation)
- `systemd` (service management)

---

## PHASE 1: Germany VPS Setup

### Step 1.1: Initial VPS Configuration

```bash
# SSH into VPS
ssh root@your-vps-ip

# Update system
apt update && apt upgrade -y

# Install dependencies
apt install -y curl wget git build-essential pkg-config \
               libssl-dev certbot ufw htop

# Install Rust (for building rathole)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Step 1.2: Configure Firewall

```bash
# Allow SSH (change 22 if using different port)
ufw allow 22/tcp

# Allow HTTPS (for ShadowTLS)
ufw allow 443/tcp

# Allow your exposed services (example: SSH tunnel)
ufw allow 2222/tcp

# Enable firewall
ufw enable

# Verify
ufw status
```

### Step 1.3: Get Let's Encrypt Certificate

```bash
# Stop any service on port 80/443
systemctl stop nginx apache2 2>/dev/null || true

# Get certificate (replace your-domain.com)
certbot certonly --standalone -d your-domain.com

# Output will be:
# Certificate: /etc/letsencrypt/live/your-domain.com/fullchain.pem
# Private Key: /etc/letsencrypt/live/your-domain.com/privkey.pem

# Verify certificate
openssl x509 -in /etc/letsencrypt/live/your-domain.com/fullchain.pem -text -noout

# Setup auto-renewal
systemctl enable certbot.timer
systemctl start certbot.timer
```

### Step 1.4: Build/Install Rathole

**Option A: Build from source (recommended for latest features)**
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/rathole.git
cd rathole
git checkout shadowtls-noise

# Build with shadowtls-noise feature
cargo build --release --features shadowtls-noise

# Install binary
cp target/release/rathole /usr/local/bin/
chmod +x /usr/local/bin/rathole

# Verify
rathole --version
```

**Option B: Copy pre-compiled binary**
```bash
# Upload from your build machine
scp target/release/rathole root@your-vps:/usr/local/bin/
ssh root@your-vps 'chmod +x /usr/local/bin/rathole'
```

### Step 1.5: Generate Noise Keys

```bash
# Generate keypair
rathole --genkey

# Output:
# Private Key: cQ/vwIqNPJZmuM/OikglzBo/+jlYGrOt9i0k5h5vn1Q=
# Public Key: GQYTKSbWLBUSZiGfdWPSgek9yoOuaiwGD/GIX8Z1kkE=

# SAVE THESE SECURELY!
# Private key stays on server
# Public key goes to client
```

### Step 1.6: Create Server Configuration

```bash
# Create config directory
mkdir -p /etc/rathole

# Create strong token
TOKEN=$(openssl rand -hex 32)
echo "Token: $TOKEN"  # SAVE THIS

# Create server config
cat > /etc/rathole/server.toml << 'EOF'
[server]
bind_addr = "0.0.0.0:443"
default_token = "REPLACE_WITH_YOUR_TOKEN"
heartbeat_interval = 30

[server.transport]
type = "shadowtls_noise"

[server.transport.tcp]
nodelay = true
keepalive_secs = 20
keepalive_interval = 8

[server.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
tls_cert = "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/your-domain.com/privkey.pem"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = "PASTE_PRIVATE_KEY_HERE"

# Example: Expose SSH
[server.services.ssh]
token = "ssh_service_token"
bind_addr = "0.0.0.0:2222"
type = "tcp"

# Example: Expose HTTP
[server.services.http]
token = "http_service_token"
bind_addr = "0.0.0.0:8080"
type = "tcp"
EOF

# Edit config with real values
nano /etc/rathole/server.toml
# Replace: TOKEN, PRIVATE_KEY, your-domain.com
```

### Step 1.7: Create Systemd Service

```bash
cat > /etc/systemd/system/rathole.service << 'EOF'
[Unit]
Description=Rathole ShadowTLS-Noise Tunnel Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rathole --server /etc/rathole/server.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Enable service (start on boot)
systemctl enable rathole

# Start service
systemctl start rathole

# Check status
systemctl status rathole

# View logs
journalctl -u rathole -f
```

**Expected logs:**
```
INFO rathole::server: Starting server
INFO rathole::server: Listening on 0.0.0.0:443
INFO rathole::transport: Using ShadowTLS-Noise transport
INFO shadowtls_noise: TLS config loaded successfully
```

### Step 1.8: Verify Server is Running

```bash
# Check port is listening
netstat -tulpn | grep 443
# Expected: rathole listening on 0.0.0.0:443

# Test TLS handshake
openssl s_client -connect localhost:443 -servername www.microsoft.com
# Should show certificate info

# Check logs for errors
journalctl -u rathole --since "5 minutes ago"
```

---

## PHASE 2: Iran Client Setup

### Step 2.1: Prepare Binary

**On your build machine (or download from release):**
```bash
# Build for Linux (if targeting Linux client)
cargo build --release --target x86_64-unknown-linux-gnu --features shadowtls-noise

# Or for specific architecture
cargo build --release --target aarch64-unknown-linux-gnu --features shadowtls-noise

# Binary location: target/release/rathole
```

### Step 2.2: Transfer to Iran Machine

```bash
# Via SCP (if you have direct access)
scp target/release/rathole user@iran-machine:/home/user/

# Or copy via USB drive, cloud service, etc.
# Make executable
chmod +x rathole
```

### Step 2.3: Create Client Configuration

```bash
# On Iran machine
mkdir -p ~/.config/rathole

cat > ~/.config/rathole/client.toml << 'EOF'
[client]
remote_addr = "your-domain.com:443"
default_token = "SAME_TOKEN_AS_SERVER"
heartbeat_timeout = 40
retry_interval = 1

[client.transport]
type = "shadowtls_noise"

[client.transport.tcp]
nodelay = true
keepalive_secs = 20
keepalive_interval = 8

[client.transport.shadowtls_noise]
camouflage_domain = "www.microsoft.com"
noise_pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
remote_public_key = "PASTE_SERVER_PUBLIC_KEY_HERE"

# Forward local SSH to remote port 2222
[client.services.ssh]
token = "ssh_service_token"
local_addr = "127.0.0.1:22"
type = "tcp"

# Forward local HTTP to remote port 8080
[client.services.http]
token = "http_service_token"
local_addr = "127.0.0.1:8000"
type = "tcp"
EOF

# Edit with real values
nano ~/.config/rathole/client.toml
```

### Step 2.4: Test Client Connection

```bash
# Test manually first
RUST_LOG=info ./rathole --client ~/.config/rathole/client.toml
```

**Expected logs:**
```
INFO rathole::client: Starting client
INFO rathole::client: Connecting to your-domain.com:443
INFO shadowtls_noise: ShadowTLS-Noise: Connecting
DEBUG shadowtls_noise: TLS handshake complete
DEBUG shadowtls_noise: Noise handshake complete
INFO rathole::client: Connection established
INFO rathole::client: Service 'ssh' ready
```

**If successful**, proceed to systemd setup. **If failed**, check:
- VPS firewall allows port 443
- Domain resolves correctly from Iran
- Token and keys match
- Certificate is valid

### Step 2.5: Create Client Systemd Service

```bash
# Create service file
sudo mkdir -p /etc/rathole
sudo cp ~/.config/rathole/client.toml /etc/rathole/
sudo cp rathole /usr/local/bin/

sudo cat > /etc/systemd/system/rathole-client.service << 'EOF'
[Unit]
Description=Rathole ShadowTLS-Noise Tunnel Client
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=YOUR_USERNAME
ExecStart=/usr/local/bin/rathole --client /etc/rathole/client.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Replace YOUR_USERNAME
sudo nano /etc/systemd/system/rathole-client.service

# Reload and enable
sudo systemctl daemon-reload
sudo systemctl enable rathole-client
sudo systemctl start rathole-client

# Check status
sudo systemctl status rathole-client

# View logs
journalctl -u rathole-client -f
```

---

## PHASE 3: Validation and Testing

### Step 3.1: Test SSH Tunnel

**From Iran machine:**
```bash
# Connect to your Iran machine's SSH through the tunnel
ssh -p 2222 username@your-domain.com

# This connects: Iran Client (localhost:22) → Germany VPS (port 2222) → back to Iran Client
# Proves tunnel is working bidirectionally
```

### Step 3.2: Test HTTP Service

**From any external machine:**
```bash
# If you exposed a local web server on Iran client
curl http://your-domain.com:8080

# Should return your local service's response
```

### Step 3.3: Monitor Traffic

**On Germany VPS:**
```bash
# Capture traffic on port 443
sudo tcpdump -i eth0 -n port 443 -w capture.pcap

# Let it run for 1 minute while tunnel is active
# Stop with Ctrl+C

# Analyze
tshark -r capture.pcap -Y tls

# Should show:
# - TLS ClientHello to www.microsoft.com
# - TLS ServerHello with your certificate
# - TLS ApplicationData records (encrypted)
```

**Verify DPI sees HTTPS:**
```bash
# Check SNI field
tshark -r capture.pcap -Y "ssl.handshake.extensions_server_name" \
  -T fields -e ssl.handshake.extensions_server_name

# Output should show: www.microsoft.com
```

### Step 3.4: Performance Test

**Throughput test:**
```bash
# On Iran machine, forward iperf3
# Client config:
[client.services.iperf]
token = "iperf_token"
local_addr = "127.0.0.1:5201"

# Server config:
[server.services.iperf]
token = "iperf_token"
bind_addr = "0.0.0.0:5201"

# Run iperf3
# Terminal 1 (Germany VPS):
iperf3 -s

# Terminal 2 (Iran):
iperf3 -c your-domain.com -t 30

# Expected: 10-50 Mbps (depends on Iran connectivity)
```

**Latency test:**
```bash
# Ping through tunnel
ping -c 10 your-domain.com

# Expected: 80-150ms (Iran to Germany typical)
```

---

## PHASE 4: Monitoring and Maintenance

### Step 4.1: Setup Monitoring

**Install monitoring tools on Germany VPS:**
```bash
apt install -y prometheus-node-exporter

# Monitor rathole process
cat > /usr/local/bin/check-rathole.sh << 'EOF'
#!/bin/bash
if ! systemctl is-active --quiet rathole; then
    echo "ALERT: Rathole is down!" | mail -s "Rathole Alert" your@email.com
    systemctl restart rathole
fi
EOF

chmod +x /usr/local/bin/check-rathole.sh

# Add to crontab (check every 5 minutes)
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/check-rathole.sh") | crontab -
```

**Log rotation:**
```bash
cat > /etc/logrotate.d/rathole << 'EOF'
/var/log/rathole/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

### Step 4.2: Backup Configuration

```bash
# On Germany VPS
mkdir -p ~/rathole-backup
cp /etc/rathole/server.toml ~/rathole-backup/
cp /etc/letsencrypt/live/your-domain.com/*.pem ~/rathole-backup/

# Save Noise keys separately
echo "Private: $PRIVATE_KEY" > ~/rathole-backup/noise-keys.txt
echo "Public: $PUBLIC_KEY" >> ~/rathole-backup/noise-keys.txt

# Backup token
echo "Token: $TOKEN" > ~/rathole-backup/token.txt

# Secure backups
chmod 600 ~/rathole-backup/*
```

### Step 4.3: Update Procedure

**When updating rathole:**
```bash
# On Germany VPS
systemctl stop rathole

# Backup current binary
cp /usr/local/bin/rathole /usr/local/bin/rathole.backup

# Update binary (build new version)
cd ~/rathole
git pull origin shadowtls-noise
cargo build --release --features shadowtls-noise
cp target/release/rathole /usr/local/bin/

# Restart
systemctl start rathole
systemctl status rathole

# If issues, rollback:
# cp /usr/local/bin/rathole.backup /usr/local/bin/rathole
# systemctl restart rathole
```

### Step 4.4: Certificate Renewal

```bash
# Certbot handles this automatically via timer
# Verify auto-renewal works:
certbot renew --dry-run

# After renewal, restart rathole to load new cert
cat > /etc/letsencrypt/renewal-hooks/deploy/rathole-restart.sh << 'EOF'
#!/bin/bash
systemctl reload-or-restart rathole
EOF

chmod +x /etc/letsencrypt/renewal-hooks/deploy/rathole-restart.sh
```

---

## PHASE 5: Troubleshooting

### Issue: Client Can't Connect

**Diagnosis:**
```bash
# 1. Check VPS is reachable
ping your-domain.com

# 2. Check port 443 is open
telnet your-domain.com 443

# 3. Test TLS handshake
openssl s_client -connect your-domain.com:443 \
  -servername www.microsoft.com

# 4. Check server logs
ssh root@your-vps
journalctl -u rathole -f
```

**Common causes:**
- Firewall blocking port 443
- Certificate expired
- Wrong token/keys
- Domain DNS not resolved from Iran

### Issue: Connection Drops Frequently

**Solutions:**
```bash
# 1. Increase keepalive
# In client.toml:
[client.transport.tcp]
keepalive_secs = 10
keepalive_interval = 5

# 2. Enable BBR congestion control (on VPS)
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

# 3. Lower heartbeat timeout
[client]
heartbeat_timeout = 20
```

### Issue: Slow Performance

**Optimizations:**
```bash
# 1. Enable TCP_NODELAY (already in config)
nodelay = true

# 2. Increase buffer sizes
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400

# 3. Choose better VPS location
# Test latency to different regions:
ping hetzner-germany.example.com
ping hetzner-finland.example.com
```

### Issue: DPI Detection

**Signs:**
- Connection works initially, then stops
- Specific time-based blocking (e.g., only works at night)
- Resets after X MB transferred

**Solutions:**
```bash
# 1. Change camouflage domain
camouflage_domain = "www.bing.com"  # Try different domains

# 2. Switch to Noise_XX pattern
noise_pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s"

# 3. Add connection delay
# In client.toml:
retry_interval = 5  # Wait longer between retries

# 4. Use different port (if 443 is scrutinized)
# Server: bind_addr = "0.0.0.0:8443"
# Client: remote_addr = "your-domain.com:8443"
```

---

## SECURITY CHECKLIST

Before going to production:

- [ ] Strong token (32+ random bytes)
- [ ] Valid Let's Encrypt certificate
- [ ] Firewall configured (only necessary ports)
- [ ] Regular updates enabled
- [ ] Backups created
- [ ] Monitoring configured
- [ ] Logs reviewed regularly
- [ ] Keys stored securely (not in git)
- [ ] Certificate auto-renewal working
- [ ] Non-root user for client (if possible)

---

## OPTIMIZATION RECOMMENDATIONS

### For Best Performance:
1. **VPS Location**: Hetzner Germany/Finland (best Iran routing)
2. **VPS Specs**: 2GB RAM, 2 CPU cores minimum
3. **BBR**: Enable TCP BBR congestion control
4. **MTU**: Set MTU to 1400 to avoid fragmentation
5. **DNS**: Use 1.1.1.1, 8.8.8.8 for faster resolution

### For Maximum Stealth:
1. **Port 443**: Use standard HTTPS port
2. **Microsoft/Google**: Camouflage as big tech domains
3. **Let's Encrypt**: Use real certificates, not self-signed
4. **Noise_XX**: Use 3-message pattern for extra obscurity
5. **Traffic Patterns**: Vary connection times, avoid patterns

---

## PRODUCTION ARCHITECTURE

```
┌─────────────┐         ┌──────────────────┐         ┌──────────┐
│ Iran Client │         │  Germany VPS     │         │ Internet │
│             │         │                  │         │          │
│ localhost:22├────────►│ TLS/Noise Wrapper├────────►│ Services │
│             │  443    │ Port 443         │         │          │
│ rathole     │◄────────┤ Port 2222, 8080  │◄────────┤          │
│ client      │ ShadowTLS└──────────────────┘         └──────────┘
└─────────────┘
        │
        └─────► DPI sees: HTTPS to microsoft.com
                Actually: Encrypted tunnel
```

Good luck with deployment! Stay safe. 🛡️
