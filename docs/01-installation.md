# Installation Guide

This guide provides step-by-step instructions for installing Suricata IDS on various operating systems.

## Table of Contents

- [Ubuntu/Debian Installation](#ubuntudebian-installation)
- [CentOS/RHEL Installation](#centosrhel-installation)
- [macOS Installation](#macos-installation)
- [Windows (WSL) Installation](#windows-wsl-installation)
- [Verification Steps](#verification-steps)
- [Post-Installation Setup](#post-installation-setup)
- [Common Installation Issues](#common-installation-issues)

## Ubuntu/Debian Installation

### Method 1: Using APT Package Manager (Recommended)

This is the easiest method for most users.

```bash
# Update package list
sudo apt-get update

# Install Suricata
sudo apt-get install suricata -y

# Check installed version
suricata --version
```

### Method 2: Using PPA for Latest Version

For the latest stable version:

```bash
# Add Suricata PPA repository
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update

# Install Suricata
sudo apt-get install suricata -y

# Verify installation
suricata --build-info
```

### Method 3: Building from Source

For advanced users who need the latest features:

```bash
# Install dependencies
sudo apt-get install -y \
    libpcre3 libpcre3-dev \
    build-essential autoconf automake libtool \
    libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev \
    pkg-config zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
    make libmagic-dev libjansson-dev libjansson4 \
    libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev \
    libevent-dev python3-yaml rustc cargo

# Download Suricata
cd /tmp
wget https://www.openinfosecfoundation.org/download/suricata-6.0.0.tar.gz
tar -xvzf suricata-6.0.0.tar.gz
cd suricata-6.0.0

# Configure and build
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
sudo make install

# Install configuration files
sudo make install-conf

# Install rules
sudo make install-rules
```

## CentOS/RHEL Installation

### Method 1: Using YUM (CentOS 7/RHEL 7)

```bash
# Install EPEL repository
sudo yum install epel-release -y

# Install Suricata
sudo yum install suricata -y

# Enable and start Suricata service
sudo systemctl enable suricata
sudo systemctl start suricata

# Check status
sudo systemctl status suricata
```

### Method 2: Using DNF (CentOS 8/RHEL 8+)

```bash
# Install EPEL repository
sudo dnf install epel-release -y

# Install Suricata
sudo dnf install suricata -y

# Enable and start service
sudo systemctl enable suricata
sudo systemctl start suricata
```

### Installing from OISF Repository (Latest Version)

```bash
# CentOS 7
sudo yum install https://copr.fedorainfracloud.org/coprs/...
sudo yum install suricata

# CentOS 8
sudo dnf copr enable @oisf/suricata-6.0
sudo dnf install suricata
```

## macOS Installation

### Using Homebrew

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Update Homebrew
brew update

# Install Suricata
brew install suricata

# Verify installation
suricata --version
suricata --build-info

# Configuration file location
# /usr/local/etc/suricata/suricata.yaml
```

### Post-Installation on macOS

```bash
# Create log directory
sudo mkdir -p /var/log/suricata

# Set permissions
sudo chown -R $(whoami) /var/log/suricata

# Update rules
suricata-update

# Test configuration
suricata -T -c /usr/local/etc/suricata/suricata.yaml
```

## Windows (WSL) Installation

Windows users can run Suricata using Windows Subsystem for Linux (WSL).

### Step 1: Enable WSL

```powershell
# Run in PowerShell as Administrator
wsl --install
```

### Step 2: Install Ubuntu from Microsoft Store

1. Open Microsoft Store
2. Search for "Ubuntu"
3. Install Ubuntu 20.04 LTS or later
4. Launch Ubuntu and create a user account

### Step 3: Install Suricata in WSL

```bash
# Inside Ubuntu WSL terminal
sudo apt-get update
sudo apt-get install suricata -y

# Verify installation
suricata --version
```

### Step 4: Network Interface Configuration

WSL2 uses a virtual network adapter:

```bash
# List network interfaces
ip addr show

# Look for eth0 or similar interface
# Use this interface in your Suricata configuration
```

**Note**: WSL has limitations for packet capture. For production use, consider running Suricata on native Linux.

## Verification Steps

After installation, verify that Suricata is properly installed:

### Check Version

```bash
suricata --version
```

Expected output:
```
This is Suricata version 6.0.0
```

### Check Build Information

```bash
suricata --build-info
```

This shows enabled features like:
- AF_PACKET support
- PCAP support  
- NFQ (NFQUEUE) support
- Lua scripting
- And more

### Test Configuration

```bash
# Test configuration file syntax
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Expected output:
```
[...] <Notice> - Configuration provided was successfully loaded. Exiting.
```

### Check File Locations

Verify important file locations:

```bash
# Configuration file
ls -l /etc/suricata/suricata.yaml

# Rules directory
ls -l /etc/suricata/rules/

# Log directory
ls -l /var/log/suricata/
```

## Post-Installation Setup

### 1. Update Rules

Download the latest detection rules:

```bash
# Update rules using suricata-update
sudo suricata-update

# Update with specific source
sudo suricata-update --reload-command "sudo systemctl reload suricata"
```

### 2. Configure Log Permissions

```bash
# Ensure log directory exists
sudo mkdir -p /var/log/suricata

# Set appropriate permissions
sudo chown -R suricata:suricata /var/log/suricata
# or for current user
sudo chown -R $USER:$USER /var/log/suricata
```

### 3. Configure Interface

Identify your network interface (see [Network Interfaces Guide](02-network-interfaces.md)):

```bash
# List interfaces
ip addr show

# Edit configuration
sudo nano /etc/suricata/suricata.yaml

# Set your interface (e.g., eth0, ens33, wlan0)
```

### 4. Enable Service (Systemd)

```bash
# Enable Suricata to start on boot
sudo systemctl enable suricata

# Start Suricata
sudo systemctl start suricata

# Check status
sudo systemctl status suricata
```

### 5. Test Detection

Test that Suricata is detecting traffic:

```bash
# Run Suricata in test mode on an interface
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 --init-errors-fatal

# Or use a test PCAP file
sudo suricata -c /etc/suricata/suricata.yaml -r test.pcap

# Monitor logs
sudo tail -f /var/log/suricata/fast.log
```

## Common Installation Issues

### Issue 1: Permission Denied

**Problem**: `Permission denied` when running Suricata

**Solution**:
```bash
# Run with sudo
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Or add user to suricata group
sudo usermod -aG suricata $USER

# Restart shell for group changes to take effect
```

### Issue 2: Interface Not Found

**Problem**: `Failed to init iface 'eth0'`

**Solution**:
```bash
# List available interfaces
ip addr show
# or
ifconfig -a

# Update suricata.yaml with correct interface name
sudo nano /etc/suricata/suricata.yaml
```

### Issue 3: Rules Not Found

**Problem**: `No rule files match the pattern`

**Solution**:
```bash
# Update rules
sudo suricata-update

# Check rules directory
ls -l /var/lib/suricata/rules/

# Verify rules path in configuration
grep "rule-files:" /etc/suricata/suricata.yaml
```

### Issue 4: Failed to Load Configuration

**Problem**: `Failed to load yaml configuration`

**Solution**:
```bash
# Test configuration syntax
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Check for YAML syntax errors
# Ensure proper indentation (spaces, not tabs)
# Check for missing colons or quotes
```

### Issue 5: libhtp Library Error

**Problem**: `error while loading shared libraries: libhtp.so.2`

**Solution**:
```bash
# Update library cache
sudo ldconfig

# Or install missing library
sudo apt-get install libhtp2

# Or add library path
sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'
sudo ldconfig
```

### Issue 6: Insufficient Privileges for Packet Capture

**Problem**: Cannot capture packets without root

**Solution**:
```bash
# Grant capabilities to Suricata binary
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/suricata

# Verify capabilities
getcap /usr/bin/suricata
```

### Issue 7: High Memory Usage During Installation

**Problem**: System runs out of memory when building from source

**Solution**:
```bash
# Use single-threaded make
make -j1

# Or increase swap space
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Issue 8: Outdated Version in Repository

**Problem**: Repository has an old version of Suricata

**Solution**:
- Use PPA (Ubuntu/Debian) or COPR (CentOS/RHEL) for latest version
- Build from source (see Method 3 above)
- Check official Suricata website for latest packages

## Verifying Successful Installation

To confirm everything is working:

```bash
# 1. Check version
suricata --version

# 2. Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# 3. List interfaces
sudo suricata --list-runmodes

# 4. Check rules are loaded
sudo suricata -c /etc/suricata/suricata.yaml --dump-config | grep "rule-files"

# 5. Run a quick test
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 --init-errors-fatal -v
# Press Ctrl+C after a few seconds

# 6. Check logs were created
ls -lh /var/log/suricata/
```

## Next Steps

After successful installation:

1. **Configure Network Interface**: See [Network Interfaces Guide](02-network-interfaces.md)
2. **Configure Suricata**: See [Basic Configuration Guide](03-basic-configuration.md)
3. **Update Rules**: See [Rule Management Guide](05-rule-management.md)
4. **Start Monitoring**: Begin capturing and analyzing traffic

## Additional Resources

- [Official Installation Guide](https://suricata.readthedocs.io/en/latest/install.html)
- [Suricata Quickstart](https://suricata.readthedocs.io/en/latest/quickstart.html)
- [Performance Tuning](09-advanced-topics.md)

---

[← Back to README](../README.md) | [Next: Network Interfaces →](02-network-interfaces.md)
