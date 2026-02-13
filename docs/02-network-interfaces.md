# Network Interfaces Configuration

Understanding and configuring network interfaces is crucial for Suricata to monitor network traffic effectively. This guide covers everything you need to know about network interfaces for Suricata.

## Table of Contents

- [Understanding Network Interfaces](#understanding-network-interfaces)
- [Identifying Network Interfaces](#identifying-network-interfaces)
- [Selecting the Right Interface](#selecting-the-right-interface)
- [Promiscuous Mode](#promiscuous-mode)
- [Multiple Interface Monitoring](#multiple-interface-monitoring)
- [Wireless vs Wired Interfaces](#wireless-vs-wired-interfaces)
- [Common Interface Names](#common-interface-names)
- [Troubleshooting Interface Issues](#troubleshooting-interface-issues)

## Understanding Network Interfaces

A network interface is the point of interconnection between a computer and a network. Suricata needs to be configured to listen on the correct interface to capture and analyze network traffic.

### Types of Interfaces

1. **Physical Interfaces**: Actual hardware network adapters (Ethernet, WiFi)
2. **Virtual Interfaces**: Software-created interfaces (loopback, docker, VPN)
3. **Bridge Interfaces**: Combine multiple physical interfaces
4. **VLAN Interfaces**: Virtual LANs for network segmentation

## Identifying Network Interfaces

### Using `ip addr` (Recommended - Modern Linux)

```bash
# Show all network interfaces
ip addr show

# Show specific interface
ip addr show eth0

# Show brief output
ip -br addr show
```

**Example Output:**
```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host

2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:3f:6c:43 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0
    inet6 fe80::a00:27ff:fe3f:6c43/64 scope link

3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.150/24 brd 192.168.1.255 scope global dynamic wlan0
```

### Using `ifconfig` (Traditional Method)

```bash
# Show all interfaces
ifconfig -a

# Show specific interface
ifconfig eth0

# Show only active interfaces
ifconfig
```

**Example Output:**
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe3f:6c43  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:3f:6c:43  txqueuelen 1000  (Ethernet)
        RX packets 12345  bytes 1234567 (1.2 MB)
        TX packets 6789  bytes 987654 (987.6 KB)
```

### Using `ip link show`

Shows link layer information:

```bash
# List all interfaces
ip link show

# Show specific interface
ip link show eth0

# Show interface statistics
ip -s link show eth0
```

**Example Output:**
```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:3f:6c:43 brd ff:ff:ff:ff:ff:ff
    RX: bytes  packets  errors  dropped overrun mcast   
    1234567    12345    0       0       0       0       
    TX: bytes  packets  errors  dropped carrier collsns 
    987654     6789     0       0       0       0
```

### Quick Comparison of Commands

```bash
# Get just interface names
ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://'

# Or use ip with brief option
ip -br link show

# List with status
ip -o link show | awk '{print $2,$9}'
```

## Selecting the Right Interface

### Factors to Consider

1. **Active vs Inactive**: Choose an interface that is UP and RUNNING
2. **Traffic Location**: Interface must be on the network segment you want to monitor
3. **Network Type**: Consider if monitoring wired, wireless, or both
4. **Permission Level**: You need root/admin access to capture on interfaces

### Decision Tree

```
Are you monitoring:
├─ Local machine traffic only? → Use loopback (lo)
├─ LAN traffic? → Use Ethernet interface (eth0, ens33)
├─ WiFi traffic? → Use wireless interface (wlan0)
├─ All traffic? → Monitor multiple interfaces
└─ Specific VLAN? → Use VLAN interface (eth0.100)
```

### Determining Your Interface

**Step 1: List all interfaces**
```bash
ip link show
```

**Step 2: Check which interfaces are UP**
```bash
ip link show | grep "state UP"
```

**Step 3: Check IP addresses**
```bash
ip addr show
```

**Step 4: Identify your active network interface**
```bash
# The one with your local IP address
ip route show default
```

**Example:**
```bash
$ ip route show default
default via 192.168.1.1 dev eth0 proto dhcp metric 100
```
This shows `eth0` is the primary interface.

## Promiscuous Mode

Promiscuous mode allows a network interface to capture ALL packets on the network segment, not just packets destined for your machine.

### What is Promiscuous Mode?

- **Normal Mode**: Interface only captures packets addressed to it
- **Promiscuous Mode**: Interface captures ALL packets on the network segment
- **Required**: For effective IDS monitoring

### Enabling Promiscuous Mode

**Temporarily (until reboot):**
```bash
# Enable promiscuous mode
sudo ip link set eth0 promisc on

# Verify promiscuous mode is enabled
ip link show eth0 | grep PROMISC

# Disable promiscuous mode
sudo ip link set eth0 promisc off
```

**Using ifconfig:**
```bash
# Enable
sudo ifconfig eth0 promisc

# Check status
ifconfig eth0 | grep PROMISC

# Disable
sudo ifconfig eth0 -promisc
```

### Persistent Promiscuous Mode (Systemd)

Create a systemd service:

```bash
# Create service file
sudo nano /etc/systemd/system/promisc-eth0.service
```

Add this content:
```ini
[Unit]
Description=Set eth0 to promiscuous mode
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set eth0 promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable the service:
```bash
sudo systemctl enable promisc-eth0.service
sudo systemctl start promisc-eth0.service
```

### Important Notes About Promiscuous Mode

⚠️ **Security Considerations:**
- Promiscuous mode may not work on all networks (especially switched networks)
- Some wireless adapters don't support promiscuous mode
- Network administrators may detect promiscuous mode usage
- Use port mirroring/SPAN on switches for better results

⚠️ **Limitations:**
- On switched networks, you only see traffic to/from your machine and broadcast traffic
- Need network tap or port mirroring to see all traffic
- WiFi promiscuous mode requires specific hardware support

## Multiple Interface Monitoring

Suricata can monitor multiple network interfaces simultaneously.

### Configuration for Multiple Interfaces

Edit `/etc/suricata/suricata.yaml`:

```yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    threads: auto
  - interface: wlan0
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
    threads: auto
  - interface: eth1
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
    threads: auto
```

### Running Suricata on Multiple Interfaces

**Method 1: Single Instance**
```bash
# Suricata will use all configured interfaces in YAML
sudo suricata -c /etc/suricata/suricata.yaml --af-packet
```

**Method 2: Multiple Instances**
```bash
# Start separate instances for each interface
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 --pidfile /var/run/suricata-eth0.pid &
sudo suricata -c /etc/suricata/suricata.yaml -i wlan0 --pidfile /var/run/suricata-wlan0.pid &
```

**Method 3: Systemd Multiple Instances**

Create service template:
```bash
sudo nano /etc/systemd/system/suricata@.service
```

```ini
[Unit]
Description=Suricata IDS on %I
After=network.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i %I --pidfile /var/run/suricata-%I.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Start instances:
```bash
sudo systemctl start suricata@eth0
sudo systemctl start suricata@wlan0
sudo systemctl enable suricata@eth0
sudo systemctl enable suricata@wlan0
```

### Best Practices for Multiple Interfaces

1. **Use different cluster IDs** for each interface
2. **Separate log files** for each interface (use `logdir` per interface)
3. **Monitor resource usage** - multiple interfaces increase CPU/memory usage
4. **Consider thread allocation** - distribute threads appropriately
5. **Use separate statistics** for each interface

## Wireless vs Wired Interfaces

### Wired Interfaces (Ethernet)

**Characteristics:**
- More reliable for packet capture
- Better performance
- Easier to configure
- Consistent packet timing

**Common Names:** `eth0`, `eth1`, `ens33`, `enp0s3`, `em1`

**Best for:**
- Production IDS deployment
- High-speed networks
- Mission-critical monitoring

**Configuration Example:**
```yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    threads: 4
```

### Wireless Interfaces (WiFi)

**Characteristics:**
- May not support promiscuous mode
- Can miss packets due to signal issues
- May require monitor mode for full capture
- Additional encryption considerations

**Common Names:** `wlan0`, `wlan1`, `wlp2s0`, `wifi0`

**Challenges:**
- **Encryption**: WPA/WPA2 encrypted traffic
- **Hidden SSIDs**: May not capture all traffic
- **Channel Hopping**: Only one channel at a time
- **Hardware Limitations**: Not all adapters support monitor mode

**Monitor Mode (Advanced):**

Monitor mode allows capturing all WiFi traffic:

```bash
# Stop network manager from interfering
sudo systemctl stop NetworkManager

# Put interface in monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set monitor none
sudo ip link set wlan0 up

# Set channel (optional)
sudo iw dev wlan0 set channel 6

# Verify monitor mode
iwconfig wlan0
```

**Recommended WiFi Adapters for Monitoring:**
- Alfa AWUS036ACH
- TP-Link TL-WN722N (v1 only)
- ASUS USB-AC56

## Common Interface Names

### Modern Linux (Predictable Network Interface Names)

| Interface Name | Description |
|----------------|-------------|
| `lo` | Loopback interface (127.0.0.1) |
| `enp0s3` | Ethernet, PCI bus 0, slot 3 |
| `ens33` | Ethernet, hotplug slot 33 |
| `enx001122334455` | Ethernet, MAC-based naming |
| `wlp2s0` | Wireless LAN, PCI bus 2, slot 0 |

### Traditional Linux

| Interface Name | Description |
|----------------|-------------|
| `eth0`, `eth1` | First, second Ethernet interface |
| `wlan0`, `wlan1` | First, second wireless interface |
| `ppp0` | Point-to-point protocol (dial-up, VPN) |

### Virtual Interfaces

| Interface Name | Description |
|----------------|-------------|
| `docker0` | Docker bridge interface |
| `virbr0` | Virtual bridge (libvirt) |
| `tun0`, `tap0` | TUN/TAP interfaces (VPN) |
| `veth*` | Virtual Ethernet pairs (containers) |

### macOS

| Interface Name | Description |
|----------------|-------------|
| `en0` | First Ethernet interface |
| `en1` | Usually WiFi interface |
| `lo0` | Loopback interface |
| `bridge0` | Bridge interface |

## Troubleshooting Interface Issues

### Problem 1: Interface Not Found

**Symptoms:**
```
ERROR: Failed to init iface 'eth0'
```

**Solutions:**
```bash
# List all interfaces
ip link show

# Check if interface exists
ip link show eth0

# Check interface name in modern Linux
ls /sys/class/net/

# Update suricata.yaml with correct name
```

### Problem 2: No Permission to Capture

**Symptoms:**
```
ERROR: Couldn't create raw socket
```

**Solutions:**
```bash
# Run with sudo
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Or give capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/suricata

# Or run as suricata user
sudo -u suricata suricata -c /etc/suricata/suricata.yaml -i eth0
```

### Problem 3: Interface Not UP

**Symptoms:**
Interface shows `state DOWN`

**Solutions:**
```bash
# Bring interface up
sudo ip link set eth0 up

# Check status
ip link show eth0

# Enable interface at boot
sudo systemctl enable networking
```

### Problem 4: No Traffic Being Captured

**Symptoms:**
Suricata runs but no alerts or logs

**Solutions:**
```bash
# 1. Check promiscuous mode
ip link show eth0 | grep PROMISC

# 2. Generate test traffic
ping 8.8.8.8

# 3. Verify Suricata is capturing
sudo tcpdump -i eth0 -c 10

# 4. Check if interface has traffic
ip -s link show eth0

# 5. Ensure you're on the right network segment
```

### Problem 5: Wireless Interface Not Working

**Symptoms:**
Cannot capture WiFi traffic

**Solutions:**
```bash
# Check if monitor mode is supported
iw list | grep -A 10 "Supported interface modes"

# Try different capture mode
# In suricata.yaml, try pcap instead of af-packet

# Consider using Ethernet instead for monitoring
```

## Testing Your Interface Configuration

### Basic Tests

**Test 1: Can Suricata see the interface?**
```bash
sudo suricata --list-runmodes
```

**Test 2: Test configuration**
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -i eth0
```

**Test 3: Run for a few seconds**
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
# Press Ctrl+C after 10 seconds
# Check logs in /var/log/suricata/
```

**Test 4: Generate traffic and check capture**
```bash
# Terminal 1: Run Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Terminal 2: Generate traffic
ping -c 5 8.8.8.8

# Terminal 3: Watch logs
tail -f /var/log/suricata/fast.log
```

## Quick Reference

### Essential Commands

```bash
# List interfaces
ip link show

# Show IP addresses
ip addr show

# Check interface status
ip link show eth0

# Enable interface
sudo ip link set eth0 up

# Enable promiscuous mode
sudo ip link set eth0 promisc on

# Test Suricata with interface
sudo suricata -T -c /etc/suricata/suricata.yaml -i eth0

# Run Suricata on interface
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

## Next Steps

After configuring your network interface:

1. **Configure Suricata**: See [Basic Configuration Guide](03-basic-configuration.md)
2. **Set HOME_NET**: Define your network range
3. **Test Detection**: Verify alerts are being generated
4. **Optimize Performance**: See [Advanced Topics](09-advanced-topics.md)

---

[← Back: Installation](01-installation.md) | [Home](../README.md) | [Next: Basic Configuration →](03-basic-configuration.md)
