# Advanced Topics

This guide covers advanced Suricata features, performance optimization, IPS mode deployment, and integration with other security tools.

## Table of Contents

- [Performance Optimization](#performance-optimization)
- [Multi-Threading Configuration](#multi-threading-configuration)
- [AF_PACKET vs PCAP Mode](#af_packet-vs-pcap-mode)
- [IPS Mode (Inline Deployment)](#ips-mode-inline-deployment)
- [File Extraction](#file-extraction)
- [Protocol Logging](#protocol-logging)
- [Statistical Analysis](#statistical-analysis)
- [Integration with Security Tools](#integration-with-security-tools)

## Performance Optimization

### System-Level Tuning

#### Kernel Parameters

```bash
# Edit sysctl configuration
sudo nano /etc/sysctl.conf
```

Add these optimizations:

```ini
# Increase network buffer sizes
net.core.rmem_max = 268435456
net.core.rmem_default = 268435456
net.core.wmem_max = 268435456
net.core.wmem_default = 268435456
net.core.netdev_max_backlog = 250000

# Increase connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000

# Disable conntrack for high traffic
# net.netfilter.nf_conntrack_tcp_loose = 0

# TCP optimization
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# Increase local port range
net.ipv4.ip_local_port_range = 10000 65535
```

Apply changes:

```bash
# Apply immediately
sudo sysctl -p

# Verify settings
sudo sysctl -a | grep -E "(rmem|wmem|netdev_max_backlog)"
```

#### NIC Tuning

```bash
# Check current settings
sudo ethtool -g eth0
sudo ethtool -k eth0

# Increase ring buffer size
sudo ethtool -G eth0 rx 4096 tx 4096

# Enable hardware offloading (if supported)
sudo ethtool -K eth0 rx on tx on sg on tso on gso on gro on lro on

# Disable offloading for IPS mode
sudo ethtool -K eth0 gro off lro off

# Set interrupt coalescing
sudo ethtool -C eth0 rx-usecs 50

# Check IRQ affinity
cat /proc/interrupts | grep eth0

# Set IRQ affinity (bind to specific CPUs)
echo "2" | sudo tee /proc/irq/[IRQ_NUMBER]/smp_affinity
```

Make NIC settings persistent:

```bash
# Create script
sudo nano /etc/network/if-up.d/suricata-nic-tuning
```

```bash
#!/bin/bash
if [ "$IFACE" = "eth0" ]; then
    ethtool -G eth0 rx 4096 tx 4096
    ethtool -K eth0 rx on tx on
fi
```

```bash
# Make executable
sudo chmod +x /etc/network/if-up.d/suricata-nic-tuning
```

### Suricata Configuration Optimization

#### Threading Configuration

```yaml
# /etc/suricata/suricata.yaml

# Set CPU affinity for optimal performance
threading:
  set-cpu-affinity: yes
  detect-thread-ratio: 1.5
  
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "0" ]  # Management thread
    - receive-cpu-set:
        cpu: [ "1-2" ]  # Packet capture
    - worker-cpu-set:
        cpu: [ "3-7" ]  # Detection workers
    - verdict-cpu-set:
        cpu: [ "8" ]  # IPS verdict (if using IPS)
```

Find optimal CPU count:

```bash
# Check CPU cores
nproc
lscpu

# Check Suricata thread usage
ps -eLf | grep suricata | wc -l

# Monitor CPU usage by thread
top -H -p $(pgrep suricata)
```

#### Memory Optimization

```yaml
# /etc/suricata/suricata.yaml

# Flow management
flow:
  memcap: 256mb  # Adjust based on available RAM
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30

# Stream engine
stream:
  memcap: 128mb
  max-sessions: 262144
  prealloc-sessions: 32768
  midstream: true
  async-oneside: false
  
# Defragmentation
defrag:
  memcap: 64mb
  hash-size: 65536
  prealloc: yes
  
# Application layer
app-layer:
  protocols:
    http:
      memcap: 128mb
    tls:
      memcap: 64mb
```

Monitor memory usage:

```bash
# Check Suricata memory
ps aux | grep suricata | awk '{print $6}'

# Detailed memory breakdown
sudo pmap $(pgrep suricata) | tail -1

# Memory statistics
sudo suricata --dump-counters | grep memuse
```

#### Rule Performance

```yaml
# /etc/suricata/suricata.yaml

detect:
  profile: high  # high, medium, low, custom
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  
  sgh-mpm-context: auto  # auto, full, single
  
  inspection-recursion-limit: 3000
  
  # Optimize pattern matching
  prefilter:
    default: mpm
  
  # Fast pattern settings
  mpm-algo: auto  # ac, ac-ks, hs
```

Test different MPM algorithms:

```bash
# Test with Aho-Corasick
sudo sed -i 's/mpm-algo: auto/mpm-algo: ac/' /etc/suricata/suricata.yaml
sudo systemctl restart suricata

# Test with Hyperscan (if available)
sudo sed -i 's/mpm-algo: auto/mpm-algo: hs/' /etc/suricata/suricata.yaml
sudo systemctl restart suricata

# Benchmark
sudo suricata --engine-analysis
```

### Benchmarking

```bash
# Create benchmark script
cat << 'EOF' > benchmark.sh
#!/bin/bash

echo "Starting Suricata benchmark..."

# Capture baseline
START=$(date +%s)
DROPS_START=$(sudo suricata --dump-counters | grep "kernel.drops" | awk '{print $2}')

# Run for 60 seconds
sleep 60

# Capture results
END=$(date +%s)
DROPS_END=$(sudo suricata --dump-counters | grep "kernel.drops" | awk '{print $2}')

# Calculate
DURATION=$((END - START))
DROPS=$((DROPS_END - DROPS_START))

echo "Duration: ${DURATION}s"
echo "Packet drops: $DROPS"
echo "Drop rate: $(echo "scale=2; $DROPS / $DURATION" | bc) drops/sec"

# Show statistics
sudo suricata --dump-counters | grep -E "(capture|decoder|flow)"
EOF

chmod +x benchmark.sh
sudo ./benchmark.sh
```

## Multi-Threading Configuration

### Understanding Thread Types

| Thread Type | Purpose | Count |
|-------------|---------|-------|
| Management | Overall coordination | 1 |
| Receive | Packet capture | 1-4 per interface |
| Decode | Packet decoding | Auto |
| Stream | TCP stream tracking | Auto |
| Detect | Pattern matching | Auto (based on CPUs) |
| Verdict | IPS decisions | 1 (IPS only) |
| Respond | Active response | 1 (if enabled) |
| Output | Logging | 1-2 |

### Optimal Configuration Examples

#### Low Traffic (< 100 Mbps)

```yaml
threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0

af-packet:
  - interface: eth0
    threads: 1
```

#### Medium Traffic (100-500 Mbps)

```yaml
threading:
  set-cpu-affinity: yes
  detect-thread-ratio: 1.5
  
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "0" ]
    - receive-cpu-set:
        cpu: [ "1" ]
    - worker-cpu-set:
        cpu: [ "2-5" ]

af-packet:
  - interface: eth0
    threads: 2
    cluster-type: cluster_flow
```

#### High Traffic (> 1 Gbps)

```yaml
threading:
  set-cpu-affinity: yes
  detect-thread-ratio: 1.5
  
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "0" ]
    - receive-cpu-set:
        cpu: [ "1-3" ]
    - worker-cpu-set:
        cpu: [ "4-15" ]

af-packet:
  - interface: eth0
    threads: 4
    cluster-type: cluster_flow
    cluster-id: 99
    ring-size: 65535
    buffer-size: 65535
```

### Monitor Thread Performance

```bash
# List Suricata threads
ps -eLf | grep suricata

# Monitor CPU usage per thread
top -H -p $(pgrep suricata)

# Thread statistics
sudo suricata --dump-counters | grep thread

# Check for imbalanced threads
sudo suricata --dump-counters | grep "thread.*.packets" | sort -k2 -n
```

## AF_PACKET vs PCAP Mode

### AF_PACKET (Recommended)

**Advantages:**
- Better performance
- Lower CPU usage
- Zero-copy capture
- Load balancing support
- Native Linux kernel support

**Configuration:**

```yaml
af-packet:
  - interface: eth0
    threads: 4
    cluster-id: 99
    cluster-type: cluster_flow  # cluster_flow, cluster_cpu, cluster_qm
    defrag: yes
    use-mmap: yes
    mmap-locked: yes
    ring-size: 65535
    buffer-size: 65535
```

**Cluster Types:**

| Type | Description | Best For |
|------|-------------|----------|
| cluster_flow | Hash-based on flow | Most deployments |
| cluster_cpu | Round-robin | Low traffic |
| cluster_qm | Queue-based | NIC with multiqueue |

**Run with AF_PACKET:**

```bash
# Configuration file
sudo suricata -c /etc/suricata/suricata.yaml --af-packet=eth0

# Command line override
sudo suricata -c /etc/suricata/suricata.yaml --af-packet
```

### PCAP Mode

**Advantages:**
- Cross-platform
- Simple setup
- Good for PCAP file analysis

**Disadvantages:**
- Lower performance
- Higher CPU usage
- Copy-based capture

**Configuration:**

```yaml
pcap:
  - interface: eth0
    buffer-size: 32768
    checksum-checks: auto
```

**Run with PCAP:**

```bash
# Live capture
sudo suricata -c /etc/suricata/suricata.yaml --pcap=eth0

# PCAP file analysis
sudo suricata -c /etc/suricata/suricata.yaml -r capture.pcap
```

### Performance Comparison

```bash
# Benchmark AF_PACKET
sudo suricata -c /etc/suricata/suricata.yaml --af-packet=eth0 &
sleep 60
sudo suricata --dump-counters | grep capture.kernel_drops
sudo pkill suricata

# Benchmark PCAP
sudo suricata -c /etc/suricata/suricata.yaml --pcap=eth0 &
sleep 60
sudo suricata --dump-counters | grep capture.kernel_drops
sudo pkill suricata
```

## IPS Mode (Inline Deployment)

### Understanding IPS Mode

**IDS Mode:** Monitors and alerts (passive)
**IPS Mode:** Monitors, alerts, and blocks (active)

### NFQueue Configuration

#### 1. Setup iptables/nftables

**Using iptables:**

```bash
# Clear existing rules
sudo iptables -F
sudo iptables -X

# Send traffic to NFQueue
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0

# Verify rules
sudo iptables -L -n -v

# Save rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

**Using nftables:**

```bash
# Create nftables config
sudo nano /etc/nftables.conf
```

```
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
        counter queue num 0
    }
    
    chain forward {
        type filter hook forward priority 0; policy accept;
        counter queue num 0
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        counter queue num 0
    }
}
```

```bash
# Apply configuration
sudo nft -f /etc/nftables.conf

# Verify
sudo nft list ruleset
```

#### 2. Configure Suricata for IPS

```yaml
# /etc/suricata/suricata.yaml

nfq:
  mode: accept  # accept or repeat
  repeat-mark: 1
  repeat-mask: 1
  route-queue: 2
  batchcount: 20
  fail-open: yes  # Continue traffic if Suricata fails
```

#### 3. Convert Rules to Drop

```bash
# Modify rules to drop instead of alert
sudo nano /etc/suricata/modify.conf
```

```
# Change critical alerts to drop
re:.*SQL.Injection.* drop
re:.*Malware.* drop
re:.*Trojan.* drop
re:.*Exploit.* drop
```

```bash
# Apply modifications
sudo suricata-update --modify-conf /etc/suricata/modify.conf
```

#### 4. Run in IPS Mode

```bash
# Start Suricata with NFQueue
sudo suricata -c /etc/suricata/suricata.yaml -q 0

# Run as daemon
sudo suricata -c /etc/suricata/suricata.yaml -q 0 -D

# Verify it's running
sudo suricata --dump-counters | grep nfq
```

### Bridge Mode (Inline)

#### Setup Network Bridge

```bash
# Install bridge utilities
sudo apt-get install bridge-utils

# Create bridge
sudo ip link add name br0 type bridge
sudo ip link set br0 up

# Add interfaces
sudo ip link set eth0 master br0
sudo ip link set eth1 master br0

# Verify
sudo brctl show
```

#### Configure Suricata

```yaml
af-packet:
  - interface: br0
    threads: 4
    cluster-type: cluster_flow
    cluster-id: 99
```

#### Test IPS Blocking

```bash
# Create test rule
echo 'drop icmp any any -> any any (msg:"Block ICMP"; sid:1000001; rev:1;)' | sudo tee -a /etc/suricata/rules/block-test.rules

# Update configuration
sudo nano /etc/suricata/suricata.yaml
# Add: - block-test.rules

# Restart
sudo systemctl restart suricata

# Test (should be blocked)
ping 8.8.8.8

# Check alerts
sudo tail /var/log/suricata/fast.log
```

### IPS Best Practices

1. **Start in IDS mode** - Monitor before blocking
2. **Test thoroughly** - Validate rules don't block legitimate traffic
3. **Enable fail-open** - Maintain connectivity if Suricata crashes
4. **Monitor logs** - Watch for blocked traffic
5. **Have bypass procedures** - Quick way to disable blocking
6. **Performance tuning** - IPS requires more resources

## File Extraction

### Enable File Extraction

```yaml
# /etc/suricata/suricata.yaml

outputs:
  - file-store:
      version: 2
      enabled: yes
      dir: /var/log/suricata/files/
      force-magic: yes
      force-hash: [sha256]
      
  - eve-log:
      enabled: yes
      filetype: regular
      types:
        - files:
            force-magic: yes
            force-hash: [sha256]
```

### Configure File Types

```yaml
file-store:
  enabled: yes
  dir: /var/log/suricata/files/
  force-magic: yes
  force-hash: [md5, sha256]
  
  # Store specific file types
  file-types:
    - exe
    - pdf
    - doc
    - xls
    - zip
    - rar
    - jar
```

### Create Extraction Rules

```bash
# Extract Windows executables
sudo nano /etc/suricata/rules/file-extract.rules
```

```
# Extract PE files
alert http any any -> any any (msg:"PE File Download"; filemagic:"PE32 executable"; filestore; sid:1000100; rev:1;)

# Extract PDF files
alert http any any -> any any (msg:"PDF Download"; filemagic:"PDF document"; filestore; sid:1000101; rev:1;)

# Extract ZIP archives
alert http any any -> any any (msg:"ZIP Archive"; filemagic:"Zip archive"; filestore; sid:1000102; rev:1;)

# Extract from specific domain
alert http any any -> any any (msg:"Download from suspicious domain"; http.host; content:"suspicious.com"; filestore; sid:1000103; rev:1;)
```

### Analyze Extracted Files

```bash
# List extracted files
sudo ls -lh /var/log/suricata/files/

# Check file info
sudo file /var/log/suricata/files/file.*

# Calculate hash
sudo sha256sum /var/log/suricata/files/file.*

# Scan with ClamAV
sudo clamscan -r /var/log/suricata/files/

# Check with VirusTotal (using vt-cli)
vt file /var/log/suricata/files/file.* 

# Parse fileinfo from eve.json
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="fileinfo")'
```

### Automated File Analysis

```bash
#!/bin/bash
# analyze-extracted-files.sh

FILES_DIR="/var/log/suricata/files"
REPORT="/tmp/file-analysis-report.txt"

echo "File Analysis Report - $(date)" > $REPORT
echo "======================================" >> $REPORT

for file in $FILES_DIR/file.*; do
    if [ -f "$file" ]; then
        echo "" >> $REPORT
        echo "File: $(basename $file)" >> $REPORT
        echo "Size: $(stat -c%s $file) bytes" >> $REPORT
        echo "Type: $(file -b $file)" >> $REPORT
        echo "SHA256: $(sha256sum $file | awk '{print $1}')" >> $REPORT
        
        # Scan with ClamAV
        clamscan --no-summary $file >> $REPORT 2>&1
    fi
done

cat $REPORT
```

## Protocol Logging

### HTTP Logging

```yaml
# /etc/suricata/suricata.yaml

outputs:
  - http-log:
      enabled: yes
      filename: http.log
      append: yes
      
  - eve-log:
      types:
        - http:
            extended: yes
```

### DNS Logging

```yaml
outputs:
  - eve-log:
      types:
        - dns:
            query: yes
            answer: yes
```

### TLS Logging

```yaml
outputs:
  - eve-log:
      types:
        - tls:
            extended: yes
```

### SSH Logging

```yaml
outputs:
  - eve-log:
      types:
        - ssh
```

### SMTP Logging

```yaml
outputs:
  - eve-log:
      types:
        - smtp:
            extended: yes
```

### Analyze Protocol Logs

```bash
# HTTP requests
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="http") | {timestamp, src_ip, hostname: .http.hostname, url: .http.url, method: .http.http_method}'

# DNS queries
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="dns") | {timestamp, src_ip, query: .dns.rrname, type: .dns.rrtype}'

# TLS connections
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="tls") | {timestamp, src_ip, dest_ip, sni: .tls.sni, subject: .tls.subject}'

# Top HTTP hosts
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="http") | .http.hostname' | sort | uniq -c | sort -rn | head -10

# Top DNS queries
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="dns") | .dns.rrname' | sort | uniq -c | sort -rn | head -10
```

## Statistical Analysis

### Enable Statistics

```yaml
# /etc/suricata/suricata.yaml

outputs:
  - stats:
      enabled: yes
      filename: stats.log
      interval: 8
      
  - eve-log:
      types:
        - stats:
            totals: yes
            threads: yes
```

### Key Statistics

```bash
# Capture statistics
sudo suricata --dump-counters | grep capture

# Decoder statistics
sudo suricata --dump-counters | grep decoder

# Flow statistics
sudo suricata --dump-counters | grep flow

# HTTP statistics
sudo suricata --dump-counters | grep http

# Alert statistics
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="stats") | .stats.capture'
```

### Monitoring Dashboard

```bash
#!/bin/bash
# dashboard.sh - Simple monitoring dashboard

while true; do
    clear
    echo "=== Suricata Dashboard ==="
    echo "Time: $(date)"
    echo ""
    
    # Service status
    echo "Status: $(systemctl is-active suricata)"
    echo ""
    
    # Packet statistics
    echo "Packet Statistics:"
    sudo suricata --dump-counters 2>/dev/null | grep -E "(capture.kernel_packets|capture.kernel_drops)" | sed 's/^/  /'
    echo ""
    
    # Recent alerts
    echo "Recent Alerts (last 5):"
    sudo tail -5 /var/log/suricata/fast.log | sed 's/^/  /'
    echo ""
    
    # CPU and Memory
    echo "Resources:"
    ps aux | grep suricata | grep -v grep | awk '{print "  CPU: " $3 "% | Memory: " $4 "%"}'
    echo ""
    
    sleep 5
done
```

## Integration with Security Tools

### Integration with Wazuh

```yaml
# Wazuh ossec.conf
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>
```

### Integration with TheHive

```python
#!/usr/bin/env python3
# suricata-to-thehive.py

import json
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

api = TheHiveApi('http://thehive:9000', 'API_KEY')

def send_to_thehive(alert_data):
    artifacts = [
        AlertArtifact(dataType='ip', data=alert_data['src_ip']),
        AlertArtifact(dataType='ip', data=alert_data['dest_ip'])
    ]
    
    alert = Alert(
        title=alert_data['alert']['signature'],
        tlp=2,
        tags=['suricata'],
        description=f"Alert from Suricata: {alert_data['alert']['signature']}",
        type='external',
        source='suricata',
        sourceRef=str(alert_data['alert']['signature_id']),
        artifacts=artifacts
    )
    
    response = api.create_alert(alert)
    return response

# Read from eve.json and send alerts
with open('/var/log/suricata/eve.json', 'r') as f:
    for line in f:
        event = json.loads(line)
        if event.get('event_type') == 'alert':
            send_to_thehive(event)
```

### Integration with MISP

```bash
# Install PyMISP
sudo pip3 install pymisp

# Create integration script
cat << 'EOF' > suricata-to-misp.py
#!/usr/bin/env python3
from pymisp import PyMISP
import json

misp = PyMISP('https://misp.local', 'API_KEY', False)

def add_to_misp(event_data):
    event = misp.new_event(
        distribution=0,
        threat_level_id=2,
        analysis=1,
        info=f"Suricata Alert: {event_data['alert']['signature']}"
    )
    
    misp.add_attribute(event, {
        'type': 'ip-src',
        'value': event_data['src_ip']
    })
    
    return event

# Process alerts
with open('/var/log/suricata/eve.json', 'r') as f:
    for line in f:
        event = json.loads(line)
        if event.get('event_type') == 'alert':
            add_to_misp(event)
EOF
```

### Integration with Elasticsearch

```bash
# Use Filebeat (see Log Analysis guide)
# Or send directly via API

curl -X POST "localhost:9200/suricata-$(date +%Y.%m.%d)/_doc" \
  -H 'Content-Type: application/json' \
  -d @- << 'EOF'
{
  "timestamp": "2024-01-15T10:30:45.123456+0000",
  "event_type": "alert",
  "src_ip": "203.0.113.10",
  "dest_ip": "192.168.1.50",
  "alert": {
    "signature": "SQL Injection Attempt",
    "severity": 1
  }
}
EOF
```

### Integration with Slack

```bash
#!/bin/bash
# suricata-to-slack.sh

SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

tail -f /var/log/suricata/eve.json | while read line; do
    event_type=$(echo $line | jq -r '.event_type')
    
    if [ "$event_type" = "alert" ]; then
        signature=$(echo $line | jq -r '.alert.signature')
        src_ip=$(echo $line | jq -r '.src_ip')
        dest_ip=$(echo $line | jq -r '.dest_ip')
        severity=$(echo $line | jq -r '.alert.severity')
        
        if [ "$severity" = "1" ]; then
            curl -X POST $SLACK_WEBHOOK \
              -H 'Content-Type: application/json' \
              -d "{\"text\":\":warning: *Suricata Alert*\n*Signature:* $signature\n*Source:* $src_ip\n*Destination:* $dest_ip\"}"
        fi
    fi
done
```

## Production Deployment Checklist

- [ ] Hardware requirements met (CPU, RAM, NIC)
- [ ] System tuning applied (kernel parameters)
- [ ] NIC tuning configured
- [ ] Suricata optimized for traffic volume
- [ ] Rules updated and tuned
- [ ] Logging configured and tested
- [ ] Log rotation enabled
- [ ] Monitoring in place
- [ ] Alerting configured
- [ ] Backup and recovery procedures
- [ ] Documentation complete
- [ ] Team trained

## Next Steps

You've completed the Suricata documentation:

1. **Review all guides** for comprehensive understanding
2. **Join the community** at https://forum.suricata.io/
3. **Contribute rules** to the community
4. **Share your experience** and help others

---

[← Back: Troubleshooting](08-troubleshooting.md) | [Home](../README.md)
