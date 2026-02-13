# Troubleshooting Guide

This guide covers common Suricata issues, their solutions, and debugging techniques to keep your IDS running smoothly.

## Table of Contents

- [Common Errors and Solutions](#common-errors-and-solutions)
- [Checking Suricata Status](#checking-suricata-status)
- [Debugging Techniques](#debugging-techniques)
- [Log File Locations](#log-file-locations)
- [Performance Issues](#performance-issues)
- [Network Interface Problems](#network-interface-problems)
- [Rule Issues](#rule-issues)
- [Configuration Problems](#configuration-problems)

## Common Errors and Solutions

### Error 1: Interface Not Found

**Error Message:**
```
[ERROR] - Unable to find interface "eth0"
```

**Causes:**
- Interface name is incorrect
- Interface doesn't exist
- Permission issues

**Solutions:**

```bash
# List all available interfaces
ip link show
# or
ifconfig -a

# Check for interface
ip addr show eth0

# Update suricata.yaml with correct interface
sudo nano /etc/suricata/suricata.yaml
# Find af-packet section and update interface name

# Verify configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Restart Suricata
sudo systemctl restart suricata
```

### Error 2: Permission Denied

**Error Message:**
```
[ERROR] - Permission denied opening device eth0
```

**Causes:**
- Running without root privileges
- Insufficient capabilities
- SELinux/AppArmor restrictions

**Solutions:**

```bash
# Run with sudo
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Set capabilities (preferred over running as root)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/suricata

# Check current capabilities
getcap /usr/bin/suricata

# Run as suricata user with capabilities
sudo -u suricata suricata -c /etc/suricata/suricata.yaml -i eth0

# Check SELinux status (CentOS/RHEL)
sestatus

# Set SELinux to permissive (temporary)
sudo setenforce 0

# Disable SELinux permanently
sudo nano /etc/selinux/config
# Set: SELINUX=disabled
```

### Error 3: No Alerts Being Generated

**Symptoms:**
- Suricata is running
- Traffic is flowing
- No alerts in logs

**Troubleshooting Steps:**

```bash
# 1. Check if rules are loaded
sudo suricata --dump-config | grep rule-files

# 2. Verify rule file exists and has content
sudo ls -lh /var/lib/suricata/rules/suricata.rules
sudo wc -l /var/lib/suricata/rules/suricata.rules

# 3. Test with simple ICMP rule
echo 'alert icmp any any -> any any (msg:"ICMP Test"; sid:1000001; rev:1;)' | sudo tee /etc/suricata/rules/test.rules

# 4. Update suricata.yaml to include test rules
sudo nano /etc/suricata/suricata.yaml
# Add: - test.rules

# 5. Restart Suricata
sudo systemctl restart suricata

# 6. Generate test traffic
ping -c 5 8.8.8.8

# 7. Check for alerts
sudo tail -f /var/log/suricata/fast.log
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# 8. Check if interface is receiving packets
sudo tcpdump -i eth0 -c 10

# 9. Verify Suricata is capturing
sudo suricata --dump-counters | grep capture
```

### Error 4: High Packet Drop Rates

**Symptoms:**
```
[NOTICE] - Capture: Kernel drops 45678 packets
```

**Causes:**
- Insufficient CPU resources
- Memory constraints
- Network card buffer issues
- Too many rules loaded

**Solutions:**

```bash
# 1. Check current packet stats
sudo suricata --dump-counters | grep -E "(capture|drop)"

# 2. Increase ring buffer size
sudo nano /etc/suricata/suricata.yaml
```

```yaml
af-packet:
  - interface: eth0
    threads: 4
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    ring-size: 65535      # Increase from default
    buffer-size: 65535    # Increase from default
```

```bash
# 3. Increase system buffer
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.rmem_default=134217728

# Make permanent
echo "net.core.rmem_max=134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.rmem_default=134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 4. Enable multi-threading
sudo nano /etc/suricata/suricata.yaml
```

```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 1, 2 ]
    - worker-cpu-set:
        cpu: [ 3, 4, 5, 6 ]
```

```bash
# 5. Optimize rules
sudo suricata-update --disable-conf /etc/suricata/disable.conf

# 6. Restart and monitor
sudo systemctl restart suricata
watch -n 5 'sudo suricata --dump-counters | grep capture'
```

### Error 5: Memory Issues

**Error Message:**
```
[ERROR] - Memory allocation failed
[ERROR] - Out of memory
```

**Solutions:**

```bash
# 1. Check current memory usage
free -h
ps aux | grep suricata

# 2. Check Suricata memory settings
sudo suricata --dump-config | grep memcap

# 3. Reduce memory usage in suricata.yaml
sudo nano /etc/suricata/suricata.yaml
```

```yaml
# Reduce memcaps
flow:
  memcap: 64mb        # Reduce from 128mb
  
stream:
  memcap: 32mb        # Reduce from 64mb
  
defrag:
  memcap: 16mb        # Reduce from 32mb
```

```bash
# 4. Limit rules
sudo suricata-update \
  --disable-conf /etc/suricata/disable.conf \
  --enable-conf /etc/suricata/enable.conf

# 5. Add swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Make permanent
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 6. Restart Suricata
sudo systemctl restart suricata
```

### Error 6: Configuration Test Failed

**Error Message:**
```
[ERROR] - Configuration provided was successfully loaded but failed validation
```

**Solutions:**

```bash
# 1. Run test with verbose output
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# 2. Check for syntax errors
sudo suricata -T -c /etc/suricata/suricata.yaml 2>&1 | grep ERROR

# 3. Validate YAML syntax
sudo python3 -c "import yaml; yaml.safe_load(open('/etc/suricata/suricata.yaml'))"

# 4. Check common issues:

# Missing colon after key
# Wrong indentation (use spaces, not tabs)
# Missing quotes around special characters
# Incorrect path to rules

# 5. Restore backup if needed
sudo cp /etc/suricata/suricata.yaml.backup /etc/suricata/suricata.yaml

# 6. Test again
sudo suricata -T -c /etc/suricata/suricata.yaml
```

### Error 7: Rule Syntax Errors

**Error Message:**
```
[ERROR] - Error parsing rule: invalid signature
[ERROR] - sid:1000001 invalid rule
```

**Solutions:**

```bash
# 1. Test specific rule file
sudo suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules

# 2. Common rule syntax issues:

# Missing semicolon
alert tcp any any -> any 80 (msg:"Test" sid:1)
# Should be:
alert tcp any any -> any 80 (msg:"Test"; sid:1;)

# Missing quotes
alert tcp any any -> any 80 (msg:Test; sid:1;)
# Should be:
alert tcp any any -> any 80 (msg:"Test"; sid:1;)

# Invalid SID (must be numeric)
alert tcp any any -> any 80 (msg:"Test"; sid:test;)
# Should be:
alert tcp any any -> any 80 (msg:"Test"; sid:1000001;)

# 3. Validate rule online
# Visit: https://suricata-ids.org/rule-editor/

# 4. Check for duplicate SIDs
grep -oP 'sid:\d+' /etc/suricata/rules/local.rules | sort | uniq -d

# 5. Comment out problematic rule
sudo nano /etc/suricata/rules/local.rules
# Add # at the beginning of the line

# 6. Test again
sudo suricata -T -c /etc/suricata/suricata.yaml
```

### Error 8: Failed to Initialize

**Error Message:**
```
[ERROR] - Failure in initialization
[ERROR] - Engine failed to initialize
```

**Solutions:**

```bash
# 1. Check logs for specific error
sudo tail -50 /var/log/suricata/suricata.log | grep ERROR

# 2. Verify all paths exist
sudo ls -la /var/log/suricata/
sudo ls -la /var/run/suricata/

# 3. Check permissions
sudo chown -R suricata:suricata /var/log/suricata/
sudo chown -R suricata:suricata /var/run/suricata/
sudo chown -R suricata:suricata /var/lib/suricata/

# 4. Create missing directories
sudo mkdir -p /var/log/suricata
sudo mkdir -p /var/run/suricata
sudo mkdir -p /var/lib/suricata/rules

# 5. Reset to default configuration
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.broken
sudo apt-get install --reinstall suricata

# 6. Try minimal configuration
sudo suricata -c /etc/suricata/suricata.yaml --init-errors-fatal
```

## Checking Suricata Status

### Service Status

```bash
# Check if running
sudo systemctl status suricata

# Detailed status
sudo systemctl status suricata -l

# Check if enabled at boot
sudo systemctl is-enabled suricata

# Check process
ps aux | grep suricata

# Check listening ports
sudo netstat -tlnp | grep suricata
```

### Performance Statistics

```bash
# Display counters
sudo suricata --dump-counters

# Filter specific counters
sudo suricata --dump-counters | grep capture
sudo suricata --dump-counters | grep decoder
sudo suricata --dump-counters | grep detect

# Monitor in real-time
watch -n 5 'sudo suricata --dump-counters | head -30'
```

### Check Configuration

```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Dump configuration
sudo suricata --dump-config

# Check specific settings
sudo suricata --dump-config | grep interface
sudo suricata --dump-config | grep rules
sudo suricata --dump-config | grep threads
```

### Verify Rules

```bash
# List loaded rules
sudo suricata --list-keywords

# Test rule syntax
sudo suricata -T -S /etc/suricata/rules/local.rules

# Count rules
sudo wc -l /var/lib/suricata/rules/suricata.rules
```

## Debugging Techniques

### Verbose Mode

```bash
# Run in verbose mode
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v

# Very verbose (debug level)
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -vv

# Maximum verbosity
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -vvv
```

### Log Levels

```bash
# Edit suricata.yaml for debug logging
sudo nano /etc/suricata/suricata.yaml
```

```yaml
logging:
  default-log-level: debug
  outputs:
  - console:
      enabled: yes
      level: debug
  - file:
      enabled: yes
      level: debug
      filename: /var/log/suricata/suricata.log
```

### Test with PCAP

```bash
# Capture traffic
sudo tcpdump -i eth0 -w test.pcap -c 100

# Run Suricata against PCAP
sudo suricata -c /etc/suricata/suricata.yaml -r test.pcap -l /tmp/suricata-test/

# Check results
ls -lh /tmp/suricata-test/
cat /tmp/suricata-test/fast.log
cat /tmp/suricata-test/eve.json | jq 'select(.event_type=="alert")'
```

### Engine Analysis

```bash
# Enable engine analysis
sudo suricata --engine-analysis -c /etc/suricata/suricata.yaml

# Output files in current directory
ls -lh rules_*.txt

# Review rule analysis
cat rules_analysis.txt
```

### Profiling

```bash
# Enable profiling in suricata.yaml
sudo nano /etc/suricata/suricata.yaml
```

```yaml
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
  keywords:
    enabled: yes
    filename: keyword_perf.log
    append: yes
```

```bash
# Restart and check logs
sudo systemctl restart suricata
sudo tail -f /var/log/suricata/rule_perf.log
```

### Packet Logging

```bash
# Enable packet logging
sudo nano /etc/suricata/suricata.yaml
```

```yaml
outputs:
  - pcap-log:
      enabled: yes
      filename: suspicious.pcap
```

```bash
# Check captured packets
sudo tcpdump -r /var/log/suricata/suspicious.pcap
```

## Log File Locations

### Standard Locations

```bash
# Debian/Ubuntu
/var/log/suricata/eve.json          # JSON events
/var/log/suricata/fast.log          # Fast alerts
/var/log/suricata/stats.log         # Statistics
/var/log/suricata/suricata.log      # Engine log
/var/log/suricata/http.log          # HTTP logs
/var/log/suricata/dns.log           # DNS logs
/var/log/suricata/tls.log           # TLS logs

# Configuration
/etc/suricata/suricata.yaml         # Main config
/etc/suricata/rules/                # Rules directory
/var/lib/suricata/rules/            # Managed rules

# Runtime
/var/run/suricata/                  # PID and sockets
```

### Check Log Locations

```bash
# From configuration
sudo grep -A 10 "^outputs:" /etc/suricata/suricata.yaml

# Find log directory
sudo suricata --dump-config | grep default-log-dir
```

### Monitor Logs

```bash
# Watch all activity
sudo tail -f /var/log/suricata/suricata.log

# Watch alerts
sudo tail -f /var/log/suricata/fast.log

# Watch JSON events
sudo tail -f /var/log/suricata/eve.json | jq '.'

# Watch specific event type
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# Multi-tail multiple logs
sudo multitail /var/log/suricata/suricata.log /var/log/suricata/fast.log
```

## Performance Issues

### Diagnose Performance Problems

```bash
# 1. Check CPU usage
top -p $(pgrep suricata)
htop -p $(pgrep suricata)

# 2. Check memory usage
ps aux | grep suricata
free -h

# 3. Check packet drops
sudo suricata --dump-counters | grep -i drop
sudo suricata --dump-counters | grep -i capture

# 4. Check interface statistics
sudo ethtool -S eth0 | grep -i drop
sudo ifconfig eth0 | grep -i drop

# 5. Monitor I/O
sudo iotop -p $(pgrep suricata)

# 6. Check disk space
df -h /var/log/suricata/
```

### Performance Optimization

#### 1. Multi-Threading

```yaml
# /etc/suricata/suricata.yaml
threading:
  set-cpu-affinity: yes
  detect-thread-ratio: 1.5

af-packet:
  - interface: eth0
    threads: auto  # or specific number
```

#### 2. Buffer Optimization

```yaml
af-packet:
  - interface: eth0
    ring-size: 65535
    buffer-size: 65535
```

#### 3. Rule Optimization

```bash
# Disable unnecessary rules
sudo nano /etc/suricata/disable.conf
```

```
# Disable entire categories
group:emerging-dos.rules
group:emerging-games.rules
group:emerging-p2p.rules

# Disable specific rules
2000123
2000456
```

```bash
# Update with optimizations
sudo suricata-update --disable-conf /etc/suricata/disable.conf
```

#### 4. Flow Optimization

```yaml
flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  
stream:
  memcap: 64mb
  max-sessions: 262144
```

#### 5. AF_PACKET Tuning

```bash
# Increase kernel buffers
sudo sysctl -w net.core.rmem_max=268435456
sudo sysctl -w net.core.rmem_default=268435456
sudo sysctl -w net.core.wmem_max=268435456
sudo sysctl -w net.core.wmem_default=268435456

# Make permanent
cat << EOF | sudo tee -a /etc/sysctl.conf
net.core.rmem_max=268435456
net.core.rmem_default=268435456
net.core.wmem_max=268435456
net.core.wmem_default=268435456
EOF

sudo sysctl -p
```

## Network Interface Problems

### Interface Not Capturing

```bash
# 1. Verify interface exists
ip link show

# 2. Bring interface up
sudo ip link set eth0 up

# 3. Check interface is in promiscuous mode
ifconfig eth0 | grep PROMISC
# or
ip link show eth0 | grep PROMISC

# 4. Enable promiscuous mode
sudo ip link set eth0 promisc on

# 5. Test with tcpdump
sudo tcpdump -i eth0 -c 10

# 6. Check for firewall rules
sudo iptables -L -n -v

# 7. Verify no other process is using interface
sudo lsof | grep eth0
```

### Interface Permissions

```bash
# Check user/group
id suricata

# Add suricata user to required groups
sudo usermod -a -G suricata,pcap suricata

# Set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/suricata

# Verify
getcap /usr/bin/suricata
```

## Rule Issues

### Rules Not Loading

```bash
# 1. Check rule file path
sudo suricata --dump-config | grep rule-files

# 2. Verify file exists
sudo ls -la /var/lib/suricata/rules/suricata.rules

# 3. Check file content
sudo head -20 /var/lib/suricata/rules/suricata.rules

# 4. Verify syntax
sudo suricata -T -S /var/lib/suricata/rules/suricata.rules

# 5. Check for errors
sudo suricata -T -c /etc/suricata/suricata.yaml 2>&1 | grep -i error
```

### Rule Update Issues

```bash
# 1. Update with verbose output
sudo suricata-update -v

# 2. Force update
sudo suricata-update --force

# 3. Check network connectivity
curl -I https://rules.emergingthreats.net

# 4. Clear cache
sudo rm -rf /var/lib/suricata/update/cache/

# 5. Reinitialize
sudo suricata-update --force
```

## Configuration Problems

### YAML Syntax Issues

```bash
# Validate YAML
python3 << EOF
import yaml
try:
    with open('/etc/suricata/suricata.yaml', 'r') as f:
        yaml.safe_load(f)
    print("YAML syntax is valid")
except yaml.YAMLError as e:
    print(f"YAML syntax error: {e}")
EOF

# Check indentation (must be spaces, not tabs)
sudo cat -A /etc/suricata/suricata.yaml | grep $'\t'
```

### Reset to Default Config

```bash
# Backup current config
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup

# Get default config
sudo cp /etc/suricata/suricata.yaml.default /etc/suricata/suricata.yaml

# Or reinstall package
sudo apt-get install --reinstall suricata

# Restore specific settings
sudo nano /etc/suricata/suricata.yaml
```

## Diagnostic Scripts

### Complete Health Check

```bash
#!/bin/bash
# suricata-healthcheck.sh

echo "=== Suricata Health Check ==="
echo ""

# Service status
echo "1. Service Status:"
systemctl is-active suricata && echo "   ✓ Running" || echo "   ✗ Not running"
echo ""

# Configuration test
echo "2. Configuration Test:"
suricata -T -c /etc/suricata/suricata.yaml > /dev/null 2>&1 && echo "   ✓ Valid" || echo "   ✗ Invalid"
echo ""

# Rules loaded
echo "3. Rules:"
rule_count=$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo "0")
echo "   Rules loaded: $rule_count"
echo ""

# Log files
echo "4. Log Files:"
[ -f /var/log/suricata/eve.json ] && echo "   ✓ eve.json exists" || echo "   ✗ eve.json missing"
[ -f /var/log/suricata/fast.log ] && echo "   ✓ fast.log exists" || echo "   ✗ fast.log missing"
echo ""

# Recent alerts
echo "5. Recent Activity:"
recent_alerts=$(sudo cat /var/log/suricata/eve.json 2>/dev/null | jq -r 'select(.event_type=="alert")' | tail -5 | wc -l)
echo "   Recent alerts: $recent_alerts"
echo ""

# Packet drops
echo "6. Performance:"
if command -v suricata &> /dev/null; then
    drops=$(sudo suricata --dump-counters 2>/dev/null | grep -i "kernel.drops" | awk '{print $2}')
    echo "   Kernel drops: ${drops:-0}"
fi
echo ""

# Disk space
echo "7. Disk Space:"
df -h /var/log/suricata/ | tail -1 | awk '{print "   Used: " $5}'
```

Make it executable and run:

```bash
sudo chmod +x suricata-healthcheck.sh
sudo ./suricata-healthcheck.sh
```

## Getting Help

### Community Resources

```bash
# Official documentation
https://suricata.readthedocs.io/

# Community forum
https://forum.suricata.io/

# GitHub issues
https://github.com/OISF/suricata/issues

# Mailing list
https://lists.openinfosecfoundation.org/mailman/listinfo/oisf-users
```

### Collecting Debug Information

```bash
# Create debug bundle
mkdir suricata-debug
cd suricata-debug

# Copy configuration
sudo cp /etc/suricata/suricata.yaml .

# Copy recent logs
sudo tail -1000 /var/log/suricata/suricata.log > suricata.log
sudo tail -1000 /var/log/suricata/stats.log > stats.log

# System information
uname -a > system_info.txt
cat /etc/os-release >> system_info.txt
suricata --version >> system_info.txt

# Rule count
wc -l /var/lib/suricata/rules/*.rules > rule_count.txt

# Create archive
cd ..
tar czf suricata-debug.tar.gz suricata-debug/
```

## Next Steps

Now that you can troubleshoot Suricata:

1. **Optimize Performance**: See [Advanced Topics](09-advanced-topics.md)
2. **Review Logs**: See [Log Analysis](07-log-analysis.md)
3. **Tune Rules**: See [Rule Management](05-rule-management.md)

---

[← Back: Log Analysis](07-log-analysis.md) | [Home](../README.md) | [Next: Advanced Topics →](09-advanced-topics.md)
