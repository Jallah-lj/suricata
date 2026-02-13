# PCAP Sample Files for Suricata Testing

This guide provides information about obtaining and using PCAP (Packet Capture) files to test and validate your Suricata IDS deployment.

## Table of Contents

- [What are PCAP Files?](#what-are-pcap-files)
- [Public PCAP Repositories](#public-pcap-repositories)
- [Creating Your Own Test Traffic](#creating-your-own-test-traffic)
- [Using PCAPs with Suricata](#using-pcaps-with-suricata)
- [Scenario-Based Testing](#scenario-based-testing)
- [Best Practices](#best-practices)

---

## What are PCAP Files?

PCAP (Packet Capture) files contain recorded network traffic that can be replayed and analyzed. They are essential for:

- **Testing Suricata rules** without generating live malicious traffic
- **Validating detection capabilities** before production deployment
- **Training and education** in a safe, controlled environment
- **Reproducing incidents** for analysis and investigation
- **Performance testing** with realistic traffic patterns

---

## Public PCAP Repositories

### 1. Malware-Traffic-Analysis.net

**URL:** https://www.malware-traffic-analysis.net/

**Description:** Excellent resource with regular updates of real-world malware traffic captures.

**Content:**
- Exploit kits (Angler, RIG, Neutrino)
- Ransomware (Locky, Cerber, CryptoLocker)
- Banking trojans (Dridex, TrickBot, Emotet)
- Malicious spam campaigns
- Detailed write-ups and IOCs included

**How to Use:**
```bash
# Download a PCAP
wget https://www.malware-traffic-analysis.net/2024/01/15/2024-01-15-traffic-analysis-exercise.pcap.zip

# Extract (password usually "infected")
unzip 2024-01-15-traffic-analysis-exercise.pcap.zip

# Run with Suricata
suricata -r 2024-01-15-traffic-analysis-exercise.pcap -l ./output/
```

**Note:** PCAPs are password-protected (usually `infected`) to prevent accidental execution.

---

### 2. Wireshark Sample Captures

**URL:** https://wiki.wireshark.org/SampleCaptures

**Description:** Large collection of protocol-specific captures for various network scenarios.

**Content:**
- Standard protocols (HTTP, DNS, TLS, SMB)
- Network attacks and exploits
- Malformed packets
- VoIP, streaming, and multimedia
- Wireless and Bluetooth captures

**Best For:**
- Protocol analysis
- Rule development
- Understanding normal vs. abnormal traffic
- Performance testing

**Example Categories:**
- `http.cap` - Basic HTTP traffic
- `dns.cap` - DNS queries and responses
- `tls-*.pcap` - Various TLS handshakes
- `smb2-*.pcap` - SMB protocol versions

---

### 3. NETRESEC Public PCAP Files

**URL:** https://www.netresec.com/?page=PcapFiles

**Description:** Curated list of publicly available PCAP files categorized by type.

**Categories:**
- CTF competitions
- Malware traffic
- Network attacks
- Normal traffic baselines
- Forensic challenges

**Notable Collections:**
- DEFCON CTF captures
- ISTS competition PCAPs
- Honeynet Project captures

---

### 4. PacketLife

**URL:** https://packetlife.net/captures/

**Description:** Protocol-specific captures focused on network engineering and security.

**Content:**
- Routing protocols (OSPF, BGP, EIGRP)
- Switching and VLANs
- Network attacks
- VPN and tunneling protocols

---

### 5. Stratosphere IPS

**URL:** https://www.stratosphereips.org/datasets-overview

**Description:** Academic datasets including both malicious and normal traffic.

**Content:**
- Botnet traffic
- Normal background traffic
- IoT device traffic
- CTU-13 dataset (labeled botnet scenarios)

---

### 6. Canadian Institute for Cybersecurity Datasets

**URL:** https://www.unb.ca/cic/datasets/

**Description:** Comprehensive labeled datasets for machine learning and IDS testing.

**Datasets:**
- **CIC-IDS2017:** Modern intrusion detection evaluation dataset
- **CSE-CIC-IDS2018:** Full week of network traffic with attacks
- **CICDDoS2019:** DDoS attack dataset
- **CIC-IoT-2023:** IoT device traffic with attacks

**Features:**
- Labeled attack types
- CSV flow files included
- Detailed documentation

---

### 7. PCAP Repository Collections

**Other Sources:**
- **Contagio:** http://contagiodump.blogspot.com/ (malware samples and PCAPs)
- **Hybrid Analysis:** https://www.hybrid-analysis.com/ (submit samples, download PCAPs)
- **Shodan.io:** Sample ICS/SCADA traffic captures
- **Internet Archive:** Historical malware campaign captures

---

## Creating Your Own Test Traffic

### Method 1: Using Test VMs

**Setup:**
1. Create isolated virtual network in VirtualBox/VMware
2. Set up victim VMs (Windows, Linux)
3. Set up attacker VM (Kali Linux)
4. Configure network tap/mirror port
5. Run Suricata on monitoring VM

**Capture Traffic:**
```bash
# Start tcpdump to capture
sudo tcpdump -i eth0 -w test-traffic.pcap

# Perform testing actions
# Stop tcpdump with Ctrl+C
```

---

### Method 2: Curl and Wget for HTTP Testing

**Generate HTTP requests:**
```bash
# Normal HTTP request
curl http://testphp.vulnweb.com/

# SQL injection attempt (safe test site)
curl "http://testphp.vulnweb.com/artists.php?artist=1'+OR+'1'='1"

# XSS attempt
curl "http://testphp.vulnweb.com/search.php?test=<script>alert(1)</script>"

# Suspicious user-agent
curl -A "sqlmap/1.0" http://testphp.vulnweb.com/
```

**Capture while testing:**
```bash
# Terminal 1: Start capture
sudo tcpdump -i any -w http-tests.pcap port 80

# Terminal 2: Run curl commands
# Terminal 1: Stop capture when done
```

---

### Method 3: Scapy for Custom Packets

**Install Scapy:**
```bash
pip install scapy
```

**Generate test traffic:**
```python
#!/usr/bin/env python3
from scapy.all import *

# Create port scan simulation
target = "192.168.1.100"
ports = [22, 80, 443, 445, 3389]

for port in ports:
    pkt = IP(dst=target)/TCP(dport=port, flags="S")
    send(pkt, verbose=False)
    print(f"Sent SYN to port {port}")

# Save to PCAP
wrpcap("port-scan-test.pcap", pkts)
```

---

### Method 4: Network Testing Tools

#### Nmap (Port Scanning)
```bash
# TCP SYN scan
sudo nmap -sS -p 1-1000 192.168.1.100

# Service version detection
sudo nmap -sV 192.168.1.100

# OS detection
sudo nmap -O 192.168.1.100
```

#### Hping3 (Packet Crafting)
```bash
# SYN flood simulation (use only on test networks!)
sudo hping3 -S --flood -V -p 80 192.168.1.100

# ICMP flood
sudo hping3 -1 --flood 192.168.1.100

# UDP scan
sudo hping3 --udp -p 53 192.168.1.100
```

#### Metasploit (Exploit Testing)
```bash
# Start Metasploit
msfconsole

# Use an auxiliary scanner
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run

# Use exploit module (test environment only!)
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 192.168.1.100
exploit
```

---

### Method 5: Safe Testing Websites

These sites are designed for security testing and won't get you in trouble:

**Web Application Testing:**
- **DVWA:** http://www.dvwa.co.uk/ (Damn Vulnerable Web Application)
- **WebGoat:** https://owasp.org/www-project-webgoat/
- **Juice Shop:** https://owasp.org/www-project-juice-shop/
- **HackTheBox:** https://www.hackthebox.eu/ (retired machines)
- **TryHackMe:** https://tryhackme.com/

**Sample Traffic Generation:**
```bash
# Generate various HTTP requests to test sites
wget -r -l 2 http://testphp.vulnweb.com/
curl -I http://testhtml5.vulnweb.com/
curl -X POST http://testphp.vulnweb.com/login.php -d "user=admin&pass=admin"
```

---

## Using PCAPs with Suricata

### Basic PCAP Analysis

**Run Suricata on PCAP:**
```bash
# Basic analysis
suricata -r capture.pcap -l ./output/

# With specific config
suricata -c /etc/suricata/suricata.yaml -r capture.pcap -l ./output/

# Verbose mode
suricata -r capture.pcap -l ./output/ -v

# With specific rules
suricata -r capture.pcap -l ./output/ -S custom.rules
```

**Check Results:**
```bash
# View alerts in fast.log
cat output/fast.log

# Parse eve.json for alerts
jq 'select(.event_type=="alert")' output/eve.json | less

# Count alerts by signature
jq -r 'select(.event_type=="alert") | .alert.signature' output/eve.json | sort | uniq -c | sort -rn
```

---

### Advanced PCAP Processing

**Process Multiple PCAPs:**
```bash
#!/bin/bash
for pcap in pcaps/*.pcap; do
    echo "Processing $pcap"
    suricata -r "$pcap" -l "output/$(basename $pcap .pcap)/" -c /etc/suricata/suricata.yaml
done
```

**Extract Specific Flows:**
```bash
# Filter PCAP before Suricata analysis
tcpdump -r large-capture.pcap 'host 192.168.1.100 and port 80' -w filtered.pcap

# Then analyze filtered PCAP
suricata -r filtered.pcap -l ./output/
```

**Performance Testing:**
```bash
# Time the analysis
time suricata -r large-capture.pcap -l ./output/

# With stats
suricata -r capture.pcap -l ./output/ --runmode=autofp --set outputs.1.stats.enabled=yes
```

---

## Scenario-Based Testing

### Scenario 1: Web Attack Detection

**Objective:** Verify detection of web application attacks

**PCAPs Needed:**
- SQL injection attempts
- XSS attacks
- Path traversal
- Command injection

**Test Process:**
```bash
# 1. Download test PCAP
wget https://download.netresec.com/pcap/ek-traffic/2017-04-13-traffic-analysis-exercise.pcap

# 2. Run Suricata
suricata -r 2017-04-13-traffic-analysis-exercise.pcap -l ./web-attack-test/

# 3. Verify alerts
grep "Web Application Attack" ./web-attack-test/fast.log
```

**Expected Results:**
- SQL injection signatures triggered
- XSS detection alerts
- Suspicious user-agent alerts

---

### Scenario 2: Malware C2 Communication

**Objective:** Detect malware command and control traffic

**PCAPs Needed:**
- Trojan communication
- Botnet traffic
- Data exfiltration

**Test Process:**
```bash
# 1. Get malware PCAP from malware-traffic-analysis.net
# 2. Run analysis
suricata -r emotet-traffic.pcap -l ./malware-test/

# 3. Check for C2 alerts
jq 'select(.alert.category=="A Network Trojan was detected")' ./malware-test/eve.json
```

**Expected Results:**
- Malware C2 signatures
- TLS certificate alerts
- Suspicious DNS queries

---

### Scenario 3: Network Scanning

**Objective:** Detect reconnaissance activities

**Generate Test Traffic:**
```bash
# Start capture
sudo tcpdump -i eth0 -w scan-test.pcap &

# Perform scan (on test network only!)
nmap -sS -p- 192.168.1.100

# Stop capture
sudo killall tcpdump

# Analyze
suricata -r scan-test.pcap -l ./scan-test/
```

**Expected Results:**
- Port scan detection alerts
- Multiple connection attempts logged

---

### Scenario 4: DNS Tunneling / DGA Detection

**Objective:** Detect DNS-based threats

**Test Process:**
```bash
# Use DNS-specific PCAP
suricata -r dns-exfil.pcap -l ./dns-test/

# Check DNS events
jq 'select(.event_type=="dns")' ./dns-test/eve.json | less
```

**Look For:**
- Long subdomain names (DNS tunneling)
- High entropy domain names (DGA)
- Unusual query patterns

---

### Scenario 5: Protocol Compliance

**Objective:** Detect protocol violations and anomalies

**PCAPs to Test:**
- Malformed packets
- Protocol violations
- Fragmentation attacks

**Analysis:**
```bash
suricata -r malformed-packets.pcap -l ./protocol-test/

# Check for decoder/stream events
grep "SURICATA" ./protocol-test/fast.log
```

---

## Best Practices

### 1. Organize Your PCAPs

```
pcaps/
├── baseline/           # Normal traffic samples
│   ├── http-normal.pcap
│   ├── dns-normal.pcap
│   └── tls-normal.pcap
├── attacks/           # Attack scenarios
│   ├── sql-injection/
│   ├── malware/
│   └── scans/
├── protocols/         # Protocol-specific
│   ├── smb/
│   ├── ssh/
│   └── rdp/
└── custom/           # Your own captures
```

### 2. Document Your Tests

Create a testing log:
```markdown
# Test Log

## Date: 2024-01-15
## PCAP: emotet-2024-01-10.pcap
## Source: malware-traffic-analysis.net
## Expected: Emotet C2 detection
## Result: ✓ Detected - SID 2024897 triggered
## Notes: JA3 hash match on TLS handshake
```

### 3. Baseline First

Always establish baseline behavior:
```bash
# 1. Run normal traffic
suricata -r normal-traffic.pcap -l ./baseline/

# 2. Count events
jq '.event_type' ./baseline/eve.json | sort | uniq -c

# 3. Use as comparison for attack traffic
```

### 4. Version Control

Keep track of rule versions:
```bash
# Document rule set used
suricata --build-info > test-runs/2024-01-15-rules-version.txt

# Store results with rule version
mkdir test-runs/2024-01-15-v7.0.3/
cp -r output/* test-runs/2024-01-15-v7.0.3/
```

### 5. Sanitize PCAPs

Before sharing, remove sensitive data:
```bash
# Anonymize IP addresses
tcprewrite --infile=capture.pcap --outfile=sanitized.pcap \
  --pnat=192.168.1.0/24:10.0.0.0/24

# Remove specific protocols
tcpdump -r capture.pcap 'not port 22' -w no-ssh.pcap
```

### 6. Performance Testing

Use PCAPs to test system performance:
```bash
# Replay at high speed
tcpreplay --intf1=eth0 --mbps=1000 large-capture.pcap

# Monitor Suricata performance
suricata -r capture.pcap --runmode=workers --set suricata.capture.threads=4
```

---

## PCAP Analysis Tools

### Essential Tools

**Wireshark** - GUI packet analyzer
```bash
wireshark capture.pcap
```

**tcpdump** - Command-line packet capture
```bash
tcpdump -r capture.pcap -n | less
```

**tshark** - Terminal Wireshark
```bash
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```

**NetworkMiner** - Network forensics tool
- Extract files from PCAP
- Identify hosts and services
- Credential harvesting

**Zeek (formerly Bro)** - Network analysis framework
```bash
zeek -r capture.pcap
ls *.log  # Various protocol logs generated
```

---

## Legal and Ethical Considerations

### ⚠️ Important Warnings

1. **Only test on networks you own or have explicit permission to test**
2. **Do not replay malware PCAPs on production networks**
3. **Malicious PCAPs may contain real malware - use isolated environments**
4. **Scanning others' networks without permission is illegal**
5. **Some PCAPs may contain sensitive personal data - handle appropriately**

### Safe Testing Practices

- ✅ Use isolated lab environments
- ✅ Virtual networks with no external connectivity
- ✅ Test/development environments only
- ✅ Documented approval for security testing
- ✅ Password-protected malware samples
- ❌ Production networks for testing
- ❌ Replaying attacks without authorization
- ❌ Public networks or third-party systems

---

## Quick Start Guide

### Complete Testing Workflow

```bash
# 1. Set up directories
mkdir -p ~/suricata-testing/{pcaps,output,rules}
cd ~/suricata-testing

# 2. Download test PCAP
wget https://www.malware-traffic-analysis.net/[latest]/example.pcap

# 3. Update Suricata rules
sudo suricata-update

# 4. Run analysis
suricata -r example.pcap -c /etc/suricata/suricata.yaml -l ./output/

# 5. Review results
cat ./output/fast.log
jq 'select(.event_type=="alert")' ./output/eve.json | jq -s 'group_by(.alert.signature) | map({signature: .[0].alert.signature, count: length})' | jq -r '.[] | "\(.count)\t\(.signature)"' | sort -rn

# 6. Document findings
echo "Date: $(date)" >> test-log.txt
echo "PCAP: example.pcap" >> test-log.txt
echo "Alerts: $(wc -l < ./output/fast.log)" >> test-log.txt
```

---

## Additional Resources

- **Suricata Documentation:** https://suricata.readthedocs.io/en/latest/
- **PCAP Analysis Guide:** https://wiki.wireshark.org/CaptureSetup
- **tcpreplay Project:** https://tcpreplay.appneta.com/
- **Network Forensics:** https://www.netresec.com/
- **Malware Traffic Analysis:** https://www.malware-traffic-analysis.net/training-exercises.html

---

## Contributing

Have a good source for test PCAPs? Found an error? 

Please contribute to this documentation or share your findings with the community!

---

*Last Updated: January 2024*
*Disclaimer: Always follow responsible disclosure practices and legal guidelines.*
