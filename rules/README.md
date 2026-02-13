# Suricata Rule Examples

This directory contains example Suricata detection rules for learning and testing purposes. These rules demonstrate various detection techniques and patterns for common network threats.

## 📁 Directory Structure

```
rules/
├── README.md                         # This file
└── examples/
    ├── basic-detection.rules         # Basic protocol and port scan detection
    ├── web-attacks.rules             # Web application attack detection
    ├── malware-detection.rules       # Malware and C2 communication detection
    └── custom-rules.rules            # Templates for creating your own rules
```

## 📋 Rule Files Overview

### basic-detection.rules

Contains fundamental detection rules for:
- **ICMP Detection**: Ping requests, replies, redirects
- **TCP Connections**: SYN packets, connection attempts to common services
- **UDP Traffic**: DNS, NTP, SNMP, TFTP
- **Port Scans**: Various scanning techniques (SYN, FIN, NULL, XMAS)
- **Basic Protocol Detection**: FTP, HTTP, DNS, TLS

**Use case**: Learning basic rule syntax and understanding network traffic patterns.

**Alerts generated**: High (these are very generic rules for learning)

### web-attacks.rules

Detects common web application attacks:
- **SQL Injection**: UNION SELECT, OR 1=1, time-based, boolean-based
- **Cross-Site Scripting (XSS)**: Script tags, event handlers, JavaScript protocol
- **Directory Traversal**: Path traversal attempts (../, ..\\)
- **Web Shells**: PHP shells, ASP shells, China Chopper
- **Suspicious User-Agents**: sqlmap, Nikto, Nmap, Burp Suite, Metasploit
- **Command Injection**: Shell command patterns
- **File Inclusion**: LFI and RFI attempts
- **XXE Injection**: XML external entity attacks
- **SSRF**: Server-side request forgery attempts

**Use case**: Protecting web applications from common attacks.

**Alerts generated**: Medium to High depending on web traffic

### malware-detection.rules

Identifies malware-related network activity:
- **Command & Control (C2)**: Beacon patterns, suspicious POST requests
- **Domain Generation Algorithm (DGA)**: Randomized domains, high entropy
- **Cryptocurrency Mining**: Stratum protocol, pool connections, XMRig
- **Ransomware Indicators**: Tor connections, Bitcoin references, SMB exploits
- **Suspicious Downloads**: Executables, scripts, macro-enabled documents
- **Backdoors and RATs**: Netcat, reverse shells, Meterpreter, Cobalt Strike
- **Malicious TLS**: Self-signed certificates, suspicious CNs
- **Data Exfiltration**: Large uploads, DNS tunneling, FTP uploads

**Use case**: Detecting malware infections and post-exploitation activity.

**Alerts generated**: Low to Medium (depends on network environment)

### custom-rules.rules

Provides templates for creating your own rules:
- HTTP detection templates
- Content-based detection
- DNS query detection
- Port-based detection
- TLS certificate detection
- User-Agent detection
- Threshold-based detection
- File type detection
- PCRE pattern matching
- Flowbits for stateful detection
- Bidirectional traffic detection
- Multiple content matches

**Use case**: Starting point for writing custom rules specific to your environment.

**Alerts generated**: None (templates are commented out)

## 🚀 How to Use These Rules

### Option 1: Copy to Suricata Rules Directory

```bash
# Copy all example rules
sudo cp rules/examples/*.rules /etc/suricata/rules/

# Or copy specific files
sudo cp rules/examples/web-attacks.rules /etc/suricata/rules/
```

### Option 2: Reference in suricata.yaml

Edit `/etc/suricata/suricata.yaml`:

```yaml
rule-files:
  - suricata.rules  # Default rules
  - /path/to/this/repo/rules/examples/basic-detection.rules
  - /path/to/this/repo/rules/examples/web-attacks.rules
  - /path/to/this/repo/rules/examples/malware-detection.rules
```

### Option 3: Testing with PCAP Files

```bash
# Test rules against a PCAP file
sudo suricata -c /etc/suricata/suricata.yaml -r sample.pcap -l /tmp/ \
  -S /path/to/rules/examples/web-attacks.rules
```

## ⚙️ Configuring Rules

### Enable Rules

```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Start Suricata with new rules
sudo systemctl restart suricata

# Or run manually
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

### Disable Specific Rules

Create a `disable.conf` file:

```bash
# Disable by SID
1000001
1000002

# Or edit the rule file and comment out rules
# alert icmp any any -> $HOME_NET any (...)
```

Reference in suricata.yaml:

```yaml
# Disable specific rules
disable-file: /etc/suricata/disable.conf
```

### Modify Rule Thresholds

For noisy rules, adjust thresholds to reduce alerts:

```
# Original rule (may be too sensitive)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Connection"; flags:S; sid:1000011;)

# Modified with threshold (alert only once per source per minute)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Connection"; flags:S; threshold:type limit, track by_src, count 1, seconds 60; sid:1000011;)
```

## 📊 Understanding Rule Output

### fast.log Format

```
12/15/2023-10:30:45.123456 [**] [1:1000100:1] SQL Injection - UNION SELECT Detected [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.1.100:54321 -> 10.0.0.50:80
```

Breaking it down:
- `12/15/2023-10:30:45.123456` - Timestamp
- `[1:1000100:1]` - [Generator ID:Signature ID:Revision]
- `SQL Injection...` - Alert message
- `[Classification: ...]` - Rule classification
- `[Priority: 1]` - Alert priority (1=high, 2=medium, 3=low)
- `{TCP}` - Protocol
- `192.168.1.100:54321 -> 10.0.0.50:80` - Source and destination

### eve.json Format

```json
{
  "timestamp": "2023-12-15T10:30:45.123456+0000",
  "flow_id": 123456789,
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "10.0.0.50",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000100,
    "rev": 1,
    "signature": "SQL Injection - UNION SELECT Detected",
    "category": "Web Application Attack",
    "severity": 1
  }
}
```

## 🎯 Tuning for Your Environment

### Reduce False Positives

1. **Use HOME_NET correctly** - Define your network accurately in suricata.yaml
2. **Add thresholds** - Limit alerts from noisy rules
3. **Whitelist known good traffic** - Use pass rules for legitimate activity
4. **Disable irrelevant rules** - Don't use rules for services you don't run
5. **Test in monitor mode** - Observe alerts before taking action

### Example: Whitelist Legitimate Scanner

```
# Allow your vulnerability scanner
pass http 192.168.1.5 any -> $HOME_NET any (msg:"Allow Internal Scanner"; sid:2000001;)
```

### Example: Threshold Adjustment

```
# Original: Too many alerts
alert tcp any any -> $HOME_NET 80 (msg:"HTTP Connection"; ...)

# Fixed: Limit to 1 alert per source per 5 minutes
alert tcp any any -> $HOME_NET 80 (msg:"HTTP Connection"; threshold:type limit, track by_src, count 1, seconds 300; ...)
```

## 📈 Monitoring Rule Performance

### Check Rule Statistics

```bash
# View rule statistics
sudo suricata -T -c /etc/suricata/suricata.yaml --dump-config

# Check which rules are loaded
sudo suricata -c /etc/suricata/suricata.yaml --dump-config | grep "rule-files"

# Monitor stats.log for rule performance
tail -f /var/log/suricata/stats.log
```

### Analyze Alert Frequency

```bash
# Count alerts by signature
sudo cat /var/log/suricata/fast.log | awk -F'\\[\\*\\*\\]' '{print $2}' | sort | uniq -c | sort -rn | head -20

# Using jq with eve.json
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn | head -20
```

## 🔧 Testing Rules

### Syntax Validation

```bash
# Test all rules
sudo suricata -T -c /etc/suricata/suricata.yaml

# Test specific rule file
sudo suricata -T -c /etc/suricata/suricata.yaml -S /path/to/rule/file.rules
```

### Generate Test Traffic

#### Test ICMP Detection

```bash
# From another machine
ping 192.168.1.100
```

#### Test HTTP Detection

```bash
# Test web attack detection
curl "http://192.168.1.100/page?id=1' UNION SELECT * FROM users--"
```

#### Test Port Scan Detection

```bash
# Perform a port scan
nmap -sS -p 1-100 192.168.1.100
```

#### Test with Sample PCAP

```bash
# Download sample PCAP
wget https://www.malware-traffic-analysis.net/sample.pcap

# Run Suricata against PCAP
sudo suricata -c /etc/suricata/suricata.yaml -r sample.pcap -l /tmp/

# Check alerts
cat /tmp/fast.log
```

## 📚 Learning Resources

### Rule Writing Guides

- [Official Suricata Rule Format](https://suricata.readthedocs.io/en/latest/rules/index.html)
- [Rule Keywords Reference](https://suricata.readthedocs.io/en/latest/rules/rule-keywords.html)
- [Writing Rules Documentation](../docs/06-custom-rules.md)

### Practice Resources

- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) - Real PCAP samples
- [DVWA (Damn Vulnerable Web Application)](http://www.dvwa.co.uk/) - Web attack testing
- [Test My IDS](http://testmyids.com/) - Simple IDS test

### Rule Repositories

- [Emerging Threats Open](https://rules.emergingthreats.net/open/) - Free ruleset
- [Proofpoint ET Pro](https://www.proofpoint.com/us/threat-insight/et-pro-ruleset) - Commercial ruleset
- [GitHub Suricata Rules](https://github.com/topics/suricata-rules) - Community rules

## ⚠️ Important Notes

### For Learning Purposes

These rules are designed for **educational purposes** and may:
- Generate false positives in production environments
- Be too generic for real-world use
- Need tuning for your specific network
- Require adjustment of thresholds

### Production Deployment

Before using in production:

1. ✅ **Test thoroughly** in a lab environment
2. ✅ **Tune thresholds** to reduce false positives  
3. ✅ **Whitelist known good** traffic
4. ✅ **Monitor alert volume** and adjust
5. ✅ **Document changes** to rules
6. ✅ **Use professional rulesets** (Emerging Threats, etc.) alongside these examples

### SID Ranges

- **1-999,999**: Reserved for public rulesets (ET, VRT, etc.)
- **1,000,000-1,899,999**: Examples in this repository
- **1,900,000-1,999,999**: Reserved for your custom rules

## 🤝 Contributing

Want to contribute more rule examples?

1. Fork this repository
2. Add your rules to the appropriate file
3. Document the rule purpose and use case
4. Test the rules
5. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

## 📞 Support

- **Documentation**: See [docs/](../docs/) for comprehensive guides
- **Issues**: Open an issue on GitHub
- **Suricata Forums**: [forum.suricata.io](https://forum.suricata.io/)

## 📄 License

These rule examples are provided under the MIT License. See [LICENSE](../LICENSE) for details.

---

**Remember**: These are example rules for learning. Always test and tune rules for your specific environment before production use!

[← Back to Main README](../README.md)
