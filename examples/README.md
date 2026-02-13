# Suricata Examples Directory

This directory contains practical examples, sample files, and documentation to help you understand and work with Suricata IDS.

## Contents

### 📁 [log-samples/](./log-samples/)
Sample log files demonstrating Suricata's output formats:

- **eve.json.example** - 20+ realistic event examples including alerts, HTTP, DNS, TLS, flow events, and more
- **fast.log.example** - 20+ alert examples in fast.log format showing various attack types
- **README.md** - Complete guide to EVE JSON format with parsing examples
- **fast.log.README.md** - Guide to fast.log format with analysis commands

**What you'll learn:**
- Understanding different event types (alerts, HTTP, DNS, TLS, flows)
- Parsing and analyzing Suricata logs
- Using tools like jq, grep, and awk for log analysis
- Integrating logs with SIEM systems

### 📄 [alert-examples.md](./alert-examples.md)
Comprehensive guide to investigating and responding to Suricata alerts:

**Includes:**
- 7 real-world alert scenarios with detailed investigation steps
- SQL injection, XSS, malware C2, port scanning, and more
- Step-by-step investigation workflows
- False positive identification and handling
- Quick reference table of common alerts
- Log analysis commands and techniques

**Perfect for:**
- Security analysts responding to alerts
- Understanding what alerts mean and how to investigate
- Learning proper incident response procedures
- Tuning Suricata to reduce false positives

### 📁 [pcap-samples/](./pcap-samples/)
Guide to finding and using PCAP files for testing:

- **Links to public PCAP repositories** (malware-traffic-analysis.net, Wireshark samples, etc.)
- **Creating your own test traffic** with curl, nmap, scapy, and other tools
- **Using PCAPs with Suricata** for offline analysis
- **Scenario-based testing** examples (web attacks, malware C2, network scans)
- **Legal and ethical considerations**

**Perfect for:**
- Testing Suricata rules without live traffic
- Training and education
- Validating detection capabilities
- Performance testing

## Quick Start

### 1. Explore Log Formats

```bash
# View EVE JSON samples
cd log-samples/
cat eve.json.example | jq .

# View fast.log samples  
cat fast.log.example

# Read the format guides
less README.md
less fast.log.README.md
```

### 2. Learn Alert Investigation

```bash
# Read alert investigation guide
less alert-examples.md

# Practice analyzing alerts
jq 'select(.event_type=="alert")' log-samples/eve.json.example
grep "Priority: 1" log-samples/fast.log.example
```

### 3. Test with PCAPs

```bash
# Read PCAP guide
less pcap-samples/README.md

# Download a test PCAP (example)
wget https://www.malware-traffic-analysis.net/[date]/sample.pcap

# Run Suricata against it
suricata -r sample.pcap -l ./test-output/

# Analyze results
cat test-output/fast.log
jq 'select(.event_type=="alert")' test-output/eve.json
```

## Use Cases

### For Security Analysts
- **Learn** what different alerts mean and how to respond
- **Practice** investigating alerts with realistic examples
- **Reference** common alert patterns and investigation steps
- **Understand** log formats for better analysis

### For Network Engineers
- **Test** Suricata rules with sample traffic
- **Validate** detection capabilities before production
- **Benchmark** performance with realistic PCAPs
- **Understand** network protocols and attack patterns

### For Students & Researchers
- **Study** real-world attack patterns safely
- **Experiment** with IDS detection and evasion
- **Analyze** network traffic without generating it
- **Learn** practical incident response skills

### For DevOps/Security Engineers
- **Automate** log parsing and analysis
- **Integrate** Suricata with SIEM systems
- **Develop** custom detection rules
- **Build** security monitoring dashboards

## Practical Examples

### Example 1: Find All SQL Injection Alerts

```bash
# From fast.log
grep "SQL Injection" log-samples/fast.log.example

# From eve.json with details
jq 'select(.event_type=="alert" and (.alert.signature | contains("SQL Injection")))' \
  log-samples/eve.json.example
```

### Example 2: Analyze Top Attackers

```bash
# Extract source IPs from alerts
jq -r 'select(.event_type=="alert") | .src_ip' log-samples/eve.json.example | \
  sort | uniq -c | sort -rn
```

### Example 3: Review TLS Certificates

```bash
# Extract all TLS certificate information
jq 'select(.event_type=="tls") | {subject: .tls.subject, issuer: .tls.issuerdn, fingerprint: .tls.fingerprint}' \
  log-samples/eve.json.example
```

### Example 4: Count Events by Type

```bash
jq -r '.event_type' log-samples/eve.json.example | sort | uniq -c
```

### Example 5: Find High-Priority Alerts

```bash
# fast.log
grep "Priority: 1" log-samples/fast.log.example

# eve.json
jq 'select(.event_type=="alert" and .alert.severity==1)' log-samples/eve.json.example
```

## Learning Path

### Beginner
1. Start with **alert-examples.md** to understand alert types
2. Review **log-samples/README.md** to learn log formats
3. Practice with the example files using grep and jq
4. Read **pcap-samples/README.md** for testing basics

### Intermediate
1. Set up a test environment with VMs
2. Download PCAPs from public repositories
3. Run Suricata against PCAPs and analyze results
4. Practice the investigation workflows from alert-examples.md
5. Create suppression rules for false positives

### Advanced
1. Create custom test traffic for specific scenarios
2. Develop custom Suricata rules
3. Integrate logs with SIEM/analytics platforms
4. Build automated alert response systems
5. Conduct performance testing and optimization

## Tools You'll Need

### Essential
- **jq** - JSON processor for parsing eve.json
  ```bash
  # Install
  sudo apt-get install jq  # Debian/Ubuntu
  sudo yum install jq      # RHEL/CentOS
  ```

- **grep/awk/sed** - Text processing for fast.log
  (Usually pre-installed on Linux systems)

### Recommended
- **Wireshark** - PCAP analysis and inspection
- **tcpdump** - Packet capture
- **suricata-update** - Rule management
- **Python 3** - Scripting and automation

### Optional
- **Elasticsearch** - Log indexing and search
- **Kibana** - Visualization and dashboards
- **Logstash** - Log processing pipeline
- **Scapy** - Packet crafting for testing

## Additional Resources

### Official Documentation
- **Suricata User Guide:** https://suricata.readthedocs.io/
- **Rule Format:** https://suricata.readthedocs.io/en/latest/rules/
- **EVE JSON Output:** https://suricata.readthedocs.io/en/latest/output/eve/

### Community Resources
- **Suricata Forum:** https://forum.suricata.io/
- **Emerging Threats Rules:** https://rules.emergingthreats.net/
- **OISF Blog:** https://suricata.io/blog/

### Security Resources
- **MITRE ATT&CK:** https://attack.mitre.org/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **SANS Reading Room:** https://www.sans.org/reading-room/

### Testing Resources
- **Malware Traffic Analysis:** https://www.malware-traffic-analysis.net/
- **Wireshark Samples:** https://wiki.wireshark.org/SampleCaptures
- **PCAP Repository:** https://www.netresec.com/?page=PcapFiles

## Contributing

Found an error? Have a suggestion? Want to add more examples?

Please contribute to improve this documentation for the community!

## License

These examples and documentation are provided under the same license as the Suricata project.

---

## Quick Reference

| Task | Command |
|------|---------|
| View all alerts | `jq 'select(.event_type=="alert")' eve.json` |
| Count by signature | `jq -r 'select(.event_type=="alert") \| .alert.signature' eve.json \| sort \| uniq -c` |
| High priority only | `grep "Priority: 1" fast.log` |
| Specific IP | `grep "192.168.1.100" fast.log` |
| Run PCAP test | `suricata -r test.pcap -l ./output/` |
| Update rules | `sudo suricata-update` |

---

*Last Updated: January 2024*
*For the latest version, visit: https://github.com/OISF/suricata*
