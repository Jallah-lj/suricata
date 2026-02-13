# Suricata IDS Documentation Repository

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive, beginner-friendly documentation repository for Suricata IDS (Intrusion Detection System) that helps developers, students, and security professionals understand how to configure, use, and analyze Suricata for network security monitoring.

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Quick Start Guide](#quick-start-guide)
- [Documentation](#documentation)
- [Prerequisites](#prerequisites)
- [Key Features](#key-features)
- [Repository Structure](#repository-structure)
- [Contributing](#contributing)
- [License](#license)
- [Resources](#resources)

## 🔍 Project Overview

**Suricata** is a high-performance, open-source Network Intrusion Detection System (NIDS), Intrusion Prevention System (IPS), and Network Security Monitoring (NSM) engine. This repository provides:

- **Step-by-step guides** for installation and configuration
- **Practical examples** of detection rules for real-world threats
- **Analysis tools** and scripts for log processing
- **Troubleshooting guides** for common issues
- **Best practices** for network security monitoring

Whether you're a security student, developer implementing network monitoring, or a professional new to Suricata, this repository will help you understand and effectively use Suricata for threat detection.

## 🚀 Quick Start Guide

### 1. Install Suricata
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install suricata -y

# CentOS/RHEL
sudo yum install epel-release -y
sudo yum install suricata -y
```

### 2. Identify Your Network Interface
```bash
# List all network interfaces
ip addr show
# or
ifconfig -a
```

### 3. Configure Suricata
```bash
# Edit the configuration file
sudo nano /etc/suricata/suricata.yaml

# Set your HOME_NET (your network) and interface
HOME_NET: "[192.168.1.0/24]"
af-packet:
  - interface: eth0  # Replace with your interface
```

### 4. Update Rules
```bash
# Update Suricata rules
sudo suricata-update
```

### 5. Start Suricata
```bash
# Run Suricata in IDS mode
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Monitor alerts in real-time
sudo tail -f /var/log/suricata/fast.log
```

### 6. Test Detection
```bash
# Trigger a test alert (from another machine)
curl http://testmyids.com
```

For detailed installation instructions, see [Installation Guide](docs/01-installation.md).

## 📚 Documentation

Our comprehensive documentation covers everything from basic setup to advanced topics:

1. **[Installation Guide](docs/01-installation.md)** - Install Suricata on various platforms
2. **[Network Interfaces](docs/02-network-interfaces.md)** - Identify and configure network interfaces
3. **[Basic Configuration](docs/03-basic-configuration.md)** - Configure suricata.yaml settings
4. **[Rules Overview](docs/04-rules-overview.md)** - Understand Suricata rule syntax
5. **[Rule Management](docs/05-rule-management.md)** - Manage and update detection rules
6. **[Custom Rules](docs/06-custom-rules.md)** - Write your own detection rules
7. **[Log Analysis](docs/07-log-analysis.md)** - Analyze and parse Suricata logs
8. **[Troubleshooting](docs/08-troubleshooting.md)** - Common issues and solutions
9. **[Advanced Topics](docs/09-advanced-topics.md)** - Performance tuning and advanced features

## ✅ Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu, Debian, CentOS, RHEL), macOS, or Windows (WSL)
- **RAM**: Minimum 2GB (4GB+ recommended for production)
- **Disk Space**: 10GB+ for logs and rules
- **Network**: Network interface with monitoring capabilities

### Knowledge Prerequisites
- Basic Linux command-line skills
- Understanding of networking concepts (IP, TCP/UDP, ports)
- Basic familiarity with network security concepts

### Software Dependencies
- **Suricata** (v6.0+)
- **Python 3.6+** (for analysis scripts)
- **jq** (for JSON log parsing)
- **tcpdump** or **Wireshark** (for packet analysis)

## ✨ Key Features

This repository covers:

### 🛡️ Detection Capabilities
- ICMP, TCP, UDP traffic monitoring
- Web attack detection (SQL injection, XSS, directory traversal)
- Malware command & control (C2) detection
- Port scanning detection
- DNS-based threat detection
- TLS/SSL certificate analysis

### 📖 Learning Resources
- Real-world rule examples
- Pre-configured detection rules for common attacks
- Sample logs for practice and analysis
- Step-by-step tutorials for beginners

### 🔧 Practical Tools
- Automated setup scripts
- Log analysis utilities
- Rule testing frameworks
- Configuration templates

### 📊 Analysis Techniques
- EVE JSON log parsing
- Alert aggregation and statistics
- Integration with SIEM platforms (Splunk, ELK)
- Python-based log analysis

## 📁 Repository Structure

```
suricata/
├── README.md                          # This file
├── CONTRIBUTING.md                    # Contribution guidelines
├── LICENSE                            # MIT License
├── .gitignore                         # Git ignore rules
│
├── docs/                              # Documentation files
│   ├── 01-installation.md             # Installation guide
│   ├── 02-network-interfaces.md       # Network interface configuration
│   ├── 03-basic-configuration.md      # Basic configuration guide
│   ├── 04-rules-overview.md           # Rule syntax overview
│   ├── 05-rule-management.md          # Rule management guide
│   ├── 06-custom-rules.md             # Custom rule creation
│   ├── 07-log-analysis.md             # Log analysis techniques
│   ├── 08-troubleshooting.md          # Troubleshooting guide
│   └── 09-advanced-topics.md          # Advanced topics
│
├── rules/                             # Example detection rules
│   ├── README.md                      # Rules documentation
│   └── examples/
│       ├── basic-detection.rules      # Basic detection examples
│       ├── web-attacks.rules          # Web attack detection
│       ├── malware-detection.rules    # Malware detection
│       └── custom-rules.rules         # Custom rule templates
│
├── configs/                           # Configuration examples
│   ├── suricata.yaml.example          # Example Suricata config
│   ├── classification.config          # Classification settings
│   └── threshold.config               # Threshold configuration
│
├── scripts/                           # Utility scripts
│   ├── setup.sh                       # Environment setup script
│   ├── analyze-logs.py                # Log analysis tool
│   └── rule-tester.sh                 # Rule testing utility
│
└── examples/                          # Example files
    ├── log-samples/
    │   ├── eve.json.example           # Sample EVE JSON logs
    │   └── fast.log.example           # Sample fast.log
    ├── alert-examples.md              # Real-world alert examples
    └── pcap-samples/
        └── README.md                  # PCAP sample information
```

## 🤝 Contributing

We welcome contributions from the community! Whether you're fixing typos, adding new examples, or improving documentation, your help is appreciated.

Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

### How to Contribute
1. Fork this repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test your changes thoroughly
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

### Official Suricata Resources
- [Suricata Official Website](https://suricata.io/)
- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Suricata GitHub Repository](https://github.com/OISF/suricata)
- [Suricata User Guide](https://suricata.readthedocs.io/en/latest/)

### Rule Sources
- [Emerging Threats](https://rules.emergingthreats.net/)
- [Proofpoint ET Open](https://rules.emergingthreats.net/open/)
- [Suricata Update Tool](https://suricata-update.readthedocs.io/)

### Community & Support
- [Suricata Forums](https://forum.suricata.io/)
- [Suricata Mailing List](https://lists.openinfosecfoundation.org/)
- [OISF (Open Information Security Foundation)](https://oisf.net/)

### Learning Resources
- [Network Security Monitoring with Suricata](https://www.networkdefense.io/)
- [Suricata Rule Writing Guide](https://suricata.readthedocs.io/en/latest/rules/)
- [IDS/IPS Fundamentals](https://www.sans.org/reading-room/whitepapers/detection/)

### Testing & Samples
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- [PCAP Sample Repository](https://wiki.wireshark.org/SampleCaptures)
- [Test Your IDS](http://testmyids.com/)

---

**Made with ❤️ for the security community**

*For questions, issues, or suggestions, please open an issue on GitHub.*