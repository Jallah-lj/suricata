# Suricata IDS Utility Scripts

This directory contains utility scripts for managing and analyzing Suricata IDS.

## Scripts

### 1. setup.sh

A comprehensive setup script that helps configure and validate your Suricata installation.

**Features:**
- Checks if Suricata is installed
- Identifies available network interfaces with detailed information
- Sets up basic directory structure for logs
- Creates symbolic links if needed
- Sets proper permissions for Suricata
- Validates suricata.yaml configuration
- Includes usage examples and help text
- Has proper error handling

**Usage:**
```bash
# Run interactive setup
./setup.sh

# Check installation only
./setup.sh --check-only

# Specify custom log directory
./setup.sh --log-dir /custom/log/path

# Show help
./setup.sh --help
```

**Requirements:**
- Bash 4.0+
- Root or sudo access for some operations

---

### 2. analyze-logs.py

A Python script for analyzing Suricata's eve.json log files.

**Features:**
- Parses eve.json file
- Displays top alerts with counts
- Shows statistics (top protocols, source IPs, destination IPs, destination ports)
- Filters by alert severity/priority
- Exports reports to CSV or JSON
- Has command-line arguments (--file, --top, --export, --filter)
- Includes usage examples and --help
- Uses argparse for CLI
- Handles missing files gracefully

**Usage:**
```bash
# Basic analysis
./analyze-logs.py --file /var/log/suricata/eve.json

# Show top 20 alerts
./analyze-logs.py --file eve.json --top 20

# Filter by severity (1=high, 2=medium, 3=low)
./analyze-logs.py --file eve.json --filter severity:1

# Export to CSV
./analyze-logs.py --file eve.json --export alerts.csv

# Export to JSON
./analyze-logs.py --file eve.json --export report.json

# Combine options
./analyze-logs.py --file eve.json --top 10 --filter priority:1 --export high_priority.csv
```

**Filter Options:**
- `severity:1` - High severity alerts
- `severity:2` - Medium severity alerts
- `severity:3` - Low severity alerts
- `priority:1` - Priority 1 alerts
- `src_ip:X.X.X.X` - Alerts from specific source IP
- `dest_ip:X.X.X.X` - Alerts to specific destination IP
- `signature:TEXT` - Alerts matching signature text

**Requirements:**
- Python 3.7+
- No external dependencies (uses standard library only)

---

### 3. rule-tester.sh

A Bash script for testing and validating Suricata rules.

**Features:**
- Tests rule syntax with suricata -T
- Validates custom rule files
- Runs Suricata against sample PCAP files (if provided)
- Shows alerts generated from PCAP tests
- Has options for: --rules, --pcap, --config
- Includes usage help
- Cleans up temporary files

**Usage:**
```bash
# Test rule file syntax only
./rule-tester.sh --rules custom.rules

# Test rules with PCAP file
./rule-tester.sh --rules custom.rules --pcap test.pcap

# Test with PCAP using default configuration
./rule-tester.sh --pcap test.pcap

# Use custom configuration
./rule-tester.sh --rules custom.rules --pcap test.pcap --config my.yaml

# Keep temporary files for inspection
./rule-tester.sh --rules custom.rules --pcap test.pcap --no-cleanup

# Show help
./rule-tester.sh --help
```

**Requirements:**
- Bash 4.0+
- Suricata installed and in PATH
- Optional: capinfos (from Wireshark) for PCAP file information

---

## Installation

All scripts are executable by default. To use them:

```bash
# Clone the repository
cd /path/to/suricata-repo

# Navigate to scripts directory
cd scripts

# Run any script
./setup.sh
./analyze-logs.py --file /var/log/suricata/eve.json
./rule-tester.sh --rules custom.rules
```

## Examples

### Complete Workflow Example

1. **Setup Suricata:**
   ```bash
   ./setup.sh
   ```

2. **Test custom rules:**
   ```bash
   ./rule-tester.sh --rules ../rules/local.rules --pcap test_traffic.pcap
   ```

3. **Analyze the logs:**
   ```bash
   ./analyze-logs.py --file /var/log/suricata/eve.json --top 20 --export report.csv
   ```

### Monitoring High-Severity Alerts

```bash
# Filter and export high-severity alerts
./analyze-logs.py --file /var/log/suricata/eve.json \
    --filter severity:1 \
    --export high_severity_alerts.json
```

### Rule Development and Testing

```bash
# Test rules without a PCAP (syntax check only)
./rule-tester.sh --rules new_rules.rules

# Test rules with sample traffic
./rule-tester.sh --rules new_rules.rules --pcap malicious_traffic.pcap

# Keep temporary files for debugging
./rule-tester.sh --rules new_rules.rules --pcap test.pcap --no-cleanup
```

## Contributing

When adding new scripts to this directory:

1. Make the script executable: `chmod +x script.sh`
2. Include comprehensive help text with `--help` option
3. Add proper error handling
4. Follow the established coding style
5. Update this README with usage examples
6. Test the script before committing

## License

These scripts are part of the Suricata IDS project. See the main LICENSE file for details.
