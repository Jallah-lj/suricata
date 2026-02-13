# Log Analysis

This guide covers understanding, parsing, and analyzing Suricata logs to detect security threats and investigate incidents.

## Table of Contents

- [Log File Overview](#log-file-overview)
- [EVE JSON Format](#eve-json-format)
- [Fast Log Format](#fast-log-format)
- [Analyzing Logs with jq](#analyzing-logs-with-jq)
- [Python Log Analysis](#python-log-analysis)
- [SIEM Integration](#siem-integration)
- [Real-World Examples](#real-world-examples)
- [Log Rotation and Management](#log-rotation-and-management)

## Log File Overview

### Default Log Locations

```bash
# Main log directory
/var/log/suricata/

# Key log files
/var/log/suricata/eve.json          # JSON event log (primary)
/var/log/suricata/fast.log          # Fast alert format
/var/log/suricata/stats.log         # Statistics log
/var/log/suricata/suricata.log      # Suricata engine log
```

### View Logs

```bash
# View EVE JSON log
sudo tail -f /var/log/suricata/eve.json

# View fast.log
sudo tail -f /var/log/suricata/fast.log

# View recent alerts only
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# Count log entries
sudo wc -l /var/log/suricata/eve.json
```

### Log Types

| Log File | Purpose | Format |
|----------|---------|--------|
| `eve.json` | All events in JSON format | JSON |
| `fast.log` | Fast alert format | Text |
| `stats.log` | Performance statistics | Text |
| `http.log` | HTTP transactions (optional) | Text |
| `dns.log` | DNS queries (optional) | Text |
| `tls.log` | TLS handshakes (optional) | Text |

## EVE JSON Format

### Structure

EVE (Extensible Event Format) is the primary Suricata log format in JSON.

Basic event structure:

```json
{
  "timestamp": "2024-01-15T10:30:45.123456+0000",
  "flow_id": 123456789,
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "93.184.216.34",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2000001,
    "rev": 1,
    "signature": "SQL Injection Attempt",
    "category": "Web Application Attack",
    "severity": 1
  }
}
```

### Event Types

Common event types in eve.json:

| Event Type | Description |
|------------|-------------|
| `alert` | Security alert triggered |
| `http` | HTTP transaction |
| `dns` | DNS query/response |
| `tls` | TLS/SSL handshake |
| `flow` | Network flow information |
| `fileinfo` | File extraction metadata |
| `ssh` | SSH connections |
| `smtp` | SMTP/email traffic |
| `stats` | Statistics |

### Alert Event Fields

```json
{
  "timestamp": "2024-01-15T10:30:45.123456+0000",
  "flow_id": 123456789,
  "event_type": "alert",
  "src_ip": "203.0.113.10",
  "src_port": 45678,
  "dest_ip": "192.168.1.50",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2000001,
    "rev": 1,
    "signature": "SQL Injection Attempt Detected",
    "category": "Web Application Attack",
    "severity": 1,
    "metadata": {
      "created_at": ["2024_01_01"],
      "updated_at": ["2024_01_15"]
    }
  },
  "http": {
    "hostname": "vulnerable.example.com",
    "url": "/login.php?id=1' UNION SELECT 1,2,3--",
    "http_method": "GET",
    "http_user_agent": "Mozilla/5.0",
    "http_content_type": "text/html",
    "status": 200
  },
  "app_proto": "http",
  "flow": {
    "pkts_toserver": 5,
    "pkts_toclient": 5,
    "bytes_toserver": 450,
    "bytes_toclient": 1200,
    "start": "2024-01-15T10:30:40.000000+0000"
  }
}
```

### HTTP Event Fields

```json
{
  "timestamp": "2024-01-15T10:30:45.123456+0000",
  "event_type": "http",
  "src_ip": "192.168.1.100",
  "dest_ip": "93.184.216.34",
  "http": {
    "hostname": "example.com",
    "url": "/api/users",
    "http_method": "POST",
    "http_user_agent": "curl/7.68.0",
    "http_content_type": "application/json",
    "http_refer": "https://example.com/",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 1234
  }
}
```

### DNS Event Fields

```json
{
  "timestamp": "2024-01-15T10:30:45.123456+0000",
  "event_type": "dns",
  "src_ip": "192.168.1.100",
  "dest_ip": "8.8.8.8",
  "dns": {
    "type": "query",
    "id": 12345,
    "rrname": "example.com",
    "rrtype": "A",
    "tx_id": 0
  }
}
```

### TLS Event Fields

```json
{
  "timestamp": "2024-01-15T10:30:45.123456+0000",
  "event_type": "tls",
  "src_ip": "192.168.1.100",
  "dest_ip": "93.184.216.34",
  "tls": {
    "subject": "CN=example.com",
    "issuerdn": "CN=Let's Encrypt Authority",
    "serial": "03:AB:CD:EF",
    "fingerprint": "aa:bb:cc:dd:ee:ff",
    "sni": "example.com",
    "version": "TLS 1.2",
    "notbefore": "2024-01-01T00:00:00",
    "notafter": "2024-12-31T23:59:59"
  }
}
```

## Fast Log Format

### Format Structure

Fast.log provides a simple, one-line format for alerts:

```
[TIMESTAMP] [**] [GID:SID:REV] MESSAGE [**] [Classification: CLASSIFICATION] [Priority: PRIORITY] {PROTOCOL} SRC_IP:SRC_PORT -> DST_IP:DST_PORT
```

### Example Entries

```
01/15/2024-10:30:45.123456 [**] [1:2000001:1] SQL Injection Attempt Detected [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 203.0.113.10:45678 -> 192.168.1.50:80

01/15/2024-10:31:12.654321 [**] [1:2000002:1] XSS Attempt in HTTP Request [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 203.0.113.10:45679 -> 192.168.1.50:80

01/15/2024-10:32:05.789012 [**] [1:2000003:1] Port Scan Detected [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.20:54321 -> 192.168.1.50:22
```

### Parsing fast.log

```bash
# View alerts in real-time
sudo tail -f /var/log/suricata/fast.log

# Count alerts by signature
sudo cat /var/log/suricata/fast.log | awk -F'[\\[\\]]' '{print $3}' | sort | uniq -c | sort -rn

# Get unique source IPs
sudo cat /var/log/suricata/fast.log | grep -oP '\d+\.\d+\.\d+\.\d+:\d+ ->' | cut -d: -f1 | sort -u

# Filter by priority
sudo grep "Priority: 1" /var/log/suricata/fast.log

# Filter by classification
sudo grep "Web Application Attack" /var/log/suricata/fast.log

# Count alerts by hour
sudo cat /var/log/suricata/fast.log | cut -d'-' -f1 | cut -d':' -f1,2 | sort | uniq -c
```

## Analyzing Logs with jq

### Install jq

```bash
# Ubuntu/Debian
sudo apt-get install jq

# CentOS/RHEL
sudo yum install jq

# macOS
brew install jq
```

### Basic jq Queries

#### View Formatted JSON

```bash
# Pretty print single event
sudo tail -n 1 /var/log/suricata/eve.json | jq '.'

# View all events formatted
sudo cat /var/log/suricata/eve.json | jq '.'
```

#### Filter by Event Type

```bash
# Show only alerts
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# Show only HTTP events
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="http")'

# Show only DNS events
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="dns")'

# Multiple event types
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" or .event_type=="http")'
```

#### Extract Specific Fields

```bash
# Show timestamps and alert signatures
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | "\(.timestamp) - \(.alert.signature)"'

# Show source and destination IPs
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | "\(.src_ip) -> \(.dest_ip)"'

# Show HTTP URLs
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="http") | .http.url'

# Show DNS queries
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="dns") | .dns.rrname'
```

### Advanced jq Queries

#### Count Events by Type

```bash
# Count all event types
sudo cat /var/log/suricata/eve.json | jq -r '.event_type' | sort | uniq -c | sort -rn

# Count alerts by signature
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn

# Count alerts by category
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .alert.category' | sort | uniq -c | sort -rn
```

#### Filter by Severity

```bash
# High severity alerts only (severity 1)
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and .alert.severity==1)'

# Medium and high severity
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and .alert.severity<=2)'

# Count by severity
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .alert.severity' | sort | uniq -c
```

#### Filter by IP Address

```bash
# Alerts from specific source IP
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and .src_ip=="203.0.113.10")'

# Alerts to specific destination
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and .dest_ip=="192.168.1.50")'

# Alerts involving specific IP (source or dest)
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and (.src_ip=="203.0.113.10" or .dest_ip=="203.0.113.10"))'

# Top source IPs
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .src_ip' | sort | uniq -c | sort -rn | head -10
```

#### Filter by Time Range

```bash
# Alerts in last hour
sudo cat /var/log/suricata/eve.json | jq --arg now "$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%S')" 'select(.event_type=="alert" and .timestamp > $now)'

# Alerts today
sudo cat /var/log/suricata/eve.json | jq --arg today "$(date -u '+%Y-%m-%d')" 'select(.event_type=="alert" and .timestamp | startswith($today))'
```

#### Complex Filtering

```bash
# SQL injection alerts from external IPs
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and (.alert.signature | contains("SQL")) and (.src_ip | startswith("203.0") or startswith("198.51")))'

# HTTP POST requests to /admin
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="http" and .http.http_method=="POST" and (.http.url | contains("/admin")))'

# High severity alerts with specific category
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and .alert.severity==1 and .alert.category=="Web Application Attack")'
```

#### Create Reports

```bash
# Alert summary report
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | "\(.timestamp) | \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port) | \(.alert.signature)"' | column -t -s '|'

# HTTP access log format
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="http") | "\(.src_ip) - \(.timestamp) - \(.http.http_method) \(.http.url) - \(.http.status)"'

# DNS query log
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="dns") | "\(.timestamp) | \(.src_ip) | \(.dns.rrname) | \(.dns.rrtype)"' | column -t -s '|'
```

## Python Log Analysis

### Basic Python Script

```python
#!/usr/bin/env python3
# analyze_suricata.py

import json
import sys
from collections import Counter
from datetime import datetime

def analyze_alerts(log_file):
    """Analyze Suricata alert events"""
    
    alerts = []
    
    # Read and parse log file
    with open(log_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    alerts.append(event)
            except json.JSONDecodeError:
                continue
    
    print(f"Total Alerts: {len(alerts)}\n")
    
    # Count by signature
    signatures = Counter(alert['alert']['signature'] for alert in alerts)
    print("Top 10 Alert Signatures:")
    for sig, count in signatures.most_common(10):
        print(f"  {count:5d} - {sig}")
    
    print()
    
    # Count by source IP
    src_ips = Counter(alert['src_ip'] for alert in alerts)
    print("Top 10 Source IPs:")
    for ip, count in src_ips.most_common(10):
        print(f"  {count:5d} - {ip}")
    
    print()
    
    # Count by severity
    severities = Counter(alert['alert']['severity'] for alert in alerts)
    print("Alerts by Severity:")
    for severity, count in sorted(severities.items()):
        sev_name = {1: "High", 2: "Medium", 3: "Low"}.get(severity, "Unknown")
        print(f"  {sev_name:6s} ({severity}): {count}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <eve.json>")
        sys.exit(1)
    
    analyze_alerts(sys.argv[1])
```

Usage:

```bash
# Make executable
chmod +x analyze_suricata.py

# Run analysis
sudo python3 analyze_suricata.py /var/log/suricata/eve.json
```

### Advanced Analysis Script

```python
#!/usr/bin/env python3
# advanced_analysis.py

import json
import sys
from collections import defaultdict, Counter
from datetime import datetime
import argparse

def parse_timestamp(ts):
    """Parse Suricata timestamp"""
    return datetime.fromisoformat(ts.replace('Z', '+00:00'))

def analyze_attacks(log_file, hours=24):
    """Analyze attack patterns"""
    
    # Data structures
    alerts_by_ip = defaultdict(list)
    alerts_by_sig = defaultdict(list)
    timeline = []
    
    # Read events
    with open(log_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    timestamp = parse_timestamp(event['timestamp'])
                    src_ip = event['src_ip']
                    signature = event['alert']['signature']
                    
                    alerts_by_ip[src_ip].append(event)
                    alerts_by_sig[signature].append(event)
                    timeline.append((timestamp, event))
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
    
    print("=" * 70)
    print("SURICATA SECURITY ANALYSIS REPORT")
    print("=" * 70)
    print()
    
    # Summary
    print(f"Total Alerts: {len(timeline)}")
    print(f"Unique Source IPs: {len(alerts_by_ip)}")
    print(f"Unique Signatures: {len(alerts_by_sig)}")
    print()
    
    # Top attackers
    print("TOP 10 ATTACKING IPs:")
    print("-" * 70)
    for ip, alerts in sorted(alerts_by_ip.items(), 
                            key=lambda x: len(x[1]), 
                            reverse=True)[:10]:
        categories = Counter(a['alert']['category'] for a in alerts)
        top_category = categories.most_common(1)[0][0] if categories else "Unknown"
        print(f"  {ip:15s} - {len(alerts):4d} alerts - {top_category}")
    print()
    
    # Top signatures
    print("TOP 10 TRIGGERED SIGNATURES:")
    print("-" * 70)
    for sig, alerts in sorted(alerts_by_sig.items(), 
                             key=lambda x: len(x[1]), 
                             reverse=True)[:10]:
        unique_ips = len(set(a['src_ip'] for a in alerts))
        print(f"  {len(alerts):4d} alerts from {unique_ips:3d} IPs - {sig}")
    print()
    
    # Attack patterns
    print("ATTACK PATTERNS:")
    print("-" * 70)
    for ip, alerts in alerts_by_ip.items():
        if len(alerts) >= 10:  # Potential attack campaign
            signatures = Counter(a['alert']['signature'] for a in alerts)
            if len(signatures) > 3:  # Multiple attack types
                print(f"  Multi-vector attack from {ip}:")
                for sig, count in signatures.most_common(3):
                    print(f"    - {count:3d}x {sig}")
                print()
    
    # Time analysis
    if timeline:
        timeline.sort(key=lambda x: x[0])
        first = timeline[0][0]
        last = timeline[-1][0]
        duration = (last - first).total_seconds() / 3600
        rate = len(timeline) / duration if duration > 0 else 0
        print(f"Time Range: {first} to {last}")
        print(f"Duration: {duration:.1f} hours")
        print(f"Alert Rate: {rate:.1f} alerts/hour")
        print()

def main():
    parser = argparse.ArgumentParser(description='Analyze Suricata logs')
    parser.add_argument('logfile', help='Path to eve.json')
    parser.add_argument('--hours', type=int, default=24, 
                       help='Hours to analyze (default: 24)')
    
    args = parser.parse_args()
    analyze_attacks(args.logfile, args.hours)

if __name__ == '__main__':
    main()
```

Usage:

```bash
# Run full analysis
sudo python3 advanced_analysis.py /var/log/suricata/eve.json

# Analyze last 6 hours
sudo python3 advanced_analysis.py /var/log/suricata/eve.json --hours 6
```

### HTTP Traffic Analysis

```python
#!/usr/bin/env python3
# http_analysis.py

import json
import sys
from collections import Counter

def analyze_http(log_file):
    """Analyze HTTP traffic"""
    
    requests = []
    
    with open(log_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get('event_type') == 'http':
                    requests.append(event)
            except json.JSONDecodeError:
                continue
    
    print(f"Total HTTP Requests: {len(requests)}\n")
    
    # Methods
    methods = Counter(r['http']['http_method'] for r in requests)
    print("HTTP Methods:")
    for method, count in methods.most_common():
        print(f"  {method:8s}: {count}")
    print()
    
    # Status codes
    statuses = Counter(r['http'].get('status', 0) for r in requests)
    print("Status Codes:")
    for status, count in sorted(statuses.items()):
        print(f"  {status}: {count}")
    print()
    
    # Top hostnames
    hostnames = Counter(r['http']['hostname'] for r in requests)
    print("Top 10 Hostnames:")
    for host, count in hostnames.most_common(10):
        print(f"  {count:5d} - {host}")
    print()
    
    # Top URLs
    urls = Counter(r['http']['url'] for r in requests)
    print("Top 10 URLs:")
    for url, count in urls.most_common(10):
        print(f"  {count:5d} - {url}")
    print()
    
    # User agents
    user_agents = Counter(r['http'].get('http_user_agent', 'Unknown') for r in requests)
    print("Top 10 User Agents:")
    for ua, count in user_agents.most_common(10):
        print(f"  {count:5d} - {ua}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <eve.json>")
        sys.exit(1)
    
    analyze_http(sys.argv[1])
```

## SIEM Integration

### Elasticsearch/ELK Stack

#### Filebeat Configuration

```yaml
# /etc/filebeat/filebeat.yml

filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    type: suricata

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "suricata-%{+yyyy.MM.dd}"

setup.template.name: "suricata"
setup.template.pattern: "suricata-*"
```

#### Logstash Configuration

```ruby
# /etc/logstash/conf.d/suricata.conf

input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => json
    type => "suricata"
  }
}

filter {
  if [type] == "suricata" {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    if [event_type] == "alert" {
      mutate {
        add_field => { "alert_signature" => "%{[alert][signature]}" }
        add_field => { "alert_category" => "%{[alert][category]}" }
        add_field => { "alert_severity" => "%{[alert][severity]}" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
  }
}
```

### Splunk Integration

#### inputs.conf

```ini
# /opt/splunk/etc/apps/suricata/local/inputs.conf

[monitor:///var/log/suricata/eve.json]
disabled = false
sourcetype = suricata:eve:json
index = suricata
```

#### props.conf

```ini
# /opt/splunk/etc/apps/suricata/local/props.conf

[suricata:eve:json]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = \"timestamp\"\s*:\s*\"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
MAX_TIMESTAMP_LOOKAHEAD = 32
```

#### Example Splunk Queries

```spl
# All alerts
index=suricata event_type=alert

# High severity alerts
index=suricata event_type=alert alert.severity=1

# SQL injection attempts
index=suricata event_type=alert alert.signature="*SQL*"

# Top attackers
index=suricata event_type=alert 
| stats count by src_ip 
| sort -count 
| head 10

# Alert timeline
index=suricata event_type=alert 
| timechart count by alert.category

# HTTP POST requests
index=suricata event_type=http http.http_method=POST 
| stats count by http.hostname
```

## Real-World Examples

### Example 1: SQL Injection Investigation

```bash
# Find SQL injection alerts
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and (.alert.signature | contains("SQL")))'

# Get unique source IPs
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert" and (.alert.signature | contains("SQL"))) | .src_ip' | sort -u

# Check HTTP details for specific IP
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="http" and .src_ip=="203.0.113.10") | .http.url'

# Timeline of attacks
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert" and .src_ip=="203.0.113.10") | "\(.timestamp) - \(.alert.signature)"'
```

### Example 2: Port Scan Detection

```bash
# Find port scan alerts
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and (.alert.signature | contains("Port Scan")))'

# Count scans by source IP
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert" and (.alert.signature | contains("Port Scan"))) | .src_ip' | sort | uniq -c | sort -rn

# Get targeted ports
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert" and (.alert.signature | contains("Port Scan"))) | .dest_port' | sort | uniq -c | sort -rn
```

### Example 3: Malware C2 Investigation

```bash
# Find C2 alerts
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and (.alert.category | contains("Trojan")))'

# Get internal IPs communicating with C2
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert" and (.alert.category | contains("Trojan"))) | .src_ip' | sort -u

# Check DNS queries from infected host
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="dns" and .src_ip=="192.168.1.100") | .dns.rrname'

# Check TLS SNI for C2 domains
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="tls" and .src_ip=="192.168.1.100") | .tls.sni'
```

### Example 4: Web Attack Campaign

```bash
# Find all web attacks
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and .alert.category=="Web Application Attack")'

# Group by target
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert" and .alert.category=="Web Application Attack") | .dest_ip' | sort | uniq -c | sort -rn

# Analyze attack types
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert" and .alert.category=="Web Application Attack") | .alert.signature' | sort | uniq -c | sort -rn

# Get attacked URLs
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert" and .alert.category=="Web Application Attack" and .dest_ip=="192.168.1.50") | .http.url' | sort -u
```

### Example 5: DNS Tunneling

```bash
# Find DNS tunneling alerts
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and (.alert.signature | contains("DNS Tunnel")))'

# Analyze DNS query lengths
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="dns" and .src_ip=="192.168.1.100") | .dns.rrname' | awk '{print length, $0}' | sort -rn | head -20

# Check query frequency
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="dns" and .src_ip=="192.168.1.100") | "\(.timestamp) | \(.dns.rrname)"' | head -50
```

## Log Rotation and Management

### Configure Log Rotation

```bash
# Create logrotate configuration
sudo nano /etc/logrotate.d/suricata
```

```
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
```

### Manual Log Rotation

```bash
# Rotate logs manually
sudo logrotate -f /etc/logrotate.d/suricata

# Check rotation status
sudo logrotate -d /etc/logrotate.d/suricata
```

### Archive Old Logs

```bash
# Compress logs older than 7 days
find /var/log/suricata/ -name "*.log" -type f -mtime +7 -exec gzip {} \;

# Move old logs to archive
sudo mkdir -p /var/log/suricata/archive
sudo mv /var/log/suricata/*.log.*.gz /var/log/suricata/archive/

# Delete logs older than 30 days
find /var/log/suricata/archive/ -type f -mtime +30 -delete
```

### Monitor Log Size

```bash
# Check current log sizes
sudo du -sh /var/log/suricata/*

# Monitor in real-time
watch -n 5 'du -sh /var/log/suricata/eve.json'

# Set up alert for large logs
(( $(stat -c%s /var/log/suricata/eve.json) > 1073741824 )) && echo "Log file exceeds 1GB"
```

## Best Practices

### 1. Regular Log Review

```bash
# Daily review script
#!/bin/bash
DATE=$(date +%Y-%m-%d)
REPORT="/tmp/suricata-daily-${DATE}.txt"

echo "Suricata Daily Report - $DATE" > $REPORT
echo "================================" >> $REPORT
echo "" >> $REPORT

# Alert count
echo "Total Alerts: $(sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert")' | wc -l)" >> $REPORT

# Top signatures
echo "" >> $REPORT
echo "Top 5 Signatures:" >> $REPORT
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn | head -5 >> $REPORT

cat $REPORT | mail -s "Suricata Daily Report" security@example.com
```

### 2. Alert Correlation

```bash
# Correlate alerts with HTTP logs
sudo cat /var/log/suricata/eve.json | jq 'select(.flow_id==123456789)'
```

### 3. Performance Monitoring

```bash
# Check log growth rate
sudo ls -lh /var/log/suricata/eve.json

# Monitor stats
sudo tail -f /var/log/suricata/stats.log
```

## Next Steps

Now that you understand log analysis:

1. **Troubleshoot Issues**: See [Troubleshooting Guide](08-troubleshooting.md)
2. **Optimize Performance**: See [Advanced Topics](09-advanced-topics.md)
3. **Setup SIEM**: Integrate with your security stack

---

[← Back: Custom Rules](06-custom-rules.md) | [Home](../README.md) | [Next: Troubleshooting →](08-troubleshooting.md)
