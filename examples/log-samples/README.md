# EVE JSON Format Guide

This document explains the structure and fields in the `eve.json.example` file.

## Overview

EVE (Extensible Event Format) JSON is Suricata's main output format containing detailed event information. Each line is a complete JSON object representing one event.

## Event Types

The example file contains these event types:

### 1. Alert Events (event_type: "alert")

Security alerts when Suricata signatures match network traffic.

**Example:**
```json
{
  "timestamp": "2024-01-15T10:23:45.123456+0000",
  "flow_id": 1234567890,
  "event_type": "alert",
  "src_ip": "192.168.1.105",
  "src_port": 54321,
  "dest_ip": "198.51.100.42",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2100498,
    "rev": 7,
    "signature": "GPL ATTACK_RESPONSE id check returned root",
    "category": "Potentially Bad Traffic",
    "severity": 2
  }
}
```

**Alert-Specific Fields:**
- `action`: "allowed" or "blocked" (depends on Suricata mode)
- `gid`: Generator ID (1 = standard rules)
- `signature_id`: Unique rule identifier (SID)
- `rev`: Rule revision number
- `signature`: Human-readable alert description
- `category`: Classification type
- `severity`: 1=High, 2=Medium, 3=Low

### 2. HTTP Events (event_type: "http")

HTTP transaction details.

**Fields:**
- `hostname`: HTTP Host header
- `url`: Requested URI
- `http_user_agent`: Client user-agent string
- `http_method`: GET, POST, etc.
- `protocol`: HTTP version
- `status`: HTTP response code
- `length`: Response body size
- `http_content_type`: MIME type of response
- `http_refer`: Referring page (if present)

**Example Use Cases:**
- Web application monitoring
- Detecting suspicious URLs
- User-agent analysis
- Response code tracking

### 3. DNS Events (event_type: "dns")

DNS queries and responses.

**Query Fields:**
- `type`: "query" or "answer"
- `id`: DNS transaction ID
- `rrname`: Domain name queried
- `rrtype`: Query type (A, AAAA, MX, TXT, etc.)
- `tx_id`: Suricata transaction ID

**Answer Fields (additional):**
- `rdata`: Response data (IP address, etc.)
- `ttl`: Time-to-live in seconds

**Example Use Cases:**
- Detecting DNS tunneling
- Identifying malicious domains
- DGA (Domain Generation Algorithm) detection
- DNS cache poisoning detection

### 4. TLS Events (event_type: "tls")

TLS/SSL connection details including certificate information.

**Fields:**
- `subject`: Certificate subject (CN=domain)
- `issuerdn`: Certificate issuer
- `serial`: Certificate serial number
- `fingerprint`: Certificate SHA256 fingerprint
- `version`: TLS version (1.0, 1.2, 1.3)
- `notbefore`: Certificate valid from date
- `notafter`: Certificate expiration date
- `ja3.hash`: JA3 fingerprint (client)
- `ja3s.hash`: JA3S fingerprint (server)

**JA3/JA3S Explained:**
- Fingerprints of TLS handshake parameters
- Used to identify specific malware families
- Unique to client/server implementations
- Useful for threat hunting

**Example Use Cases:**
- Detecting fake/self-signed certificates
- Malware C2 identification via JA3
- Certificate expiration monitoring
- TLS version compliance

### 5. Flow Events (event_type: "flow")

Network flow statistics and metadata.

**Fields:**
- `pkts_toserver`: Packets sent to server
- `pkts_toclient`: Packets sent to client
- `bytes_toserver`: Bytes uploaded
- `bytes_toclient`: Bytes downloaded
- `start`: Flow start timestamp
- `end`: Flow end timestamp
- `age`: Duration in seconds
- `state`: Connection state (established, closed, etc.)
- `reason`: Why flow ended (shutdown, timeout, etc.)
- `alerted`: Boolean - did this flow trigger alerts?

**Example Use Cases:**
- Data exfiltration detection (large uploads)
- Network baseline profiling
- Connection duration analysis
- Bandwidth monitoring

### 6. Fileinfo Events (event_type: "fileinfo")

Files transferred over the network.

**Fields:**
- `filename`: Original filename
- `magic`: File type detection (libmagic)
- `state`: TRUNCATED, CLOSED, etc.
- `md5`: MD5 hash of file
- `sha256`: SHA256 hash of file
- `size`: File size in bytes

**Example Use Cases:**
- Malware hash lookups (VirusTotal)
- File transfer monitoring
- Executable download tracking
- Data loss prevention

### 7. SMTP Events (event_type: "smtp")

Email protocol details.

**Fields:**
- `helo`: SMTP HELO/EHLO hostname
- `mail_from`: Sender address
- `rcpt_to`: Recipient address(es)

**Email nested object:**
- `from`: Email From header
- `to`: Email To header(s)
- `subject`: Email subject line

**Example Use Cases:**
- Phishing detection
- Spam monitoring
- Email spoofing detection
- BEC (Business Email Compromise) detection

### 8. SMB Events (event_type: "smb")

SMB/CIFS protocol events (when available).

**Fields:**
- `command`: SMB command type
- `status`: Command status code

**Example Use Cases:**
- Lateral movement detection
- Ransomware activity
- Credential theft attempts

## Common Fields (All Events)

**Present in all event types:**
- `timestamp`: ISO 8601 format with microseconds
- `flow_id`: Unique identifier linking related events
- `src_ip`: Source IP address
- `src_port`: Source port number
- `dest_ip`: Destination IP address
- `dest_port`: Destination port number
- `proto`: Protocol (TCP, UDP, ICMP, etc.)

## Alert Examples Explained

### Example 1: Attack Response Detection
```json
"signature": "GPL ATTACK_RESPONSE id check returned root"
```
**What it detects:** Server response containing "uid=0(root)" indicating successful privilege escalation
**Severity:** Medium (2)
**Action:** Investigate web server for compromise

### Example 2: Emotet Malware
```json
"signature": "ET MALWARE Win32/Emotet CnC Activity"
```
**What it detects:** Network traffic matching known Emotet malware patterns
**Severity:** High (1)
**Action:** Isolate infected host immediately

### Example 3: SQL Injection
```json
"signature": "ET WEB_SPECIFIC_APPS SQL Injection Attempt"
"url": "/login.php?user=admin' OR '1'='1"
```
**What it detects:** SQL injection attempt in URL parameters
**Severity:** High (1)
**Action:** Block source IP, patch web application

### Example 4: XSS Attack
```json
"signature": "ET WEB_SPECIFIC_APPS XSS Attempt"
"url": "/search?q=<script>alert(document.cookie)</script>"
```
**What it detects:** JavaScript injection in user input
**Severity:** Medium (2)
**Action:** Sanitize user input, implement CSP headers

### Example 5: SSH Port Scan
```json
"signature": "ET SCAN Potential SSH Scan"
```
**What it detects:** Rapid connection attempts to SSH on multiple hosts
**Severity:** Medium (2)
**Action:** Block scanner IP, review SSH exposure

### Example 6: TOR Usage
```json
"signature": "ET INFO TOR Client SSL Certificate"
```
**What it detects:** TLS certificate patterns associated with TOR
**Severity:** Medium (2)
**Action:** Verify if TOR usage is authorized

### Example 7: EternalBlue Exploit
```json
"signature": "ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response"
```
**What it detects:** SMB exploit used by WannaCry ransomware
**Severity:** High (1)
**Action:** Patch immediately, check for compromise

### Example 8: Malicious DNS Query
```json
"signature": "ET DNS Query to a *.top domain - Likely Hostile"
"rrname": "malware-download.top"
```
**What it detects:** DNS query to suspicious TLD often used by malware
**Severity:** Medium (2)
**Action:** Investigate requesting host for malware

### Example 9: IRC Bot Communication
```json
"signature": "ET MALWARE IRC Bot JOIN command"
```
**What it detects:** IRC protocol commands used by botnets
**Severity:** High (1)
**Action:** Isolate infected system, remove malware

### Example 10: Cryptocurrency Mining
```json
"signature": "ET POLICY Cryptocurrency Miner Checkin"
"http_user_agent": "xmrig/6.16.0"
```
**What it detects:** Connection to cryptocurrency mining pool
**Severity:** Medium (2)
**Action:** Remove mining software, check authorization

## Parsing EVE JSON

### Using jq (JSON processor)

**Count events by type:**
```bash
jq -r '.event_type' eve.json | sort | uniq -c
```

**Extract all alerts:**
```bash
jq 'select(.event_type=="alert")' eve.json
```

**Get unique alert signatures:**
```bash
jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort -u
```

**Find high-severity alerts:**
```bash
jq 'select(.event_type=="alert" and .alert.severity==1)' eve.json
```

**Extract all HTTP events with status code:**
```bash
jq 'select(.event_type=="http") | {host: .http.hostname, url: .http.url, status: .http.status}' eve.json
```

**DNS queries by host:**
```bash
jq -r 'select(.event_type=="dns" and .dns.type=="query") | "\(.src_ip) -> \(.dns.rrname)"' eve.json
```

**TLS certificates by fingerprint:**
```bash
jq -r 'select(.event_type=="tls") | {subject: .tls.subject, fingerprint: .tls.fingerprint}' eve.json
```

### Using Python

```python
import json

alerts = []
with open('eve.json', 'r') as f:
    for line in f:
        event = json.loads(line)
        if event['event_type'] == 'alert':
            alerts.append({
                'timestamp': event['timestamp'],
                'signature': event['alert']['signature'],
                'src_ip': event['src_ip'],
                'dest_ip': event['dest_ip']
            })

# Print all alerts
for alert in alerts:
    print(f"{alert['timestamp']}: {alert['signature']}")
```

### Using Logstash

```ruby
input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => json
    type => "suricata"
  }
}

filter {
  if [event_type] == "alert" {
    mutate {
      add_tag => ["alert"]
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

## Integration Examples

### Elasticsearch Query

```json
GET suricata-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event_type": "alert" }},
        { "range": { "alert.severity": { "lte": 1 }}}
      ]
    }
  },
  "sort": [
    { "timestamp": "desc" }
  ]
}
```

### Splunk Search

```
index=suricata event_type=alert 
| stats count by alert.signature, alert.severity 
| sort -count
```

### SIEM Correlation

Look for multiple alerts from same source:
```bash
jq -r 'select(.event_type=="alert") | "\(.src_ip) \(.alert.signature)"' eve.json | \
  awk '{print $1}' | sort | uniq -c | sort -rn
```

## Best Practices

1. **Rotate logs regularly** - EVE JSON can grow very large
2. **Index for searching** - Use Elasticsearch or similar for large deployments
3. **Monitor disk space** - Set appropriate log retention policies
4. **Parse incrementally** - Don't load entire file into memory
5. **Correlate events** - Use flow_id to link related events
6. **Baseline normal traffic** - Understand your environment before alerting

## Related Files

- `fast.log.example` - Simplified alert format
- `alert-examples.md` - Detailed alert analysis guide
- `pcap-samples/README.md` - Testing with packet captures

---

*For more information, see the official Suricata EVE JSON documentation:*
https://suricata.readthedocs.io/en/latest/output/eve/eve-json-format.html
