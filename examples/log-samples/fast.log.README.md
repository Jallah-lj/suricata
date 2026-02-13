# Fast.log Format Guide

This document explains the format and structure of Suricata's `fast.log` output.

## Overview

The fast.log format provides a quick, single-line view of each alert. It's designed for:
- Quick scanning of alerts
- Log aggregation tools
- Real-time monitoring
- Lightweight alert storage

## Format Structure

```
TIMESTAMP  [**] [GID:SID:REV] SIGNATURE [**] [Classification: CATEGORY] [Priority: N] {PROTOCOL} SOURCE_IP:PORT -> DEST_IP:PORT
```

### Field Breakdown

**Example:**
```
01/15/2024-10:23:45.123456  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.105:54321 -> 198.51.100.42:80
```

**1. Timestamp:** `01/15/2024-10:23:45.123456`
- Format: MM/DD/YYYY-HH:MM:SS.microseconds
- Local time (depends on Suricata configuration)

**2. Generator ID (GID):** `1`
- `1` = Standard Suricata rules
- `2` = Preprocessor events
- `3` = Custom rules
- Higher numbers = specific rule sources

**3. Signature ID (SID):** `2100498`
- Unique identifier for the rule
- Used to reference specific signatures
- Emerging Threats rules typically use 2000000-2999999

**4. Revision (REV):** `7`
- Rule version number
- Increments when rule is updated

**5. Signature:** `GPL ATTACK_RESPONSE id check returned root`
- Human-readable alert description
- Describes what was detected

**6. Classification:** `Potentially Bad Traffic`
- Category/type of attack
- See [Classifications](#common-classifications) section

**7. Priority:** `2`
- `1` = High severity
- `2` = Medium severity
- `3` = Low severity

**8. Protocol:** `{TCP}`
- Network protocol: TCP, UDP, ICMP, etc.

**9. Source:** `192.168.1.105:54321`
- Source IP address and port

**10. Destination:** `198.51.100.42:80`
- Destination IP address and port

## Common Classifications

| Classification | Description | Typical Priority |
|----------------|-------------|------------------|
| A Network Trojan was detected | Malware/botnet activity | 1 |
| Web Application Attack | SQL injection, XSS, etc. | 1 |
| Attempted Administrator Privilege Gain | Privilege escalation attempts | 1 |
| Potentially Bad Traffic | Suspicious but not confirmed malicious | 2 |
| Attempted Information Leak | Data exfiltration, recon | 2 |
| Potential Corporate Privacy Violation | Policy violations | 2 |
| Generic Protocol Command Decode | Protocol parsing issues | 3 |

## Parsing Fast.log

### Using grep

**Find all high-priority alerts:**
```bash
grep "Priority: 1" fast.log
```

**Search for specific signature:**
```bash
grep "SQL Injection" fast.log
```

**Find alerts from specific IP:**
```bash
grep "192.168.1.105" fast.log
```

**Count alerts by classification:**
```bash
grep -oP '\[Classification: \K[^\]]+' fast.log | sort | uniq -c | sort -rn
```

### Using awk

**Extract timestamp and signature:**
```bash
awk -F'\\[\\*\\*\\]' '{print $1, $2}' fast.log
```

**Find top source IPs:**
```bash
grep -oP '\{TCP\} \K[\d.]+(?=:)' fast.log | sort | uniq -c | sort -rn | head -10
```

**Count alerts per hour:**
```bash
awk '{print substr($1, 1, 13)}' fast.log | sort | uniq -c
```

### Using sed

**Extract just signatures:**
```bash
sed -n 's/.*\] \(.*\) \[.*\[Classification.*/\1/p' fast.log
```

**Remove duplicate alerts:**
```bash
sort fast.log | uniq
```

## Analysis Examples

### Example 1: Detecting Attack Campaigns

Multiple alerts from same source in short time:
```bash
cat fast.log | \
  grep -oP '\{TCP\} \K[\d.]+' | \
  sort | uniq -c | \
  awk '$1 > 10 {print $2, "triggered", $1, "alerts"}'
```

### Example 2: Priority Distribution

```bash
echo "Priority 1 (High):   $(grep -c 'Priority: 1' fast.log)"
echo "Priority 2 (Medium): $(grep -c 'Priority: 2' fast.log)"
echo "Priority 3 (Low):    $(grep -c 'Priority: 3' fast.log)"
```

### Example 3: Timeline Analysis

```bash
# Alerts per minute
awk '{print substr($1, 1, 16)}' fast.log | sort | uniq -c | \
  awk '{printf "%s %3d alerts\n", $2, $1}'
```

### Example 4: Top Attacked Targets

```bash
grep -oP '-> \K[\d.]+(?=:)' fast.log | \
  sort | uniq -c | sort -rn | head -5 | \
  awk '{print $2, "received", $1, "attacks"}'
```

### Example 5: Protocol Distribution

```bash
grep -oP '\{\K[^}]+' fast.log | sort | uniq -c | \
  awk '{printf "%-10s %d alerts\n", $2, $1}'
```

## Integration with Tools

### Fail2Ban Integration

Create `/etc/fail2ban/filter.d/suricata.conf`:
```ini
[Definition]
failregex = ^\S+ \[.*\] .*\[Priority: 1\] \{TCP\} <HOST>:\d+ ->
ignoreregex =
```

Then in `/etc/fail2ban/jail.local`:
```ini
[suricata]
enabled = true
filter = suricata
logpath = /var/log/suricata/fast.log
bantime = 3600
maxretry = 5
action = iptables-allports[name=suricata]
```

### Logwatch Configuration

Create custom logwatch script to summarize fast.log alerts.

### Syslog Integration

Send alerts to syslog:
```bash
tail -F fast.log | while read line; do
  logger -t suricata -p security.alert "$line"
done
```

### Real-time Monitoring with watch

```bash
watch -n 5 'tail -20 /var/log/suricata/fast.log'
```

### Dashboard Script

```bash
#!/bin/bash
echo "=== Suricata Alert Summary ==="
echo "Total Alerts: $(wc -l < fast.log)"
echo ""
echo "By Priority:"
echo "  High:   $(grep -c 'Priority: 1' fast.log)"
echo "  Medium: $(grep -c 'Priority: 2' fast.log)"
echo "  Low:    $(grep -c 'Priority: 3' fast.log)"
echo ""
echo "Top 5 Signatures:"
grep -oP '\]\s+\K[^\[]+(?=\s+\[)' fast.log | \
  sort | uniq -c | sort -rn | head -5
echo ""
echo "Top 5 Attackers:"
grep -oP '\{TCP\} \K[\d.]+(?=:)' fast.log | \
  sort | uniq -c | sort -rn | head -5
```

## Comparison with EVE JSON

| Feature | fast.log | eve.json |
|---------|----------|----------|
| Format | Single line | JSON objects |
| Size | Smaller | Larger (detailed) |
| Parsing | grep/awk friendly | Requires JSON parser |
| Details | Alert summary only | Full event context |
| Performance | Very fast | Slightly slower |
| Use Case | Quick scanning | Deep analysis |

**When to use fast.log:**
- Quick alert review
- Log aggregation tools that parse text
- Limited disk space
- Real-time monitoring dashboards
- Simple alerting scripts

**When to use eve.json:**
- Detailed investigation
- SIEM integration
- Forensic analysis
- Need HTTP/DNS/TLS details
- Machine learning/analytics

## Log Rotation

### Using logrotate

Create `/etc/logrotate.d/suricata`:
```
/var/log/suricata/fast.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 suricata suricata
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
```

### Manual rotation

```bash
# Rotate logs
mv /var/log/suricata/fast.log /var/log/suricata/fast.log.1

# Signal Suricata to reopen log files
kill -HUP $(cat /var/run/suricata.pid)

# Compress old log
gzip /var/log/suricata/fast.log.1
```

## Tips and Best Practices

1. **Grep is your friend** - fast.log is optimized for grep
2. **Monitor priority 1 alerts** - Set up real-time alerting
3. **Correlate with eve.json** - Use fast.log for overview, eve.json for details
4. **Watch disk space** - Implement log rotation
5. **Create baselines** - Know your normal alert rate
6. **Use timestamps** - Track alert timing patterns
7. **Filter noise** - Suppress known false positives

## Common Patterns

### Port Scan Detection
```
01/15/2024-10:27:30.567890  [**] [1:2001219:19] ET SCAN Potential SSH Scan [**]
01/15/2024-10:27:31.234567  [**] [1:2001219:19] ET SCAN Potential SSH Scan [**]
01/15/2024-10:27:32.456789  [**] [1:2001219:19] ET SCAN Potential SSH Scan [**]
```
*Sequential alerts with same SID indicate scanning activity*

### Malware Beaconing
```
01/15/2024-10:00:00  [**] [1:2024897:4] ET MALWARE Emotet CnC
01/15/2024-10:05:00  [**] [1:2024897:4] ET MALWARE Emotet CnC
01/15/2024-10:10:00  [**] [1:2024897:4] ET MALWARE Emotet CnC
```
*Regular intervals suggest C2 beaconing*

### Web Application Attack
```
01/15/2024-10:25:03  [**] [1:2013028:3] SQL Injection Attempt [**]
01/15/2024-10:25:15  [**] [1:2019401:2] XSS Attempt [**]
01/15/2024-10:25:30  [**] [1:2012345:1] Path Traversal [**]
```
*Multiple web attack types from same source*

## Troubleshooting

**No alerts appearing:**
- Check if Suricata is running: `systemctl status suricata`
- Verify rule loading: `suricata --dump-config | grep rule-files`
- Check permissions: `ls -la /var/log/suricata/`

**Too many alerts:**
- Review and tune rules
- Implement threshold/suppress rules
- Check for false positives
- Consider home_net configuration

**Missing timestamps:**
- Check Suricata configuration for time format
- Verify system time is correct

## Related Documentation

- `eve.json.example` - Detailed JSON event format
- `README.md` - EVE JSON format guide
- `../alert-examples.md` - Alert investigation guide
- `../pcap-samples/README.md` - Testing with PCAPs

---

*For official documentation, visit:*
https://suricata.readthedocs.io/en/latest/output/eve/eve-json-output.html
