# Rules Overview

Suricata rules are the heart of the intrusion detection system. This guide explains the syntax, structure, and components of Suricata rules.

## Table of Contents

- [What are Suricata Rules?](#what-are-suricata-rules)
- [Rule Structure](#rule-structure)
- [Rule Headers](#rule-headers)
- [Rule Options](#rule-options)
- [Rule Actions](#rule-actions)
- [Common Keywords](#common-keywords)
- [Rule Examples](#rule-examples)
- [Rule Order and Priority](#rule-order-and-priority)
- [Best Practices](#best-practices)

## What are Suricata Rules?

Suricata rules define what network traffic patterns to detect and alert on. Each rule describes:
- **What** to look for (malicious patterns, suspicious behavior)
- **Where** to look (protocol, ports, direction)
- **How** to respond (alert, drop, reject)
- **Details** about the detection (message, classification, severity)

## Rule Structure

A Suricata rule has two main parts:

```
[ACTION] [PROTOCOL] [SOURCE] [SOURCE_PORT] [DIRECTION] [DESTINATION] [DEST_PORT] ([OPTIONS])
```

### Visual Breakdown

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"HTTP GET Request"; content:"GET"; sid:1000001; rev:1;)
  │    │         │        │   │      │      │        │                     │              │        │
  │    │         │        │   │      │      │        └─ Options────────────┘              │        │
  │    │         │        │   │      │      └─ Destination Port                           │        │
  │    │         │        │   │      └─ Destination IP                                    │        │
  │    │         │        │   └─ Direction                                                │        │
  │    │         │        └─ Source Port                                                  │        │
  │    │         └─ Source IP                                                             │        │
  │    └─ Protocol                                                                         │        │
  └─ Action                                                                               SID     Revision
```

### Example Rules

**Simple ICMP Detection:**
```
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
```

**HTTP SQL Injection:**
```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL Injection Attempt"; flow:established,to_server; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; sid:1000002; rev:1;)
```

**SSH Brute Force:**
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000003; rev:1;)
```

## Rule Headers

The rule header defines the basic parameters of the detection.

### Action

What Suricata should do when the rule matches:

| Action | Description |
|--------|-------------|
| `alert` | Generate an alert (most common) |
| `pass` | Stop further inspection, allow the packet |
| `drop` | Drop the packet and generate alert (IPS mode) |
| `reject` | Drop packet, send TCP RST or ICMP error (IPS mode) |
| `rejectsrc` | Same as reject, but only send RST to source |
| `rejectdst` | Same as reject, but only send RST to destination |
| `rejectboth` | Send RST to both source and destination |

**Examples:**
```
alert tcp any any -> any any (...)     # Just alert
drop tcp any any -> any any (...)      # Drop and alert (IPS)
pass tcp any any -> any 80 (...)       # Allow without further inspection
reject tcp any any -> any 23 (...)     # Reject telnet connections
```

### Protocol

Which network protocol to inspect:

| Protocol | Description |
|----------|-------------|
| `tcp` | TCP traffic |
| `udp` | UDP traffic |
| `icmp` | ICMP traffic |
| `ip` | Any IP traffic |
| `http` | HTTP protocol (application layer) |
| `ftp` | FTP protocol |
| `tls` | TLS/SSL traffic |
| `smb` | SMB protocol |
| `dns` | DNS protocol |
| `ssh` | SSH protocol |

**Examples:**
```
alert tcp ...       # TCP traffic
alert udp ...       # UDP traffic
alert http ...      # HTTP application layer
alert dns ...       # DNS queries/responses
```

### Source and Destination

#### IP Addresses

| Format | Description | Example |
|--------|-------------|---------|
| `any` | Any IP address | `any` |
| `IP/CIDR` | Specific network | `192.168.1.0/24` |
| `IP` | Specific host | `192.168.1.1` |
| `[...]` | List of addresses | `[192.168.1.1,10.0.0.1]` |
| `!IP` | NOT this address | `!192.168.1.1` |
| `$VAR` | Variable from config | `$HOME_NET` |

**Examples:**
```
alert tcp 192.168.1.0/24 any -> any any (...)          # From local network
alert tcp any any -> $HOME_NET any (...)                # To home network
alert tcp !$HOME_NET any -> $HOME_NET any (...)         # External to internal
alert tcp [192.168.1.1,192.168.1.2] any -> any any (...) # Specific hosts
```

#### Ports

| Format | Description | Example |
|--------|-------------|---------|
| `any` | Any port | `any` |
| `80` | Specific port | `80` |
| `[80,443]` | Multiple ports | `[80,443,8080]` |
| `80:90` | Port range | `1024:65535` |
| `!80` | NOT this port | `!22` |
| `$VAR` | Variable | `$HTTP_PORTS` |

**Examples:**
```
alert tcp any any -> any 80 (...)                # To port 80
alert tcp any any -> any [80,443,8080] (...)     # To web ports
alert tcp any any -> any 1024:65535 (...)        # To high ports
alert tcp any 22 -> any any (...)                # From SSH port
alert tcp any !80 -> any any (...)               # From non-HTTP
```

### Direction

| Operator | Description |
|----------|-------------|
| `->` | From source to destination (unidirectional) |
| `<>` | Bidirectional (matches both directions) |

**Examples:**
```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (...)    # Inbound only
alert tcp $HOME_NET any <> $EXTERNAL_NET any (...)    # Both directions
```

## Rule Options

Rule options provide the detailed detection logic and are enclosed in parentheses.

### General Options

#### msg (Message)

Human-readable description of what the rule detects:

```
msg:"SQL Injection Attempt Detected";
msg:"Possible Malware C2 Communication";
msg:"SSH Brute Force Attack";
```

#### sid (Signature ID)

Unique identifier for the rule:

```
sid:1000001;
```

**SID Ranges:**
- `1-999,999`: Reserved for Suricata/Emerging Threats
- `1,000,000-1,999,999`: Local/custom rules (recommended)
- `2,000,000+`: User rules

#### rev (Revision)

Version number of the rule:

```
rev:1;    # First version
rev:2;    # Updated version
```

#### classtype (Classification)

Categorizes the alert:

```
classtype:trojan-activity;
classtype:web-application-attack;
classtype:attempted-admin;
```

**Common classtypes:**
- `attempted-admin` - Administrator privilege gain
- `attempted-user` - User privilege gain
- `web-application-attack` - Web attack
- `trojan-activity` - Trojan or backdoor
- `successful-admin` - Successful admin access
- `denial-of-service` - DoS attack
- `bad-unknown` - Unknown bad traffic
- `misc-attack` - Miscellaneous attack

#### reference

Links to external information:

```
reference:url,www.exploit-db.com/exploits/12345;
reference:cve,2021-12345;
reference:bugtraq,12345;
```

#### priority

Alert priority (1=high, 2=medium, 3=low):

```
priority:1;   # High priority
priority:2;   # Medium priority
priority:3;   # Low priority
```

### Content Matching

#### content

Match specific byte sequences:

```
content:"GET";                    # Case-sensitive
content:"admin"; nocase;          # Case-insensitive
content:"|0d 0a|";                # Hex bytes (CRLF)
content:"password"; offset:0;     # Start at beginning
content:"admin"; depth:100;       # Look in first 100 bytes
```

**Multiple content matches:**
```
content:"POST"; nocase;
content:"/login.php"; nocase; distance:0;
content:"password="; nocase;
```

#### nocase

Make content match case-insensitive:

```
content:"admin"; nocase;
content:"SELECT"; nocase;
```

#### depth

How far into the packet to search (from start):

```
content:"GET"; depth:4;          # Look in first 4 bytes
content:"HTTP"; depth:100;       # Look in first 100 bytes
```

#### offset

Where to start searching:

```
content:"admin"; offset:10;      # Start 10 bytes in
```

#### distance

Bytes between previous and current match:

```
content:"POST";
content:"/login"; distance:1;    # Must be 1+ bytes after POST
```

#### within

Maximum bytes after previous match:

```
content:"user";
content:"admin"; within:50;      # Must be within 50 bytes after "user"
```

### PCRE (Regular Expressions)

Use Perl-Compatible Regular Expressions for complex patterns:

```
pcre:"/admin|root|administrator/i";              # Alternative usernames
pcre:"/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/";   # IP address pattern
pcre:"/union.+select/i";                         # SQL injection
pcre:"/(<script|javascript:)/i";                 # XSS patterns
```

**PCRE modifiers:**
- `i` - Case insensitive
- `s` - Dot matches newline
- `m` - Multi-line mode
- `U` - Match non-greedy

### Flow and State

#### flow

Match on connection state and direction:

```
flow:established;                 # Established connection
flow:to_server;                   # Client to server
flow:to_client;                   # Server to client
flow:from_server;                 # Same as to_client
flow:from_client;                 # Same as to_server
flow:established,to_server;       # Established, client to server
flow:stateless;                   # No state tracking
```

#### flowbits

Set and check connection-level flags:

```
flowbits:set,malware.download;    # Set a flag
flowbits:isset,malware.download;  # Check if flag is set
flowbits:unset,malware.download;  # Unset a flag
flowbits:toggle,suspicious;       # Toggle flag
flowbits:noalert;                 # Don't generate alert
```

### Threshold and Detection Frequency

#### threshold

Control alert frequency:

```
threshold:type threshold, track by_src, count 5, seconds 60;
threshold:type limit, track by_dst, count 1, seconds 3600;
threshold:type both, track by_src, count 10, seconds 120;
```

**Types:**
- `threshold` - Alert every N matches
- `limit` - Alert once per time period
- `both` - Alert once at threshold, then once per period

**Track by:**
- `by_src` - Track by source IP
- `by_dst` - Track by destination IP
- `by_rule` - Track by rule globally

### Protocol-Specific Keywords

#### HTTP Keywords

```
http.method; content:"POST";              # HTTP method
http.uri; content:"/admin";               # Request URI
http.host; content:"evil.com";            # Host header
http.user_agent; content:"bot";           # User-Agent
http.header; content:"X-Custom";          # Any header
http.cookie; content:"session=";          # Cookie header
http.response_body; content:"error";      # Response content
http.stat_code; content:"404";            # Status code
```

#### DNS Keywords

```
dns.query; content:"evil.com";            # DNS query name
dns.opcode; content:"0";                  # DNS operation
```

#### TLS Keywords

```
tls.subject; content:"evil.com";          # TLS certificate subject
tls.issuer; content:"LetsEncrypt";        # Certificate issuer
tls.sni; content:"malware.com";           # Server Name Indication
```

#### SSH Keywords

```
ssh.proto; content:"2.0";                 # SSH protocol version
ssh.software; content:"OpenSSH";          # SSH software
```

## Rule Actions

### Alert (IDS Mode)

Generate alert without blocking:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Connection Attempt"; sid:1000001;)
```

### Drop (IPS Mode)

Block the packet and generate alert:

```
drop tcp any any -> $HOME_NET any (msg:"Known Malware C2"; content:"malicious.com"; sid:1000002;)
```

### Pass

Allow packet without further inspection:

```
pass tcp $HOME_NET any -> any 443 (msg:"Allow HTTPS to trusted site"; content:"trusted.com"; sid:1000003;)
```

### Reject

Block and send RST/ICMP error:

```
reject tcp $EXTERNAL_NET any -> $HOME_NET 23 (msg:"Block Telnet"; sid:1000004;)
```

## Rule Examples

### Example 1: ICMP Ping Detection

```
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; itype:8; sid:1000001; rev:1;)
```

### Example 2: HTTP SQL Injection

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL Injection - UNION SELECT"; flow:established,to_server; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:1000002; rev:1;)
```

### Example 3: SSH Brute Force

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Possible SSH Brute Force"; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000003; rev:1;)
```

### Example 4: DNS Tunneling

```
alert dns $HOME_NET any -> any 53 (msg:"Possible DNS Tunneling - Long Query"; dns.query; content:"."; pcre:"/^.{50,}/"; classtype:bad-unknown; sid:1000004; rev:1;)
```

### Example 5: TLS Certificate Check

```
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"Suspicious TLS Certificate"; tls.subject; content:"malware"; nocase; classtype:trojan-activity; sid:1000005; rev:1;)
```

## Rule Order and Priority

### Processing Order

Suricata processes rules in the order they appear in the rule files, but with some optimizations:

1. **Pass rules** are processed first
2. **Drop/Reject rules** before alert rules (in IPS mode)
3. **Rules are optimized** by Suricata's engine

### Priority Levels

Priority affects alert importance:

```
priority:1;   # High (critical issues)
priority:2;   # Medium (suspicious activity)
priority:3;   # Low (policy violations, info)
```

Classtype sets default priority:
```
classtype:trojan-activity;        # Priority 1 (high)
classtype:web-application-attack; # Priority 2 (medium)
classtype:misc-activity;          # Priority 3 (low)
```

### Rule Organization

Organize rules logically:

```
# File: /etc/suricata/rules/local.rules

# === Web Attacks ===
alert http ...
alert http ...

# === Malware Detection ===
alert tcp ...
alert dns ...

# === Brute Force ===
alert tcp ...
alert ssh ...
```

## Best Practices

### Writing Effective Rules

1. **Be Specific**: Avoid overly broad rules that generate false positives
   ```
   # Bad: Too broad
   alert tcp any any -> any any (content:"admin"; sid:1;)
   
   # Good: Specific context
   alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Admin Login Attempt"; http.uri; content:"/admin/login"; http.method; content:"POST"; sid:1;)
   ```

2. **Use Flow**: Always use flow for TCP connections
   ```
   alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"HTTP Attack"; flow:established,to_server; content:"attack"; sid:1;)
   ```

3. **Optimize Content Matches**: Put most unique content first
   ```
   # Good: Unique string first
   content:"very_unique_string";
   content:"common_word";
   ```

4. **Use Protocol Keywords**: Leverage application-layer keywords
   ```
   alert http any any -> any any (msg:"Admin Access"; http.uri; content:"/admin"; sid:1;)
   ```

5. **Add Context**: Use msg, classtype, and reference
   ```
   alert http any any -> any any (
       msg:"SQL Injection Attempt"; 
       flow:established,to_server; 
       content:"UNION"; nocase; 
       classtype:web-application-attack; 
       reference:url,owasp.org/sqli; 
       sid:1000001; 
       rev:1;
   )
   ```

### Testing Rules

```bash
# Test rule syntax
sudo suricata -T -c /etc/suricata/suricata.yaml

# Test rules with PCAP
sudo suricata -c /etc/suricata/suricata.yaml -r test.pcap -l /tmp/

# Check for rule errors
sudo suricata -c /etc/suricata/suricata.yaml --init-errors-fatal -v
```

### Documentation

Always document your custom rules:

```
# Rule: SQL Injection Detection
# Author: Security Team
# Date: 2024-01-15
# Purpose: Detect UNION-based SQL injection attacks
# Testing: Verified against DVWA and SQLMap
# False Positives: None known
# References: OWASP Top 10, CWE-89
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SQL Injection - UNION SELECT";
    flow:established,to_server;
    content:"UNION"; nocase;
    content:"SELECT"; nocase; distance:0;
    classtype:web-application-attack;
    reference:url,owasp.org/www-community/attacks/SQL_Injection;
    sid:1000001;
    rev:1;
)
```

## Common Mistakes to Avoid

1. ❌ **No sid or rev**
   ```
   alert tcp any any -> any any (content:"bad";)  # Missing sid and rev!
   ```

2. ❌ **Too broad**
   ```
   alert tcp any any -> any any (content:"a";)  # Will match everything!
   ```

3. ❌ **No flow for TCP**
   ```
   alert tcp any any -> any 80 (content:"GET";)  # Should use flow
   ```

4. ❌ **Improper quoting**
   ```
   alert tcp any any -> any any (msg:Test;)  # Should be "Test"
   ```

5. ❌ **Missing semicolons**
   ```
   alert tcp any any -> any any (msg:"test" sid:1)  # Missing semicolons
   ```

## Next Steps

Now that you understand rule syntax:

1. **Manage Rules**: See [Rule Management Guide](05-rule-management.md)
2. **Write Custom Rules**: See [Custom Rules Guide](06-custom-rules.md)
3. **Analyze Alerts**: See [Log Analysis](07-log-analysis.md)
4. **See Examples**: Check `rules/examples/` directory

---

[← Back: Basic Configuration](03-basic-configuration.md) | [Home](../README.md) | [Next: Rule Management →](05-rule-management.md)
