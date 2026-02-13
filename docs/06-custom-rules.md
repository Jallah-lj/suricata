# Writing Custom Detection Rules

This guide provides practical examples for writing custom Suricata detection rules, from simple pattern matching to complex multi-stage detections.

## Table of Contents

- [Getting Started](#getting-started)
- [Rule Writing Basics](#rule-writing-basics)
- [Content Matching](#content-matching)
- [PCRE (Regular Expressions)](#pcre-regular-expressions)
- [HTTP-Specific Rules](#http-specific-rules)
- [DNS Rules](#dns-rules)
- [TLS/SSL Rules](#tlsssl-rules)
- [Practical Examples](#practical-examples)
- [Testing Your Rules](#testing-your-rules)
- [Best Practices](#best-practices)

## Getting Started

### Setup Local Rules File

```bash
# Create custom rules directory
sudo mkdir -p /etc/suricata/rules

# Create local rules file
sudo nano /etc/suricata/rules/local.rules
```

### SID Ranges

Use appropriate SID ranges for custom rules:

| Range | Purpose |
|-------|---------|
| 1-999,999 | Reserved (Emerging Threats) |
| 1,000,000-1,999,999 | Local custom rules (recommended) |
| 2,000,000-2,999,999 | Custom/organization rules |
| 3,000,000+ | Testing and development |

Example SID assignment:

```
# SQL injection rules: 1000001-1000099
sid:1000001;
sid:1000002;

# XSS rules: 1000100-1000199
sid:1000100;
sid:1000101;

# Malware rules: 1000200-1000299
sid:1000200;
sid:1000201;
```

## Rule Writing Basics

### Simple Detection Template

```
alert [PROTOCOL] $EXTERNAL_NET any -> $HOME_NET [PORT] (
    msg:"[DESCRIPTION]";
    flow:[FLOW_OPTIONS];
    [DETECTION_LOGIC];
    classtype:[CLASSIFICATION];
    sid:[SID_NUMBER];
    rev:1;
)
```

### Basic Example

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"SSH Connection Attempt";
    flow:to_server,established;
    content:"SSH-2.0";
    classtype:misc-activity;
    sid:1000001;
    rev:1;
)
```

### Rule Components Explained

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (
    msg:"HTTP GET Request to Admin";          # Alert message
    flow:established,to_server;                # Connection state
    content:"GET"; http_method;                # HTTP method
    content:"/admin"; http_uri; nocase;        # URI path
    classtype:web-application-activity;        # Classification
    sid:1000002;                               # Unique ID
    rev:1;                                     # Revision
)
```

## Content Matching

### Basic Content Matching

```
# Case-sensitive match
content:"password";

# Case-insensitive match
content:"admin"; nocase;

# Multiple content matches (AND logic)
content:"POST"; nocase;
content:"login.php"; nocase;
content:"password="; nocase;
```

### Content with Position

```
# Look in first 10 bytes
content:"GET"; depth:10;

# Start at offset 50
content:"password"; offset:50;

# Between previous match and 100 bytes after
content:"user";
content:"admin"; distance:0; within:100;
```

### Hex Content

```
# Match hex bytes
content:"|0d 0a|";                    # CRLF
content:"|00 00 00 00|";              # Four null bytes
content:"|ff d8 ff|";                 # JPEG signature

# Mixed content
content:"GET |0d 0a|Host:";           # GET\r\nHost:
```

### Content Negation

```
# Match if content is NOT present
content:!"admin"; nocase;

# Complex logic
content:"login.php";
content:!"success"; nocase;    # No "success" in response
```

### Fast Pattern

Optimize rule performance:

```
# Mark most unique content as fast pattern
content:"very_unique_string"; fast_pattern;
content:"common_word";
```

## PCRE (Regular Expressions)

### Basic PCRE Syntax

```
# Simple pattern
pcre:"/admin/i";                      # Case-insensitive "admin"

# Alternative patterns
pcre:"/(admin|root|administrator)/i"; # Any of these

# Character classes
pcre:"/[0-9]{1,3}\.[0-9]{1,3}/";     # IP pattern

# Anchors
pcre:"/^GET/";                        # Starts with GET
pcre:"/\.php$/";                      # Ends with .php
```

### PCRE Modifiers

```
pcre:"/pattern/i";     # Case insensitive
pcre:"/pattern/s";     # Dot matches newline
pcre:"/pattern/m";     # Multi-line mode
pcre:"/pattern/x";     # Extended (ignore whitespace)
pcre:"/pattern/U";     # Non-greedy matching
```

### Advanced PCRE Examples

```
# Email address pattern
pcre:"/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/";

# URL pattern
pcre:"/https?:\/\/[^\s]+/i";

# SQL injection pattern
pcre:"/(union|select|insert|update|delete|drop)\s+/i";

# XSS pattern
pcre:"/(<script|javascript:|onerror=|onload=)/i";

# Credit card pattern (PCI compliance)
pcre:"/\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/";
```

### Combining Content and PCRE

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SQL Injection with PCRE";
    flow:established,to_server;
    content:"UNION"; nocase; fast_pattern;
    pcre:"/union\s+select/i";
    classtype:web-application-attack;
    sid:1000003;
    rev:1;
)
```

## HTTP-Specific Rules

### HTTP Method Detection

```
# Detect specific HTTP method
alert http any any -> any any (
    msg:"HTTP POST to Login";
    http.method; content:"POST";
    http.uri; content:"/login"; nocase;
    sid:1000010;
    rev:1;
)

# Detect dangerous methods
alert http any any -> any any (
    msg:"HTTP TRACE Method Detected";
    http.method; content:"TRACE";
    classtype:web-application-attack;
    sid:1000011;
    rev:1;
)
```

### HTTP URI Detection

```
# Detect admin access
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Admin Panel Access Attempt";
    flow:established,to_server;
    http.uri; content:"/admin"; nocase;
    http.uri; content:"/wp-admin"; nocase;
    classtype:web-application-activity;
    sid:1000012;
    rev:1;
)

# Detect directory traversal
alert http any any -> any any (
    msg:"Directory Traversal Attempt";
    flow:established,to_server;
    http.uri; content:".."; nocase;
    pcre:"/\.\.\/.*\.\./";
    classtype:web-application-attack;
    sid:1000013;
    rev:1;
)
```

### HTTP Host Detection

```
# Detect specific domain
alert http any any -> any any (
    msg:"Access to Malicious Domain";
    flow:established,to_server;
    http.host; content:"evil.com"; nocase;
    classtype:trojan-activity;
    sid:1000014;
    rev:1;
)

# Detect suspicious TLD
alert http any any -> any any (
    msg:"Suspicious TLD Access";
    flow:established,to_server;
    http.host; pcre:"/\.(tk|ml|ga|cf)$/i";
    classtype:bad-unknown;
    sid:1000015;
    rev:1;
)
```

### HTTP User-Agent Detection

```
# Detect suspicious user agents
alert http any any -> any any (
    msg:"Suspicious User-Agent - Scanner Detected";
    flow:established,to_server;
    http.user_agent; content:"sqlmap"; nocase;
    classtype:web-application-attack;
    sid:1000016;
    rev:1;
)

# Detect bot patterns
alert http any any -> any any (
    msg:"Known Bot User-Agent";
    flow:established,to_server;
    http.user_agent; pcre:"/(bot|crawler|spider|scraper)/i";
    classtype:misc-activity;
    sid:1000017;
    rev:1;
)
```

### HTTP Header Detection

```
# Detect custom headers
alert http any any -> any any (
    msg:"Custom Attack Header Detected";
    flow:established,to_server;
    http.header; content:"X-Forwarded-For"; nocase;
    http.header; content:"127.0.0.1";
    classtype:web-application-attack;
    sid:1000018;
    rev:1;
)

# Detect missing headers
alert http any any -> any any (
    msg:"HTTP Request Without User-Agent";
    flow:established,to_server;
    http.user_agent; content:!"|20|";    # No space (empty)
    classtype:bad-unknown;
    sid:1000019;
    rev:1;
)
```

### HTTP Cookie Detection

```
# Detect session manipulation
alert http any any -> any any (
    msg:"Session Cookie Manipulation Attempt";
    flow:established,to_server;
    http.cookie; content:"admin=true"; nocase;
    classtype:web-application-attack;
    sid:1000020;
    rev:1;
)
```

### HTTP Response Detection

```
# Detect error pages
alert http any any -> any any (
    msg:"SQL Error in HTTP Response";
    flow:established,to_client;
    http.stat_code; content:"200";
    content:"SQL syntax error"; nocase;
    classtype:web-application-attack;
    sid:1000021;
    rev:1;
)

# Detect data leakage
alert http any any -> any any (
    msg:"Credit Card in HTTP Response";
    flow:established,to_client;
    http.response_body;
    pcre:"/\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/";
    classtype:policy-violation;
    sid:1000022;
    rev:1;
)
```

## DNS Rules

### DNS Query Detection

```
# Detect specific domain query
alert dns $HOME_NET any -> any 53 (
    msg:"DNS Query to Suspicious Domain";
    dns.query; content:"evil.com"; nocase;
    classtype:bad-unknown;
    sid:1000030;
    rev:1;
)

# Detect subdomain pattern
alert dns any any -> any 53 (
    msg:"Suspicious DNS Subdomain Pattern";
    dns.query; pcre:"/[a-z0-9]{20,}\..*\.(com|net|org)/i";
    classtype:bad-unknown;
    sid:1000031;
    rev:1;
)
```

### DNS Tunneling Detection

```
# Detect long DNS queries (tunneling)
alert dns $HOME_NET any -> any 53 (
    msg:"Possible DNS Tunneling - Long Query";
    dns.query; content:".";
    pcre:"/^.{50,}/";
    classtype:bad-unknown;
    sid:1000032;
    rev:1;
)

# Detect high query rate
alert dns $HOME_NET any -> any 53 (
    msg:"DNS Tunneling - High Query Rate";
    dns.query; content:".";
    threshold:type threshold, track by_src, count 50, seconds 60;
    classtype:bad-unknown;
    sid:1000033;
    rev:1;
)
```

### DNS DGA Detection

```
# Detect Domain Generation Algorithm patterns
alert dns any any -> any 53 (
    msg:"Possible DGA Domain Detected";
    dns.query;
    pcre:"/^[a-z]{15,}\.(com|net|org|info)$/i";
    classtype:trojan-activity;
    sid:1000034;
    rev:1;
)

# Detect random-looking subdomains
alert dns any any -> any 53 (
    msg:"Random Subdomain Pattern - Possible DGA";
    dns.query;
    pcre:"/^[bcdfghjklmnpqrstvwxz]{8,}\./i";
    classtype:trojan-activity;
    sid:1000035;
    rev:1;
)
```

## TLS/SSL Rules

### TLS Certificate Detection

```
# Detect suspicious certificate subject
alert tls $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Suspicious TLS Certificate Subject";
    tls.subject; content:"evil.com"; nocase;
    classtype:bad-unknown;
    sid:1000040;
    rev:1;
)

# Detect self-signed certificates
alert tls any any -> any any (
    msg:"Self-Signed Certificate Detected";
    tls.subject; content:"CN=";
    tls.issuer; content:"CN=";
    pcre:"/subject=.*issuer=\1/i";
    classtype:misc-activity;
    sid:1000041;
    rev:1;
)
```

### TLS SNI Detection

```
# Detect Server Name Indication
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"TLS Connection to Suspicious SNI";
    tls.sni; content:"malware.com"; nocase;
    classtype:trojan-activity;
    sid:1000042;
    rev:1;
)

# Detect missing SNI
alert tls any any -> any 443 (
    msg:"TLS Connection Without SNI";
    flow:to_server,established;
    ssl_state:client_hello;
    tls.sni; content:!".";
    classtype:bad-unknown;
    sid:1000043;
    rev:1;
)
```

### TLS Version Detection

```
# Detect old TLS versions
alert tls any any -> any 443 (
    msg:"Deprecated TLS Version 1.0 Detected";
    tls.version:1.0;
    classtype:policy-violation;
    sid:1000044;
    rev:1;
)
```

## Practical Examples

### Example 1: SQL Injection Detection

#### Basic SQL Injection

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SQL Injection - UNION SELECT";
    flow:established,to_server;
    content:"UNION"; nocase; fast_pattern;
    content:"SELECT"; nocase; distance:0; within:20;
    classtype:web-application-attack;
    reference:url,owasp.org/www-community/attacks/SQL_Injection;
    sid:1000100;
    rev:1;
)
```

#### Advanced SQL Injection

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SQL Injection - Multiple Techniques";
    flow:established,to_server;
    http.uri; pcre:"/(union|select|insert|update|delete|drop|create|alter|exec|script|javascript|eval)[\s\+\/*]+/i";
    classtype:web-application-attack;
    sid:1000101;
    rev:1;
)
```

#### Blind SQL Injection

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Blind SQL Injection - Time Delay";
    flow:established,to_server;
    content:"WAITFOR"; nocase;
    content:"DELAY"; nocase; distance:0; within:20;
    classtype:web-application-attack;
    sid:1000102;
    rev:1;
)

alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Blind SQL Injection - Boolean";
    flow:established,to_server;
    content:"AND"; nocase;
    pcre:"/and\s+[0-9]+=+[0-9]+/i";
    classtype:web-application-attack;
    sid:1000103;
    rev:1;
)
```

#### SQL Injection in POST Data

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SQL Injection in POST Data";
    flow:established,to_server;
    http.method; content:"POST";
    http.request_body;
    content:"'"; fast_pattern;
    pcre:"/'.*(\s+or\s+|\s+and\s+).*[=<>]/i";
    classtype:web-application-attack;
    sid:1000104;
    rev:1;
)
```

### Example 2: Cross-Site Scripting (XSS) Detection

#### Reflected XSS

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"XSS Attempt - Script Tag";
    flow:established,to_server;
    content:"<script"; nocase; fast_pattern;
    pcre:"/<script[^>]*>.*<\/script>/i";
    classtype:web-application-attack;
    sid:1000110;
    rev:1;
)
```

#### XSS Event Handlers

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"XSS Attempt - Event Handler";
    flow:established,to_server;
    pcre:"/(onerror|onload|onclick|onmouseover|onmousemove)[\s]*=[\s]*[\"']?/i";
    classtype:web-application-attack;
    sid:1000111;
    rev:1;
)
```

#### XSS JavaScript Protocol

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"XSS Attempt - JavaScript Protocol";
    flow:established,to_server;
    content:"javascript:"; nocase;
    classtype:web-application-attack;
    sid:1000112;
    rev:1;
)
```

#### XSS in URL

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"XSS in URL Parameter";
    flow:established,to_server;
    http.uri; content:"<"; nocase;
    http.uri; pcre:"/[?&][^=]+=/";
    http.uri; pcre:"/<[^>]*script/i";
    classtype:web-application-attack;
    sid:1000113;
    rev:1;
)
```

#### Stored XSS Detection

```
alert http any any -> $HOME_NET any (
    msg:"Stored XSS - Script in Response";
    flow:established,to_client;
    http.response_body;
    content:"<script"; nocase;
    content:"alert("; nocase; distance:0; within:100;
    classtype:web-application-attack;
    sid:1000114;
    rev:1;
)
```

### Example 3: Port Scanning Detection

#### SYN Scan Detection

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Port Scan - SYN Scan Detected";
    flags:S,12;
    threshold:type threshold, track by_src, count 20, seconds 60;
    classtype:attempted-recon;
    sid:1000120;
    rev:1;
)
```

#### Full Connect Scan

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Port Scan - Multiple Connection Attempts";
    flags:S;
    threshold:type threshold, track by_src, count 30, seconds 60;
    classtype:attempted-recon;
    sid:1000121;
    rev:1;
)
```

#### NULL Scan Detection

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Port Scan - NULL Scan Detected";
    flags:0;
    threshold:type threshold, track by_src, count 10, seconds 60;
    classtype:attempted-recon;
    sid:1000122;
    rev:1;
)
```

#### XMAS Scan Detection

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Port Scan - XMAS Scan Detected";
    flags:FPU,12;
    threshold:type threshold, track by_src, count 10, seconds 60;
    classtype:attempted-recon;
    sid:1000123;
    rev:1;
)
```

#### UDP Scan Detection

```
alert udp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Port Scan - UDP Scan Detected";
    threshold:type threshold, track by_src, count 50, seconds 60;
    classtype:attempted-recon;
    sid:1000124;
    rev:1;
)
```

### Example 4: Malware Callback Detection

#### Generic C2 Beacon

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Possible Malware C2 Beacon - Regular Intervals";
    flow:established,to_server;
    http.method; content:"POST";
    content:"User-Agent|3a 20|"; nocase;
    threshold:type threshold, track by_src, count 10, seconds 600;
    classtype:trojan-activity;
    sid:1000130;
    rev:1;
)
```

#### Suspicious User-Agent

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Malware C2 - Suspicious User-Agent";
    flow:established,to_server;
    http.user_agent; content:"Mozilla/4.0 (compatible|3b| MSIE 6.0|3b|)";
    classtype:trojan-activity;
    sid:1000131;
    rev:1;
)
```

#### Base64 Encoded Payload

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Malware C2 - Base64 Encoded Payload";
    flow:established,to_server;
    http.request_body;
    pcre:"/^[A-Za-z0-9+\/]{100,}={0,2}$/";
    classtype:trojan-activity;
    sid:1000132;
    rev:1;
)
```

#### DNS C2 Channel

```
alert dns $HOME_NET any -> any 53 (
    msg:"Malware C2 - DNS Tunneling Pattern";
    dns.query; pcre:"/^[a-f0-9]{32,}\./i";
    threshold:type threshold, track by_src, count 20, seconds 300;
    classtype:trojan-activity;
    sid:1000133;
    rev:1;
)
```

#### TLS C2 Connection

```
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"Malware C2 - Suspicious TLS SNI";
    tls.sni; pcre:"/^[a-z]{15,}\.(com|net|org)$/i";
    flowbits:set,malware.c2;
    classtype:trojan-activity;
    sid:1000134;
    rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Malware C2 - Follow-up HTTP After TLS";
    flowbits:isset,malware.c2;
    http.method; content:"POST";
    classtype:trojan-activity;
    sid:1000135;
    rev:1;
)
```

#### Cobalt Strike Detection

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Cobalt Strike - Beacon Detected";
    flow:established,to_server;
    content:"MZ"; depth:2;
    content:"This program cannot be run in DOS mode"; distance:0;
    classtype:trojan-activity;
    reference:url,cobaltstrike.com;
    sid:1000136;
    rev:1;
)
```

## Testing Your Rules

### Syntax Testing

```bash
# Test rule syntax
sudo suricata -T -c /etc/suricata/suricata.yaml \
  -S /etc/suricata/rules/local.rules

# Test and show errors
sudo suricata -T -c /etc/suricata/suricata.yaml \
  -S /etc/suricata/rules/local.rules -v
```

### Testing with PCAP

```bash
# Test against PCAP file
sudo suricata -c /etc/suricata/suricata.yaml \
  -r test.pcap \
  -l /tmp/suricata-test/

# Check alerts
cat /tmp/suricata-test/fast.log
```

### Generate Test Traffic

#### Test SQL Injection Rule

```bash
# Using curl
curl "http://testsite.local/test.php?id=1' UNION SELECT * FROM users--"

# Using browser console
fetch("http://testsite.local/test.php?id=1' UNION SELECT 1,2,3--")
```

#### Test XSS Rule

```bash
# Test with curl
curl "http://testsite.local/test.php?search=<script>alert(1)</script>"

# Test event handler
curl "http://testsite.local/test.php?x=<img src=x onerror=alert(1)>"
```

#### Test Port Scan Rule

```bash
# Simulate port scan with nmap
nmap -sS -p 1-100 targethost

# Test with nc
for i in {1..50}; do nc -zv -w1 targethost $i 2>&1 & done
```

#### Test DNS Rule

```bash
# Test DNS query
dig evil.com @dns-server

# Test with nslookup
nslookup suspicious.domain
```

### Create Test PCAP

```bash
# Capture your test traffic
sudo tcpdump -i eth0 -w test.pcap host testsite.local

# Generate traffic
curl "http://testsite.local/vulnerable.php?id=1' OR '1'='1"

# Stop capture (Ctrl+C)

# Test rules against capture
sudo suricata -c /etc/suricata/suricata.yaml -r test.pcap -l /tmp/test/
```

## Best Practices

### 1. Rule Design

```
# ✅ Good: Specific and targeted
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SQL Injection - UNION SELECT in URI";
    flow:established,to_server;
    http.uri; content:"UNION"; nocase; fast_pattern;
    http.uri; content:"SELECT"; nocase; distance:0; within:50;
    classtype:web-application-attack;
    sid:1000001;
    rev:1;
)

# ❌ Bad: Too broad
alert tcp any any -> any any (
    content:"admin";
    sid:1000001;
    rev:1;
)
```

### 2. Performance Optimization

```
# Use fast_pattern on most unique content
content:"very_unique_identifier"; fast_pattern;
content:"common_word";

# Limit search depth
content:"GET"; depth:4;
content:"HTTP/1.1"; offset:4;

# Use within instead of distance alone
content:"user";
content:"password"; distance:0; within:100;
```

### 3. Reduce False Positives

```
# Use flow for established connections
flow:established,to_server;

# Combine multiple indicators
content:"admin";
content:"password";
content:"login";

# Use thresholds
threshold:type threshold, track by_src, count 5, seconds 60;

# Use negation
content:!"legitimate_pattern";
```

### 4. Documentation

```
# Document each rule
# Rule: SQL Injection Detection
# Author: Security Team
# Date: 2024-01-15
# Purpose: Detect UNION-based SQL injection in HTTP URIs
# Testing: curl "http://test/?id=1' UNION SELECT 1,2,3--"
# False Positives: None known
# Last Updated: 2024-01-15
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SQL Injection - UNION SELECT in URI";
    flow:established,to_server;
    http.uri; content:"UNION"; nocase; fast_pattern;
    http.uri; content:"SELECT"; nocase; distance:0; within:50;
    classtype:web-application-attack;
    reference:url,owasp.org/sql-injection;
    sid:1000001;
    rev:1;
)
```

### 5. Version Control

```bash
# Initialize git repository for rules
cd /etc/suricata/rules
sudo git init
sudo git add local.rules
sudo git commit -m "Initial rule set"

# Track changes
sudo git add local.rules
sudo git commit -m "Added XSS detection rules"

# Review history
sudo git log --oneline
```

### 6. Rule Maintenance

```bash
# Regular review schedule
# - Weekly: Review false positives
# - Monthly: Update rules based on new threats
# - Quarterly: Performance review

# Track performance
sudo suricata --engine-analysis
```

### 7. Testing Checklist

- [ ] Syntax validation passes
- [ ] Tested with PCAP
- [ ] No false positives on legitimate traffic
- [ ] Performance impact measured
- [ ] Documentation complete
- [ ] SID doesn't conflict
- [ ] Revision tracking in place

## Complete Example Ruleset

```
# /etc/suricata/rules/local.rules
# Custom Suricata Rules
# Organization: Example Corp
# Maintained by: Security Team
# Last Updated: 2024-01-15

# =====================================================
# SQL Injection Detection
# =====================================================

alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SQL Injection - UNION SELECT";
    flow:established,to_server;
    http.uri; content:"UNION"; nocase; fast_pattern;
    http.uri; content:"SELECT"; nocase; distance:0; within:50;
    classtype:web-application-attack;
    sid:1000001;
    rev:1;
)

alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SQL Injection - OR 1=1";
    flow:established,to_server;
    http.uri; pcre:"/(\s+or\s+|\+or\+)['\"]*\d+['\"]*\s*=\s*['\"]*\d+/i";
    classtype:web-application-attack;
    sid:1000002;
    rev:1;
)

# =====================================================
# Cross-Site Scripting (XSS)
# =====================================================

alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"XSS Attempt - Script Tag";
    flow:established,to_server;
    content:"<script"; nocase; fast_pattern;
    pcre:"/<script[^>]*>/i";
    classtype:web-application-attack;
    sid:1000010;
    rev:1;
)

alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"XSS Attempt - Event Handler";
    flow:established,to_server;
    pcre:"/(onerror|onload|onclick)[\s]*=/i";
    classtype:web-application-attack;
    sid:1000011;
    rev:1;
)

# =====================================================
# Port Scanning
# =====================================================

alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Port Scan - SYN Scan";
    flags:S,12;
    threshold:type threshold, track by_src, count 20, seconds 60;
    classtype:attempted-recon;
    sid:1000020;
    rev:1;
)

# =====================================================
# Malware C2 Detection
# =====================================================

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Malware C2 - Regular Beacon";
    flow:established,to_server;
    http.method; content:"POST";
    threshold:type threshold, track by_src, count 10, seconds 600;
    classtype:trojan-activity;
    sid:1000030;
    rev:1;
)

alert dns $HOME_NET any -> any 53 (
    msg:"Malware C2 - DNS Tunneling";
    dns.query; pcre:"/^[a-f0-9]{32,}\./i";
    threshold:type threshold, track by_src, count 20, seconds 300;
    classtype:trojan-activity;
    sid:1000031;
    rev:1;
)
```

## Next Steps

Now that you can write custom rules:

1. **Analyze Logs**: See [Log Analysis](07-log-analysis.md)
2. **Troubleshoot Issues**: See [Troubleshooting](08-troubleshooting.md)
3. **Optimize Performance**: See [Advanced Topics](09-advanced-topics.md)

---

[← Back: Rule Management](05-rule-management.md) | [Home](../README.md) | [Next: Log Analysis →](07-log-analysis.md)
