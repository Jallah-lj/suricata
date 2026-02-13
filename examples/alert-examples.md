# Suricata Alert Examples and Investigation Guide

This guide provides real-world alert scenarios, interpretation guidance, and recommended actions for common Suricata alerts.

## Table of Contents

- [Understanding Alert Priority Levels](#understanding-alert-priority-levels)
- [Common Alert Scenarios](#common-alert-scenarios)
- [Investigation Workflow](#investigation-workflow)
- [False Positives](#false-positives)
- [Common Alerts Reference](#common-alerts-reference)

## Understanding Alert Priority Levels

| Priority | Severity | Description | Response Time |
|----------|----------|-------------|---------------|
| 1 | High | Critical security threat requiring immediate action | Immediate |
| 2 | Medium | Suspicious activity that should be investigated | Within 24 hours |
| 3 | Low | Informational or policy violations | As time permits |

## Common Alert Scenarios

### Scenario 1: SQL Injection Attack

**Alert:**
```
ET WEB_SPECIFIC_APPS SQL Injection Attempt
Classification: Web Application Attack
Priority: 1
```

**What it means:**
An attacker is attempting to inject SQL commands into your web application to manipulate or extract database information.

**Investigation Steps:**
1. Check the `eve.json` for the complete HTTP request details
2. Look for patterns like `' OR '1'='1`, `UNION SELECT`, or `DROP TABLE`
3. Identify the targeted web application and URI
4. Review application logs for successful authentication or data access
5. Check if the attack was successful (HTTP 200 response with data)

**Recommended Actions:**
- **Immediate:** Block the source IP at the firewall if multiple attempts detected
- **Short-term:** Review and patch the vulnerable web application
- **Long-term:** Implement parameterized queries and input validation
- **Monitoring:** Watch for similar patterns from other IPs (coordinated attack)

**Example from logs:**
```json
{
  "alert": {
    "signature": "ET WEB_SPECIFIC_APPS SQL Injection Attempt"
  },
  "http": {
    "url": "/login.php?user=admin' OR '1'='1",
    "http_user_agent": "sqlmap/1.0"
  }
}
```

---

### Scenario 2: Port Scanning Activity

**Alert:**
```
ET SCAN Potential SSH Scan
Classification: Attempted Information Leak
Priority: 2
```

**What it means:**
A system is scanning your network to identify open ports and services, typically reconnaissance before an attack.

**Investigation Steps:**
1. Count the number of unique destination IPs/ports from the same source
2. Check if multiple ports are being scanned (22, 23, 80, 443, 445, etc.)
3. Look at the time pattern - rapid sequential attempts indicate automated scanning
4. Determine if source IP is internal (compromised host) or external
5. Check if any scanned services responded or allowed connections

**Recommended Actions:**
- **Internal Source:** Isolate the host immediately, scan for malware
- **External Source:** Block at perimeter firewall, add to threat intelligence
- **All Cases:** Review firewall rules to minimize exposed services
- **Follow-up:** Monitor for exploitation attempts on discovered services

**Pattern Recognition:**
```
10:27:30 -> 10.0.0.0:22
10:27:31 -> 10.0.0.1:22
10:27:32 -> 10.0.0.2:22
10:27:33 -> 10.0.0.3:22
```
*Sequential IP scanning in rapid succession*

---

### Scenario 3: Malware Command and Control (C2)

**Alert:**
```
ET MALWARE Win32/Emotet CnC Activity
Classification: A Network Trojan was detected
Priority: 1
```

**What it means:**
A compromised host is communicating with a malware command and control server, indicating active infection.

**Investigation Steps:**
1. Identify the infected internal host (source IP)
2. Check DNS logs for the C2 domain resolution
3. Review TLS certificate information (often self-signed or suspicious)
4. Look for data exfiltration (large outbound data transfers)
5. Check file system for recently created/modified executables
6. Review email logs if Emotet (often delivered via phishing)

**Recommended Actions:**
- **CRITICAL:** Immediately isolate the infected host from network
- **Forensics:** Take memory dump and disk image before cleanup
- **Remediation:** Wipe and rebuild the system (malware may have persistence)
- **Investigation:** Identify patient zero and infection vector
- **Prevention:** Block C2 domain/IP across all security controls
- **Response:** Force password resets for any credentials on infected system

**Warning Signs:**
- Periodic beaconing (connections every X minutes)
- Encrypted traffic to suspicious IPs
- Unusual outbound connections on non-standard ports

---

### Scenario 4: Cross-Site Scripting (XSS) Attack

**Alert:**
```
ET WEB_SPECIFIC_APPS XSS Attempt
Classification: Web Application Attack
Priority: 2
```

**What it means:**
Attacker is attempting to inject malicious JavaScript into your web application to steal user sessions or data.

**Investigation Steps:**
1. Examine the URL/POST parameters for script tags
2. Check if input is reflected in response (reflected XSS)
3. Test if script is stored in database (stored XSS)
4. Identify vulnerable parameter and application component
5. Check if Web Application Firewall (WAF) blocked the attempt

**Recommended Actions:**
- **Immediate:** If successful, identify affected users and force re-authentication
- **Development:** Implement output encoding and Content Security Policy (CSP)
- **Testing:** Scan application with security tools (OWASP ZAP, Burp Suite)
- **Training:** Educate developers on secure coding practices

**Common XSS Patterns:**
```
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
javascript:alert('XSS')
<iframe src="javascript:alert('XSS')">
```

---

### Scenario 5: Cryptocurrency Mining

**Alert:**
```
ET POLICY Cryptocurrency Miner Checkin
Classification: Potentially Bad Traffic
Priority: 2
```

**What it means:**
A system is connecting to a cryptocurrency mining pool, using company resources for unauthorized mining.

**Investigation Steps:**
1. Identify the internal host performing mining
2. Check if mining software is installed or browser-based (cryptojacking)
3. Review CPU usage patterns (mining causes sustained high usage)
4. Examine web browsing history for suspicious sites
5. Check scheduled tasks or startup programs

**Recommended Actions:**
- **Investigation:** Determine if authorized (some companies allow it) or malicious
- **If unauthorized:** Remove mining software, block mining pool domains
- **Detection:** Monitor for high CPU usage and network connections to mining pools
- **Prevention:** Deploy browser extensions that block mining scripts
- **Policy:** Establish clear acceptable use policy

**Mining Indicators:**
- User-Agent: `xmrig`, `ccminer`, `ethminer`
- Connections to ports: 3333, 4444, 8333, 45560
- Domain patterns: `*-pool.*`, `*.crypto.*`, `*.mining.*`

---

### Scenario 6: Suspicious File Download

**Alert:**
```
ET POLICY PE EXE or DLL Windows file download HTTP
Classification: Potential Corporate Privacy Violation
Priority: 1
```

**What it means:**
A Windows executable file was downloaded over HTTP, which could be malware or legitimate software.

**Investigation Steps:**
1. Identify the source URL and hosting domain
2. Calculate and lookup file hash in threat intelligence (VirusTotal)
3. Check if domain is known for malware distribution
4. Review user's recent web browsing activity
5. Scan the downloaded file with antivirus

**Recommended Actions:**
- **Immediate:** Quarantine the file if hash is unknown
- **Analysis:** Submit to sandbox environment (any.run, Joe Sandbox)
- **If malicious:** Block domain, scan system for IOCs, review other downloads
- **If legitimate:** Whitelist known good domains/hashes to reduce noise
- **Policy:** Block EXE downloads over HTTP, require HTTPS with valid certificates

---

### Scenario 7: TOR Usage

**Alert:**
```
ET INFO TOR Client SSL Certificate
Classification: Potentially Bad Traffic
Priority: 2
```

**What it means:**
A user is accessing the TOR network, which provides anonymity but can be used to bypass security controls.

**Investigation Steps:**
1. Identify the user/system accessing TOR
2. Determine if access is authorized (security research, privacy testing)
3. Check for correlation with other suspicious activities
4. Review data exfiltration indicators

**Recommended Actions:**
- **Policy Decision:** Determine if TOR usage is permitted in your environment
- **If prohibited:** Block TOR exit nodes, use TOR bridge detection
- **If allowed:** Require approval and logging
- **Monitor:** Watch for data transfer volumes that indicate exfiltration

---

## Investigation Workflow

### Step 1: Alert Triage
1. Review alert priority and classification
2. Check if alert is a known false positive
3. Determine if part of a larger attack campaign
4. Assess potential impact

### Step 2: Data Collection
Gather information from multiple sources:
- **Suricata Logs:** eve.json (detailed), fast.log (summary)
- **Firewall Logs:** Connection attempts, blocks
- **DNS Logs:** Domain resolutions
- **Proxy Logs:** Web traffic details
- **Endpoint Logs:** Process execution, file modifications
- **SIEM:** Correlated events and patterns

### Step 3: Analysis
1. Timeline reconstruction
2. Identify attack vector
3. Determine scope (single host or multiple)
4. Assess if attack was successful
5. Identify indicators of compromise (IOCs)

### Step 4: Response
1. Contain the threat (isolate, block, disable)
2. Eradicate the cause (remove malware, patch vulnerability)
3. Recover (restore from backup, rebuild systems)
4. Document findings and actions taken

### Step 5: Post-Incident
1. Update signatures and detection rules
2. Implement preventive measures
3. Conduct lessons learned review
4. Update incident response procedures
5. Provide security awareness training

---

## False Positives

### Common False Positive Scenarios

#### 1. Security Scanning Tools

**Alert:** `ET POLICY Suspicious User-Agent (Nmap Scripting Engine)`

**Cause:** Authorized security scanning by your team

**Solution:**
- Create whitelist for authorized scanner IPs
- Add `suppress` rule for specific networks:
  ```
  suppress gen_id 1, sig_id 2022050, track by_src, ip 192.168.100.0/24
  ```

#### 2. Legitimate Software Updates

**Alert:** `ET POLICY PE EXE or DLL Windows file download HTTP`

**Cause:** Legitimate software downloading updates

**Solution:**
- Whitelist known update domains (Microsoft, Adobe, etc.)
- Create pass rules for trusted sources:
  ```
  pass http any any -> any any (msg:"Allowed software updates"; content:"download.microsoft.com"; sid:9000001;)
  ```

#### 3. Corporate VPN/Proxy

**Alert:** `ET INFO TOR Client SSL Certificate`

**Cause:** VPN or proxy using similar certificate patterns

**Solution:**
- Document known VPN endpoints
- Suppress alerts for corporate VPN servers
- Use more specific signatures

#### 4. Development/Testing

**Alert:** `ET WEB_SPECIFIC_APPS SQL Injection Attempt`

**Cause:** Security testing in dev/test environment

**Solution:**
- Segment dev/test networks
- Apply different rule sets per network
- Document testing schedules and suppress during testing windows

### Handling False Positives

1. **Verify:** Confirm it's actually a false positive through investigation
2. **Document:** Record the reason and evidence
3. **Tune:** Create suppress rules or adjust thresholds
4. **Review:** Periodically review suppression rules for validity
5. **Balance:** Don't over-suppress - err on side of detection

**Example suppress.conf:**
```
# Authorized security scanners
suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.100.50

# Known software update servers
suppress gen_id 1, sig_id 2002910, track by_dst, ip 13.107.4.50

# Development environment
suppress gen_id 1, sig_id 2013028, track by_dst, ip 192.168.200.0/24
```

---

## Common Alerts Reference

| Signature | Category | Priority | Common Cause | Action |
|-----------|----------|----------|--------------|--------|
| SQL Injection Attempt | Web Attack | 1 | Application vulnerability | Block IP, patch app |
| XSS Attempt | Web Attack | 2 | Input validation failure | Sanitize inputs, CSP |
| SSH Scan | Scan | 2 | Network reconnaissance | Block scanner, review exposure |
| Malware C2 | Trojan | 1 | Infected endpoint | Isolate host, incident response |
| TOR Usage | Policy | 2 | Anonymity network | Check policy, investigate purpose |
| EXE Download | Policy | 1 | Software download | Verify legitimacy, scan file |
| DNS .top Query | Policy | 2 | Suspicious TLD | Block domain, check host |
| Crypto Miner | Policy | 2 | Unauthorized mining | Remove software, block pool |
| ETERNALBLUE | Exploit | 1 | SMB vulnerability | Patch immediately, check breach |
| Nmap User-Agent | Policy | 2 | Network scanning | Verify authorization |

---

## Quick Response Guide

### Priority 1 - Immediate Response (within minutes)

1. **Isolate** affected systems from network
2. **Block** attacker IPs at firewall
3. **Alert** security team and management
4. **Preserve** evidence (logs, memory dumps)
5. **Begin** incident response procedures

### Priority 2 - Urgent Response (within hours)

1. **Investigate** full scope of activity
2. **Identify** root cause and vulnerabilities
3. **Implement** temporary mitigations
4. **Monitor** for continued activity
5. **Plan** remediation actions

### Priority 3 - Standard Response (within days)

1. **Review** alert for accuracy
2. **Document** findings
3. **Update** detection rules if needed
4. **Schedule** remediation during maintenance window
5. **Track** for pattern analysis

---

## Additional Resources

- **Suricata Official Documentation:** https://suricata.readthedocs.io/
- **Emerging Threats Rules:** https://rules.emergingthreats.net/
- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **SANS Internet Storm Center:** https://isc.sans.edu/

---

## Log Analysis Tips

### Analyzing eve.json

**Find all alerts from specific IP:**
```bash
jq 'select(.event_type=="alert" and .src_ip=="192.168.1.105")' eve.json
```

**Count alerts by signature:**
```bash
jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -rn
```

**Extract all C2 communications:**
```bash
jq 'select(.alert.category=="A Network Trojan was detected")' eve.json
```

**Find high-priority alerts:**
```bash
jq 'select(.event_type=="alert" and .alert.severity<=1)' eve.json
```

### Analyzing fast.log

**Count alerts by classification:**
```bash
grep -oP '\[Classification: \K[^\]]+' fast.log | sort | uniq -c | sort -rn
```

**Find all Priority 1 alerts:**
```bash
grep "Priority: 1" fast.log
```

**Extract unique source IPs:**
```bash
grep -oP '\{TCP\} \K[\d.]+(?=:)' fast.log | sort -u
```

---

*Last Updated: January 2024*
