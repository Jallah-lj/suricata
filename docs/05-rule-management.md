# Rule Management

This guide covers managing Suricata rules using suricata-update, enabling/disabling rulesets, and maintaining both community and custom rules.

## Table of Contents

- [Introduction to suricata-update](#introduction-to-suricata-update)
- [Initial Setup](#initial-setup)
- [Updating Rules](#updating-rules)
- [Managing Rule Sources](#managing-rule-sources)
- [Enabling and Disabling Rules](#enabling-and-disabling-rules)
- [Managing Local Rules](#managing-local-rules)
- [Rule Sources](#rule-sources)
- [Automation](#automation)
- [Troubleshooting](#troubleshooting)

## Introduction to suricata-update

**suricata-update** is the official tool for managing Suricata rule sources. It:

- Downloads rules from multiple sources
- Merges rules into a single file
- Enables/disables specific rules or entire rulesets
- Handles rule updates automatically
- Manages rule conflicts and duplicates

### Why Use suricata-update?

```bash
# Manual approach (not recommended)
# - Download rules manually
# - Extract archives
# - Copy files
# - Merge rule files
# - Update suricata.yaml
# - Reload Suricata

# With suricata-update (recommended)
sudo suricata-update
sudo systemctl reload suricata
```

## Initial Setup

### Installation

Most installations include suricata-update:

```bash
# Check if installed
which suricata-update

# Install if missing (Ubuntu/Debian)
sudo apt-get install python3-suricata-update

# Install if missing (CentOS/RHEL)
sudo yum install suricata-update

# Install via pip
sudo pip3 install --upgrade suricata-update
```

### First Run

Initialize suricata-update:

```bash
# Run initial update (downloads default ruleset)
sudo suricata-update

# This will:
# 1. Create /var/lib/suricata/rules/ directory
# 2. Download Emerging Threats Open ruleset
# 3. Create suricata.rules file
# 4. Configure rule files
```

**Output:**
```
[*] Checking for directory /var/lib/suricata/rules
[*] Creating directory /var/lib/suricata/rules
[*] Fetching https://rules.emergingthreats.net/open/suricata-7.0.0/emerging.rules.tar.gz
[*] Done
[*] Loading /var/lib/suricata/rules/emerging.rules.tar.gz
[*] Loaded 38247 rules
[*] Disabled 0 rules
[*] Enabled 0 rules
[*] Modified 0 rules
[*] Dropped 0 rules
[*] Writing rules to /var/lib/suricata/rules/suricata.rules: total: 38247; enabled: 38247; added: 38247; removed: 0; modified: 0
[*] Writing /var/lib/suricata/update/update.yaml
[*] Testing Suricata configuration with: suricata -T -S /var/lib/suricata/rules/suricata.rules
[*] Done
```

### Configure Suricata

Update suricata.yaml to use the managed rules:

```bash
# Edit configuration
sudo nano /etc/suricata/suricata.yaml
```

Find the `rule-files:` section and update:

```yaml
# Old (manual rules)
rule-files:
  - suricata.rules
  - local.rules

# New (suricata-update managed)
rule-files:
  - /var/lib/suricata/rules/suricata.rules
```

Test and reload:

```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Reload Suricata
sudo systemctl reload suricata
```

## Updating Rules

### Manual Update

Run updates manually:

```bash
# Update all rule sources
sudo suricata-update

# Update and reload Suricata
sudo suricata-update && sudo systemctl reload suricata

# Update with verbose output
sudo suricata-update -v

# Update specific source
sudo suricata-update --source et/open
```

### Check Current Status

```bash
# List enabled sources
sudo suricata-update list-sources --enabled

# Show update summary
sudo suricata-update update-sources
```

### Force Update

```bash
# Force download even if rules haven't changed
sudo suricata-update --force

# Bypass signature validation
sudo suricata-update --no-check-certificate
```

## Managing Rule Sources

### List Available Sources

```bash
# List all available sources
sudo suricata-update list-sources

# List enabled sources only
sudo suricata-update list-sources --enabled

# List free sources
sudo suricata-update list-sources --free

# List sources with details
sudo suricata-update list-sources | grep -A 5 "et/open"
```

**Sample Output:**
```
Name: et/open
  Vendor: Proofpoint
  Summary: Emerging Threats Open Ruleset
  License: MIT
  URL: https://rules.emergingthreats.net/open/suricata-7.0.0/emerging.rules.tar.gz
  Support URL: https://doc.emergingthreats.net/
```

### Enable Rule Sources

```bash
# Enable default ET Open (usually already enabled)
sudo suricata-update enable-source et/open

# Enable ET Pro (requires subscription)
sudo suricata-update enable-source et/pro

# Enable OISF Traffic ID rules
sudo suricata-update enable-source oisf/trafficid

# Enable Abuse.ch SSL Blacklist
sudo suricata-update enable-source sslbl/ssl-fp-blacklist

# Enable multiple sources at once
sudo suricata-update enable-source et/open
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update enable-source sslbl/ssl-fp-blacklist
```

### Disable Rule Sources

```bash
# Disable a source
sudo suricata-update disable-source et/open

# Remove a source completely
sudo suricata-update remove-source et/pro
```

### Add Custom Source

```bash
# Add URL-based source
sudo suricata-update add-source custom-rules https://example.com/rules.tar.gz

# Add local directory as source
sudo suricata-update add-source local-rules file:///etc/suricata/custom-rules/
```

## Enabling and Disabling Rules

### Disable Individual Rules

Create disable.conf:

```bash
# Create disable configuration
sudo nano /etc/suricata/disable.conf
```

Add rule SIDs to disable:

```
# Disable specific rules (one per line)
2000001
2000002
2000003

# Disable by pattern (regex)
re:.*malware-cnc.*

# Disable rule group
group:emerging-malware.rules

# Comments are allowed
# This rule generates too many false positives
2000123
```

Apply the configuration:

```bash
# Update with disable.conf
sudo suricata-update --disable-conf /etc/suricata/disable.conf

# Verify rules are disabled
sudo suricata-update list-enabled-sources
```

### Enable Specific Rules

Create enable.conf:

```bash
# Create enable configuration
sudo nano /etc/suricata/enable.conf
```

Add rule SIDs to enable:

```
# Enable specific rules
2000001
2000002

# Enable by pattern
re:.*sql-injection.*

# Enable entire group
group:emerging-web-attacks.rules
```

Apply the configuration:

```bash
# Update with enable.conf
sudo suricata-update --enable-conf /etc/suricata/enable.conf
```

### Modify Rules

Create modify.conf to change rule actions:

```bash
# Create modify configuration
sudo nano /etc/suricata/modify.conf
```

Modify rule actions:

```
# Change action from alert to drop
2000001 drop

# Change multiple rules
2000002 drop
2000003 reject

# Change by pattern
re:.*trojan.* drop

# Change entire group
group:emerging-malware.rules drop
```

Apply modifications:

```bash
# Update with modify.conf
sudo suricata-update --modify-conf /etc/suricata/modify.conf
```

### Drop Rules Entirely

Create drop.conf to completely remove rules:

```bash
# Create drop configuration
sudo nano /etc/suricata/drop.conf
```

Drop rules from output:

```
# Drop (don't include) these rules
2000001
2000002

# Drop by pattern
re:.*test.*

# Drop by group
group:emerging-dos.rules
```

Apply drop configuration:

```bash
# Update with drop.conf
sudo suricata-update --drop-conf /etc/suricata/drop.conf
```

## Managing Local Rules

### Create Local Rules

Local rules take precedence over downloaded rules:

```bash
# Create local rules directory
sudo mkdir -p /etc/suricata/rules

# Create local rules file
sudo nano /etc/suricata/rules/local.rules
```

Add your custom rules:

```
# Custom local rules
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Custom SSH Detection"; flow:to_server,established; content:"SSH-2.0"; sid:1000001; rev:1;)

alert http any any -> any any (msg:"Custom Admin Access"; http.uri; content:"/admin"; sid:1000002; rev:1;)
```

### Include Local Rules

Configure suricata-update to include local rules:

```bash
# Edit update configuration
sudo nano /var/lib/suricata/update/update.yaml
```

Add local rules:

```yaml
sources:
  - et/open
  
local:
  - /etc/suricata/rules/local.rules
```

Or use command line:

```bash
# Update with local rules
sudo suricata-update --local /etc/suricata/rules/local.rules

# Multiple local rule files
sudo suricata-update \
  --local /etc/suricata/rules/local.rules \
  --local /etc/suricata/rules/custom.rules
```

### Organize Local Rules

Create organized structure:

```bash
# Create rule categories
sudo mkdir -p /etc/suricata/rules/{web,malware,network,custom}

# Create category files
sudo touch /etc/suricata/rules/web/sql-injection.rules
sudo touch /etc/suricata/rules/web/xss.rules
sudo touch /etc/suricata/rules/malware/c2.rules
sudo touch /etc/suricata/rules/network/scanning.rules
```

Include all local rules:

```bash
# Update with all local rules
sudo suricata-update \
  --local /etc/suricata/rules/web/*.rules \
  --local /etc/suricata/rules/malware/*.rules \
  --local /etc/suricata/rules/network/*.rules
```

## Rule Sources

### Free Rule Sources

#### 1. Emerging Threats Open (ET Open)

**Default and most comprehensive free ruleset**

```bash
# Enable ET Open
sudo suricata-update enable-source et/open

# Update
sudo suricata-update
```

**Coverage:**
- Web attacks (SQL injection, XSS, RCE)
- Malware and C2 communications
- Exploits and CVEs
- Network attacks (scanning, DoS)
- Policy violations

#### 2. OISF Traffic ID

**Protocol detection and traffic identification**

```bash
# Enable OISF Traffic ID
sudo suricata-update enable-source oisf/trafficid

# Update
sudo suricata-update
```

**Coverage:**
- Application protocol detection
- Service identification
- Traffic classification

#### 3. Abuse.ch SSL Blacklist

**SSL/TLS certificate blacklist**

```bash
# Enable SSL Blacklist
sudo suricata-update enable-source sslbl/ssl-fp-blacklist

# Update
sudo suricata-update
```

**Coverage:**
- Known malicious SSL certificates
- C2 TLS fingerprints
- Phishing SSL certificates

#### 4. Abuse.ch URLhaus

**Malware URL blacklist**

```bash
# Enable URLhaus
sudo suricata-update enable-source abuse.ch/urlhaus

# Update
sudo suricata-update
```

**Coverage:**
- Malware distribution URLs
- Phishing URLs
- C2 server URLs

### Commercial Rule Sources

#### Emerging Threats Pro (ET Pro)

**Professional ruleset with faster updates**

```bash
# Register at https://www.proofpoint.com/us/threat-insight/et-pro-ruleset
# Get your license key

# Enable with key
sudo suricata-update enable-source et/pro <YOUR-LICENSE-KEY>

# Update
sudo suricata-update
```

**Benefits:**
- Faster updates (ahead of ET Open)
- Additional rules
- Better coverage
- Commercial support

#### Proofpoint ET Intelligence

```bash
# Requires subscription
sudo suricata-update enable-source etnetera/aggressive

# Update
sudo suricata-update
```

### Community Sources

Check available community sources:

```bash
# List all sources
sudo suricata-update list-sources --all

# Search for specific source
sudo suricata-update list-sources | grep -i "malware"
```

## Automation

### Setup Automatic Updates

#### Using Cron

```bash
# Edit crontab
sudo crontab -e

# Add update schedule
# Update rules daily at 2 AM
0 2 * * * /usr/bin/suricata-update && /usr/bin/systemctl reload suricata

# Update every 6 hours
0 */6 * * * /usr/bin/suricata-update && /usr/bin/systemctl reload suricata

# Update weekly on Sunday at 3 AM
0 3 * * 0 /usr/bin/suricata-update && /usr/bin/systemctl reload suricata
```

#### Using Systemd Timer

Create service file:

```bash
# Create service
sudo nano /etc/systemd/system/suricata-update.service
```

```ini
[Unit]
Description=Suricata Update Rules
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/suricata-update
ExecStartPost=/usr/bin/systemctl reload suricata
```

Create timer:

```bash
# Create timer
sudo nano /etc/systemd/system/suricata-update.timer
```

```ini
[Unit]
Description=Suricata Update Timer
Requires=suricata-update.service

[Timer]
OnCalendar=daily
OnBootSec=10min
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable timer
sudo systemctl enable suricata-update.timer

# Start timer
sudo systemctl start suricata-update.timer

# Check timer status
sudo systemctl status suricata-update.timer

# List timers
sudo systemctl list-timers suricata-update.timer
```

### Update Script with Logging

Create update script:

```bash
# Create script
sudo nano /usr/local/bin/update-suricata-rules.sh
```

```bash
#!/bin/bash

# Suricata Rule Update Script
LOG_FILE="/var/log/suricata/rule-update.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] Starting rule update..." | tee -a "$LOG_FILE"

# Update rules
if /usr/bin/suricata-update >> "$LOG_FILE" 2>&1; then
    echo "[$DATE] Rules updated successfully" | tee -a "$LOG_FILE"
    
    # Test configuration
    if /usr/bin/suricata -T -c /etc/suricata/suricata.yaml >> "$LOG_FILE" 2>&1; then
        echo "[$DATE] Configuration valid" | tee -a "$LOG_FILE"
        
        # Reload Suricata
        if /usr/bin/systemctl reload suricata; then
            echo "[$DATE] Suricata reloaded successfully" | tee -a "$LOG_FILE"
        else
            echo "[$DATE] ERROR: Failed to reload Suricata" | tee -a "$LOG_FILE"
            exit 1
        fi
    else
        echo "[$DATE] ERROR: Configuration test failed" | tee -a "$LOG_FILE"
        exit 1
    fi
else
    echo "[$DATE] ERROR: Rule update failed" | tee -a "$LOG_FILE"
    exit 1
fi

echo "[$DATE] Update complete" | tee -a "$LOG_FILE"
```

Make executable:

```bash
# Make executable
sudo chmod +x /usr/local/bin/update-suricata-rules.sh

# Test script
sudo /usr/local/bin/update-suricata-rules.sh

# Add to cron
sudo crontab -e
# Add: 0 2 * * * /usr/local/bin/update-suricata-rules.sh
```

## Troubleshooting

### Common Issues

#### Issue 1: Update Fails

```bash
# Check network connectivity
curl -I https://rules.emergingthreats.net

# Update with verbose output
sudo suricata-update -v

# Check logs
sudo journalctl -u suricata-update

# Force update
sudo suricata-update --force
```

#### Issue 2: Configuration Not Found

```bash
# Check configuration path
ls -la /var/lib/suricata/update/update.yaml

# Reinitialize
sudo suricata-update --force

# Specify config manually
sudo suricata-update --config /etc/suricata/update.yaml
```

#### Issue 3: Rules Not Loading

```bash
# Verify rule file exists
ls -la /var/lib/suricata/rules/suricata.rules

# Check suricata.yaml configuration
sudo grep -A 5 "rule-files:" /etc/suricata/suricata.yaml

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Check permissions
sudo chown -R suricata:suricata /var/lib/suricata/rules/
```

#### Issue 4: Too Many Rules

```bash
# Check rule count
wc -l /var/lib/suricata/rules/suricata.rules

# Disable unnecessary categories
sudo nano /etc/suricata/disable.conf
# Add: group:emerging-dos.rules
# Add: group:emerging-games.rules

# Update with disable config
sudo suricata-update --disable-conf /etc/suricata/disable.conf

# Verify count
wc -l /var/lib/suricata/rules/suricata.rules
```

#### Issue 5: License Key Issues

```bash
# Remove old source
sudo suricata-update remove-source et/pro

# Re-add with new key
sudo suricata-update enable-source et/pro <NEW-KEY>

# Update
sudo suricata-update
```

### Debug Mode

```bash
# Run with maximum verbosity
sudo suricata-update -vv

# Check what would change without applying
sudo suricata-update --dry-run

# Show all disabled rules
sudo suricata-update --dump-sample-configs
```

### Reset Configuration

```bash
# Backup current config
sudo cp -r /var/lib/suricata/update /var/lib/suricata/update.backup

# Remove configuration
sudo rm -rf /var/lib/suricata/update/

# Reinitialize
sudo suricata-update

# Restore custom configs
sudo cp /var/lib/suricata/update.backup/*.conf /etc/suricata/
```

## Best Practices

### 1. Regular Updates

- Update rules at least daily
- Use automation (cron/systemd)
- Monitor update logs
- Test after updates

### 2. Rule Tuning

- Start with default rules
- Monitor false positives
- Disable noisy rules gradually
- Document all changes

### 3. Local Rules

- Keep local rules separate
- Use SID range 1000000+
- Version control local rules
- Document each rule

### 4. Testing

```bash
# Always test before reload
sudo suricata -T -c /etc/suricata/suricata.yaml

# Test with PCAP
sudo suricata -c /etc/suricata/suricata.yaml -r test.pcap

# Verify rule loading
sudo suricata --dump-config | grep rules
```

### 5. Backup

```bash
# Backup rules before update
sudo cp /var/lib/suricata/rules/suricata.rules \
  /var/lib/suricata/rules/suricata.rules.backup

# Backup configuration
sudo cp -r /var/lib/suricata/update \
  /var/lib/suricata/update.backup
```

## Example Workflow

Complete workflow for rule management:

```bash
# 1. Check current status
sudo suricata-update list-sources --enabled

# 2. Enable additional sources
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update enable-source sslbl/ssl-fp-blacklist

# 3. Update rules
sudo suricata-update

# 4. Create disable.conf for false positives
echo "2000123" | sudo tee -a /etc/suricata/disable.conf
echo "2000456" | sudo tee -a /etc/suricata/disable.conf

# 5. Add local rules
sudo nano /etc/suricata/rules/local.rules

# 6. Update with configurations
sudo suricata-update \
  --disable-conf /etc/suricata/disable.conf \
  --local /etc/suricata/rules/local.rules

# 7. Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# 8. Reload Suricata
sudo systemctl reload suricata

# 9. Verify
sudo tail -f /var/log/suricata/suricata.log
```

## Next Steps

Now that you can manage rules:

1. **Write Custom Rules**: See [Custom Rules Guide](06-custom-rules.md)
2. **Analyze Logs**: See [Log Analysis](07-log-analysis.md)
3. **Optimize Performance**: See [Advanced Topics](09-advanced-topics.md)

---

[← Back: Rules Overview](04-rules-overview.md) | [Home](../README.md) | [Next: Custom Rules →](06-custom-rules.md)
