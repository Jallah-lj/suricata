# Basic Configuration

This guide covers the essential configuration of Suricata through the `suricata.yaml` file. We'll focus on the most important settings that beginners need to understand and modify.

## Table of Contents

- [Configuration File Location](#configuration-file-location)
- [Understanding suricata.yaml](#understanding-suricatayaml)
- [Key Configuration Sections](#key-configuration-sections)
- [HOME_NET and EXTERNAL_NET](#home_net-and-external_net)
- [Interface Configuration](#interface-configuration)
- [Log Output Configuration](#log-output-configuration)
- [Rule File Paths](#rule-file-paths)
- [Performance Settings](#performance-settings)
- [Testing Your Configuration](#testing-your-configuration)
- [Common Configuration Patterns](#common-configuration-patterns)

## Configuration File Location

The main configuration file is typically located at:

- **Linux**: `/etc/suricata/suricata.yaml`
- **macOS**: `/usr/local/etc/suricata/suricata.yaml`
- **Custom**: Specify with `-c` flag

```bash
# View configuration file
sudo nano /etc/suricata/suricata.yaml

# Or with less for reading
sudo less /etc/suricata/suricata.yaml

# Check where Suricata looks for config
suricata --build-info | grep "conf"
```

## Understanding suricata.yaml

The `suricata.yaml` file uses YAML (YAML Ain't Markup Language) format:

### YAML Basics

- **Indentation matters**: Use spaces, NOT tabs
- **Colons**: Used for key-value pairs (`key: value`)
- **Dashes**: Used for lists
- **Comments**: Start with `#`
- **Strings**: Can be quoted or unquoted

```yaml
# This is a comment
key: value
another-key: "quoted value"

# A list
items:
  - item1
  - item2
  - item3

# Nested structure
parent:
  child: value
  another-child:
    grandchild: value
```

### Backup Your Configuration

Always backup before editing:

```bash
# Create a backup
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup

# Or with timestamp
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.$(date +%Y%m%d)
```

## Key Configuration Sections

The configuration file is organized into several main sections:

### 1. Variables Section

Defines network variables used throughout the configuration:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
```

### 2. Packet Capture Section

Configures how Suricata captures packets:

```yaml
# AF_PACKET (Linux)
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# PCAP (Cross-platform)
pcap:
  - interface: eth0

# PCAP file reading
pcap-file:
  checksum-checks: auto
```

### 3. Outputs Section

Controls logging and alert outputs:

```yaml
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
      
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
```

### 4. Logging Section

General logging configuration:

```yaml
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: suricata.log
```

## HOME_NET and EXTERNAL_NET

These are the most important variables to configure correctly.

### What is HOME_NET?

`HOME_NET` defines your internal network(s) that you're protecting. This tells Suricata which traffic is "inbound" vs "outbound".

### Determining Your HOME_NET

**Find your network range:**

```bash
# Check your IP and subnet
ip addr show

# Or
ifconfig

# Example output:
# inet 192.168.1.100/24
# This means HOME_NET should be 192.168.1.0/24
```

### Configuration Examples

**Single Home Network:**
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
```

**Multiple Networks:**
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24,192.168.2.0/24,10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"
```

**Private RFC1918 Networks:**
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
```

**Corporate Network with DMZ:**
```yaml
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    DMZ_NET: "[192.168.100.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
```

**Monitoring All Traffic (Less Common):**
```yaml
vars:
  address-groups:
    HOME_NET: "any"
    EXTERNAL_NET: "any"
```

### EXTERNAL_NET

Usually defined as `!$HOME_NET` (everything not in HOME_NET):

```yaml
EXTERNAL_NET: "!$HOME_NET"
```

Or explicitly defined:
```yaml
EXTERNAL_NET: "any"
```

### Server-Specific Variables

Define specific servers in your network:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    
    # Specific servers
    HTTP_SERVERS: "[192.168.1.10,192.168.1.11]"
    SMTP_SERVERS: "192.168.1.20"
    SQL_SERVERS: "192.168.1.30"
    DNS_SERVERS: "[192.168.1.1,8.8.8.8]"
```

## Interface Configuration

### AF_PACKET Configuration (Linux - Recommended)

High-performance packet capture for Linux:

```yaml
af-packet:
  - interface: eth0
    # Cluster settings for load balancing
    cluster-id: 99
    cluster-type: cluster_flow
    
    # Enable defragmentation
    defrag: yes
    
    # Number of threads (auto = CPU cores)
    threads: auto
    
    # Use mmap for better performance
    use-mmap: yes
    
    # Ring buffer size
    ring-size: 2048
```

### Multiple Interfaces

```yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    threads: 2
    
  - interface: wlan0
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
    threads: 2
```

### PCAP Configuration (Cross-platform)

For systems without AF_PACKET support:

```yaml
pcap:
  - interface: eth0
  - interface: wlan0
```

### Interface Selection at Runtime

You can override configuration interface at runtime:

```bash
# Use interface from config
sudo suricata -c /etc/suricata/suricata.yaml

# Override interface
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Multiple interfaces
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -i wlan0
```

## Log Output Configuration

### EVE JSON Log (Recommended)

EVE (Extensible Event Format) provides structured JSON logging:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular  # regular, unix_dgram, unix_stream
      filename: eve.json
      
      # Enable specific event types
      types:
        - alert:
            # Include packet payload
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            
            # Include packet info
            packet: yes
            
            # Include metadata
            metadata: yes
            
            # Include tagged packets
            tagged-packets: yes
        
        - http:
            extended: yes  # Extended logging
            
        - dns:
            query: yes
            answer: yes
            
        - tls:
            extended: yes
            
        - files:
            force-magic: no
            force-hash: [md5]
            
        - smtp:
            extended: yes
        
        - ssh
        
        - flow
        
        - netflow
```

### Fast Log (Simple Alert Format)

Simple, human-readable alert log:

```yaml
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes  # Append to existing file
```

**Example fast.log output:**
```
12/15/2023-10:30:45.123456 [**] [1:2013028:6] ET POLICY HTTP Request to a *.tk domain [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.100:54321 -> 93.184.216.34:80
```

### Unified2 Output (For Snort Compatibility)

```yaml
outputs:
  - unified2-alert:
      enabled: no  # Usually disabled
      filename: unified2.alert
```

### Stats Log

Statistics about Suricata's performance:

```yaml
outputs:
  - stats:
      enabled: yes
      filename: stats.log
      append: yes
      totals: yes
      threads: yes
```

### Log File Locations

Default locations:

```yaml
# Set global log directory
default-log-dir: /var/log/suricata/

# Or set per-output
outputs:
  - eve-log:
      enabled: yes
      filename: /var/log/suricata/eve.json
```

## Rule File Paths

Configure which rule files to load:

### Default Rules Configuration

```yaml
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
  - local.rules
```

### Custom Rules

```yaml
rule-files:
  - suricata.rules
  - /etc/suricata/rules/emerging-threats.rules
  - /etc/suricata/rules/custom.rules
  - /etc/suricata/rules/local.rules
```

### Rule File Patterns

Use patterns to load multiple files:

```yaml
rule-files:
  - "*.rules"
```

### Classification and Reference Config

```yaml
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
```

## Performance Settings

### Thread Configuration

```yaml
# Number of packets threads process
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "all" ]
        mode: "exclusive"
        prio:
          low: [ 0 ]
          medium: [ "1-2" ]
          high: [ 3 ]
          default: "medium"
```

### Memory Settings

```yaml
# Maximum pending packets
max-pending-packets: 1024

# Memcap for various features
stream:
  memcap: 64mb
  
flow:
  memcap: 128mb
  
defrag:
  memcap: 32mb
```

### Packet Processing

```yaml
# Checksum validation
host-mode: auto  # auto, sniffer-only

# Defragmentation
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  timeout: 60
```

## Testing Your Configuration

### Syntax Validation

```bash
# Test configuration syntax
sudo suricata -T -c /etc/suricata/suricata.yaml

# Verbose test
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Test with specific interface
sudo suricata -T -c /etc/suricata/suricata.yaml -i eth0
```

**Success output:**
```
[...] <Notice> - Configuration provided was successfully loaded. Exiting.
```

**Error output:**
```
[...] <Error> - Unable to load configuration file
```

### Dump Configuration

View active configuration:

```bash
# Dump entire config
sudo suricata --dump-config

# Dump specific section
sudo suricata --dump-config | grep "HOME_NET"

# List all configured rules
sudo suricata -c /etc/suricata/suricata.yaml --dump-config | grep "rule-files"
```

### Check Rules Loading

```bash
# Show rule loading
sudo suricata -c /etc/suricata/suricata.yaml -v --init-errors-fatal
```

## Common Configuration Patterns

### Pattern 1: Home User

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth0
    threads: 2

outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert
        - http
        - dns
  - fast:
      enabled: yes
      filename: fast.log

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
```

### Pattern 2: Small Business

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "[192.168.1.10,192.168.1.11]"
    SMTP_SERVERS: "192.168.1.20"

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    threads: 4

outputs:
  - eve-log:
      enabled: yes
      types:
        - alert
        - http
        - dns
        - tls
        - smtp
  - fast:
      enabled: yes

rule-files:
  - suricata.rules
  - emerging-threats.rules
  - custom-business-rules.rules
```

### Pattern 3: Development/Testing

```yaml
vars:
  address-groups:
    HOME_NET: "any"
    EXTERNAL_NET: "any"

pcap-file:
  checksum-checks: no

outputs:
  - eve-log:
      enabled: yes
      types:
        - alert
        - http
        - dns
        - tls
        - ssh
        - flow
  - fast:
      enabled: yes

logging:
  default-log-level: debug  # More verbose

rule-files:
  - test-rules.rules
```

## Minimal Working Configuration

Here's a minimal configuration to get started:

```yaml
%YAML 1.1
---

# Network variables
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

# Interface
af-packet:
  - interface: eth0

# Outputs
outputs:
  - fast:
      enabled: yes
  - eve-log:
      enabled: yes
      types:
        - alert

# Rules
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
```

## Troubleshooting Configuration Issues

### YAML Syntax Errors

```bash
# Common issues:
# - Tabs instead of spaces
# - Missing colons
# - Incorrect indentation
# - Unquoted special characters

# Use yamllint to check
sudo apt-get install yamllint
yamllint /etc/suricata/suricata.yaml
```

### Configuration Not Loading

```bash
# Check file permissions
ls -l /etc/suricata/suricata.yaml

# Should be readable
sudo chmod 644 /etc/suricata/suricata.yaml

# Test with verbose output
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

### Rules Not Loading

```bash
# Check rule file path
ls -l /var/lib/suricata/rules/

# Verify path in config
grep "default-rule-path" /etc/suricata/suricata.yaml

# Update rules
sudo suricata-update
```

## Best Practices

1. **Always backup** before editing configuration
2. **Test after changes** with `suricata -T`
3. **Use comments** to document your changes
4. **Start simple** and add complexity gradually
5. **Monitor logs** after configuration changes
6. **Use variables** for reusable values
7. **Keep configuration** in version control (without secrets)
8. **Document** your specific network setup

## Next Steps

Now that you understand basic configuration:

1. **Learn Rule Syntax**: See [Rules Overview](04-rules-overview.md)
2. **Manage Rules**: See [Rule Management](05-rule-management.md)
3. **Analyze Logs**: See [Log Analysis](07-log-analysis.md)
4. **Troubleshoot**: See [Troubleshooting Guide](08-troubleshooting.md)

---

[← Back: Network Interfaces](02-network-interfaces.md) | [Home](../README.md) | [Next: Rules Overview →](04-rules-overview.md)
