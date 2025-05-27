---
title: "Set 3: Configure Suricata Network Monitoring"
description: Network intrusion detection and threat analysis setup
layout: default
nav_order: 4
---

# 🌐 DVWA Set 3: Configure Suricata Network Monitoring

## 🎯 Objective
Configure Suricata IDS to monitor network traffic to DVWA applications and detect network-level threats and attacks.

---

## 👥 Role Requirements
- **AM Security (amsec)** or **PM Security (pmsec)** access required
- Instructor assistance needed for Suricata configuration (sudo required)

---

## 📋 Configuration Steps

### Step 1: Verify Suricata Installation

```bash
# Check Suricata service status
sudo systemctl status suricata

# Verify Suricata version
suricata --version

# Check default configuration
sudo ls -la /etc/suricata/
```

**💡 Suricata Overview:**
- Network Intrusion Detection System (IDS)
- Monitors network packets in real-time
- Detects threats using signature rules
- Logs events in JSON format

**💡 Installation Check:**
- Should be pre-installed on security servers
- Configuration files in `/etc/suricata/`
- Rule files typically in `/var/lib/suricata/rules/`

### Step 2: Check Network Interface Configuration

```bash
# List available network interfaces
ip addr show

# Check current Suricata interface config
sudo grep -E "interface:|af-packet" /etc/suricata/suricata.yaml

# Verify network traffic to DVWA ports
sudo netstat -tlnp | grep -E "8080|8081"
```

**💡 Network Monitoring Setup:**
- Suricata monitors specific network interfaces
- Must capture traffic to DVWA ports (8080/8081)
- AF_PACKET mode provides high-performance capture

**💡 Interface Selection:**
- Usually the primary network interface (eth0, ens160, etc.)
- Should have traffic flowing to DVWA applications
- May need promiscuous mode for full packet capture

### Step 3: Configure Team-Specific Logging

**Ask instructor to create team log directories:**

**🔵 For AM Team:**
```bash
sudo mkdir -p /srv/logs/am/suricata
sudo chown suricata:amsec /srv/logs/am/suricata
sudo chmod 2770 /srv/logs/am/suricata
```

**🟣 For PM Team:**
```bash
sudo mkdir -p /srv/logs/pm/suricata  
sudo chown suricata:pmsec /srv/logs/pm/suricata
sudo chmod 2770 /srv/logs/pm/suricata
```

**💡 Team Isolation:**
- Separate log directories for each team
- Proper ownership for Suricata process
- Security team read access maintained

**💡 Permission Structure:**
- suricata user can write logs
- Team security roles can read logs
- Sticky bit ensures consistent ownership

> ⚠️ **Requires sudo - ask instructor**

### Step 4: Request Suricata Configuration Update

**Ask instructor to configure output logging:**

```yaml
# Add to /etc/suricata/suricata.yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /srv/logs/am/suricata/eve.json
      community-id: true
      types:
        - alert
        - http
        - dns
        - flow
        
  - eve-log:
      enabled: yes  
      filetype: regular
      filename: /srv/logs/pm/suricata/eve.json
      community-id: true
      types:
        - alert
        - http
        - dns
        - flow
```

**💡 EVE JSON Logging:**
- Structured JSON output format
- Contains detailed network event data
- Includes HTTP requests, DNS queries, alerts
- Community-ID for event correlation

**💡 Event Types:**
- alert: IDS rule matches
- http: HTTP request/response details
- dns: DNS query information
- flow: Network connection metadata

> ⚠️ **Requires sudo access to modify configuration**

### Step 5: Configure Network Monitoring Rules

**Ask instructor to enable web application rules:**

```bash
# Update rule management
sudo suricata-update

# Enable specific rule categories
sudo suricata-update enable-source ptresearch/attackdetection
sudo suricata-update enable-source sslbl/ssl-fp-blacklist

# Add custom DVWA detection rules
sudo nano /etc/suricata/rules/dvwa.rules
```

**Custom DVWA Rules:**
```bash
# SQL Injection Detection
alert http any any -> any any (msg:"DVWA SQL Injection Attempt"; content:"union"; http_uri; sid:1000001;)

# XSS Detection  
alert http any any -> any any (msg:"DVWA XSS Attempt"; content:"<script"; http_uri; sid:1000002;)

# Login Brute Force
alert http any any -> any any (msg:"DVWA Multiple Login Attempts"; content:"login.php"; http_uri; threshold:type both,track by_src,count 5,seconds 60; sid:1000003;)
```

**💡 Rule Management:**
- suricata-update downloads latest rules
- Additional sources provide specialized detection
- Custom rules target DVWA-specific threats

**💡 Custom Rule Components:**
- action: alert, pass, drop, reject
- protocol: http, tcp, udp, icmp
- source/dest: IP addresses and ports
- rule options: detection patterns and metadata

**💡 DVWA-Specific Detection:**
- SQL injection patterns in URIs
- XSS attempt identification
- Brute force login detection

### Step 6: Start and Test Suricata

**Ask instructor to restart Suricata:**
```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Restart service
sudo systemctl restart suricata

# Verify status
sudo systemctl status suricata

# Check log generation
sudo tail -f /srv/logs/am/suricata/eve.json
```

**💡 Configuration Testing:**
- `-T` flag tests configuration without running
- Identifies syntax errors before start
- Prevents service failures

**💡 Service Management:**
- Restart applies new configuration
- Status should show "active (running)"
- Logs begin immediately upon traffic

**💡 Initial Log Verification:**
- EVE logs should start generating
- JSON format events appear
- HTTP events visible for web traffic

### Step 7: Generate Test Traffic and Verify Detection

```bash
# Generate normal HTTP traffic
curl -s http://192.168.0.169:8080/login.php

# Test SQL injection detection
curl "http://192.168.0.169:8080/vulnerabilities/sqli/?id=1%27%20union%20select%201,2--&Submit=Submit"

# Test XSS detection  
curl "http://192.168.0.169:8080/vulnerabilities/xss_r/?name=<script>alert('test')</script>"

# Monitor live events
tail -f /srv/logs/am/suricata/eve.json | grep -E "alert|http"
```

**💡 Traffic Generation:**
- Normal requests establish baseline
- Attack payloads test detection rules
- URL encoding simulates real attacks

**💡 Live Monitoring:**
- EVE logs show events immediately
- HTTP events for all web requests
- Alerts when rules trigger

**💡 Expected Detections:**
- SQL injection: union/select keywords
- XSS: script tag detection
- Multiple requests: brute force patterns

### Step 8: Analyze Suricata Events

```bash
# Count different event types
jq '.event_type' /srv/logs/am/suricata/eve.json | sort | uniq -c

# View HTTP events
jq 'select(.event_type=="http")' /srv/logs/am/suricata/eve.json

# View alerts only
jq 'select(.event_type=="alert")' /srv/logs/am/suricata/eve.json

# Search for specific attacks
grep -i "union\|script\|injection" /srv/logs/am/suricata/eve.json
```

**💡 Event Analysis:**
- JSON query language (jq) for parsing
- Event types: http, alert, flow, dns
- Pattern matching for threat detection

**💡 Key Event Fields:**
- timestamp: when event occurred
- src_ip/dest_ip: network endpoints
- alert.signature: rule that triggered
- http.url: requested URL path

**💡 Threat Intelligence:**
- Alert severity levels
- Attack classification
- IOC (Indicators of Compromise)

### Step 9: Integrate Suricata with Wazuh

**Ask instructor to add Suricata monitoring to Wazuh:**

```xml
<!-- Add to /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/srv/logs/am/suricata/eve.json</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/srv/logs/pm/suricata/eve.json</location>
</localfile>
```

**Restart Wazuh agent:**
```bash
sudo systemctl restart wazuh-agent
```

**💡 Centralized Monitoring:**
- Wazuh ingests Suricata JSON logs
- Correlates network and application events
- Unified security event timeline

**💡 Multi-Layer Detection:**
- Application layer: Apache logs via Wazuh
- Network layer: packet analysis via Suricata
- Host layer: system logs via Wazuh

**💡 Event Correlation:**
- Same attacks visible in both systems
- Cross-reference for investigation
- Enhanced threat context

### Step 10: Verify Integration in Wazuh Dashboard

1. **Access Wazuh Dashboard:**
   - URL: `https://wazuh-indexer:443`
   - Login: admin/admin

2. **Check Suricata Events:**
   - Menu → "Security Events"
   - Search: `rule.groups:suricata`
   - Filter: `data.event_type:alert`

3. **View Network Events:**
   - Search: `data.event_type:http`
   - Analyze: Source IPs, URLs, timestamps
   - Correlate: with Apache log events

**💡 Unified Dashboard:**
- All security events in one place
- Network and application data combined
- Real-time threat visualization

**💡 Search Capabilities:**
- Filter by event type or source
- Time-based analysis
- Geographic IP mapping
- Threat trend analysis

**💡 Investigation Workflow:**
- Start with alerts
- Drill down to raw events
- Correlate across data sources
- Export for reporting

---

## ✅ Success Criteria

- [ ] Suricata actively monitoring network interfaces
- [ ] EVE JSON logs generating in team directories
- [ ] Custom DVWA detection rules active
- [ ] Test attacks triggering alerts
- [ ] Suricata events appearing in Wazuh Dashboard
- [ ] Network and application event correlation working

---

## 📊 Key Event Analysis Queries

```bash
# Top source IPs
jq -r 'select(.event_type=="http") | .src_ip' /srv/logs/am/suricata/eve.json | sort | uniq -c | sort -nr

# Alert summary by signature
jq -r 'select(.event_type=="alert") | .alert.signature' /srv/logs/am/suricata/eve.json | sort | uniq -c

# HTTP requests to DVWA
jq 'select(.event_type=="http" and (.http.url | contains("dvwa")))' /srv/logs/am/suricata/eve.json

# High-severity alerts
jq 'select(.event_type=="alert" and .alert.severity<=2)' /srv/logs/am/suricata/eve.json
```

---

## 🔍 Suricata Event Types Explained

| Event Type | Purpose | Key Fields |
|------------|---------|------------|
| **alert** | Rule matches/threats detected | signature, severity, category |
| **http** | HTTP request/response details | url, method, status, user_agent |
| **flow** | Network connection metadata | src_ip, dest_ip, protocol, bytes |
| **dns** | DNS query information | query, answer, query_type |
| **tls** | SSL/TLS connection details | subject, issuer, fingerprint |

---

## ⚠️ Common Issues & Solutions

| Problem | Solution |
|---------|----------|
| No EVE logs generating | Check interface configuration and traffic flow |
| Suricata service fails to start | Validate YAML syntax in configuration |
| No alerts triggering | Verify custom rules syntax and update rules |
| High CPU usage | Tune performance settings or reduce rule scope |
| Missing events in Wazuh | Check file permissions and Wazuh agent restart |

---

## 📈 Next Steps

- **[Set 4: Generate comprehensive attack scenarios and analyze responses](set4-attacks)**
- **[Set 5: Advanced threat hunting and incident response](set5-hunting)**
- **Integration:** Connect with SIEM platforms for enterprise monitoring

---

## 🎉 Outstanding!

You now have comprehensive network monitoring with Suricata providing real-time threat detection for your DVWA environment.

---

**Navigation:**
- **[← Set 2: Wazuh Configuration](set2-wazuh)** | **[Set 4: Attack Scenarios →](set4-attacks)**
