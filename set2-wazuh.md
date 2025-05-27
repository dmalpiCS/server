---
title: "Set 2: Configure Wazuh to Monitor DVWA Logs"
description: Security event monitoring and analysis configuration
layout: default
nav_order: 3
---

# 📊 DVWA Set 2: Configure Wazuh to Monitor DVWA Logs

## 🎯 Objective
Configure Wazuh agent to monitor Apache logs from DVWA containers and set up real-time security event analysis.

---

## 👥 Role Requirements
- **AM Security (amsec)** or **PM Security (pmsec)** access required
- Instructor assistance needed for Wazuh configuration (sudo required)

---

## 📋 Configuration Steps

### Step 1: Verify DVWA Deployment

```bash
# Check your team's DVWA logs exist
ls -la /srv/logs/am/dvwa/     # AM team
ls -la /srv/logs/pm/dvwa/     # PM team

# Verify log content
tail -5 /srv/logs/am/dvwa/access.log    # AM
tail -5 /srv/logs/pm/dvwa/access.log    # PM
```

**💡 Prerequisites Check:**
- DVWA must be deployed from Set 1
- Log files should exist and contain entries
- If no logs, ask deployment team to generate traffic

**💡 Expected Log Format:**
- Apache Combined Log Format
- Contains IP, timestamp, request, response code
- Security events will be embedded in these logs

### Step 2: Check Wazuh Agent Status

```bash
# Verify Wazuh agent is running
sudo systemctl status wazuh-agent

# Check agent connectivity
sudo /var/ossec/bin/wazuh-control status
```

**Ask instructor if agent is not running:**
```bash
sudo systemctl start wazuh-agent
sudo systemctl enable wazuh-agent
```

**💡 Wazuh Infrastructure:**
- Agent runs on each monitored server
- Connects to central Wazuh Manager
- Processes logs locally before sending events

**💡 Connection Verification:**
- Agent should show "Active: active (running)"
- All processes should be operational
- Manager connectivity is essential

### Step 3: Request Wazuh Configuration

**Ask instructor to add log monitoring configuration:**

**For monitoring both teams:**
```xml
<!-- DVWA Apache Log Monitoring -->
<localfile>
  <log_format>apache</log_format>
  <location>/srv/logs/am/dvwa/access.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/srv/logs/am/dvwa/error.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/srv/logs/pm/dvwa/access.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/srv/logs/pm/dvwa/error.log</location>
</localfile>
```

**💡 Configuration Details:**
- Apache log format handles HTTP request parsing
- Monitors both access and error logs
- Covers both team deployments
- Enables real-time log processing

> ⚠️ **Requires sudo access**
> - File: `/var/ossec/etc/ossec.conf`
> - Restart required after changes
> - Configuration validation needed

### Step 4: Restart Wazuh Agent

**Ask instructor to apply configuration:**
```bash
# Validate configuration
sudo /var/ossec/bin/wazuh-control configtest

# Restart agent
sudo systemctl restart wazuh-agent

# Verify restart
sudo systemctl status wazuh-agent
```

**💡 Configuration Activation:**
- configtest validates XML syntax
- Restart applies new log monitoring
- Status should show healthy restart

**💡 Troubleshooting:**
- If configtest fails: XML syntax error
- If restart fails: check logs
- If status shows failed: configuration issue

### Step 5: Verify Log Monitoring

```bash
# Check Wazuh is processing logs
sudo tail -f /var/ossec/logs/ossec.log

# Look for messages like:
# INFO: Monitoring output: '/srv/logs/am/dvwa/access.log'
# INFO: Started monitoring '/srv/logs/am/dvwa/access.log'
```

**Generate test traffic:**
```bash
# Visit DVWA to create log entries
curl http://192.168.0.169:8080    # AM
curl http://192.168.0.169:8081    # PM
```

**💡 Monitoring Verification:**
- Wazuh should detect new log files
- Processing messages appear in ossec.log
- Real-time monitoring begins immediately

**💡 Active Testing:**
- Generate HTTP requests to create logs
- Watch for immediate processing
- Verify both access and error logs

### Step 6: Access Wazuh Dashboard

1. **Connect via NoMachine or browser:**
   - URL: `https://wazuh-indexer:443`
   - Or: `https://192.168.0.169:443`

2. **Login credentials:**
   - Username: `admin`
   - Password: `admin`

3. **Navigate to Security Events:**
   - Menu → "Security Events"
   - Filter by "apache" or "dvwa"
   - Set time range to "Last 15 minutes"

**💡 Dashboard Access:**
- Centralized security event console
- Real-time event visualization
- Advanced filtering and search

**💡 Initial Setup:**
- May take 5-10 minutes for first events
- Index patterns auto-created
- Events indexed by timestamp

**💡 Navigation Tips:**
- Use time filters for recent events
- Search by filename or content
- Group by agent or log source

### Step 7: Verify Event Collection

**In Wazuh Dashboard:**

1. **Check Agent Status:**
   - Menu → "Agents" 
   - Verify server appears and shows "Active"

2. **View Log Events:**
   - Menu → "Security Events"
   - Search: `data.srcip:*` (for HTTP requests)
   - Filter: `rule.groups:apache`

3. **Analyze Event Details:**
   - Click on individual events
   - Review parsed fields
   - Note rule classifications

**💡 Event Analysis:**
- Events should show within minutes
- HTTP requests parsed into fields
- IP addresses, URLs, response codes extracted

**💡 Key Fields to Monitor:**
- `data.srcip`: Source IP address
- `data.url`: Requested URL  
- `data.status`: HTTP response code
- `rule.description`: Security rule triggered

**💡 Troubleshooting:**
- No events: check agent connectivity
- No parsing: verify log format
- Missing fields: check Apache log format

---

## ✅ Success Criteria

- [ ] Wazuh agent actively monitoring DVWA logs
- [ ] Apache log entries appearing in Wazuh Dashboard
- [ ] Security events generated from HTTP requests
- [ ] Dashboard shows agent as "Active" 
- [ ] Real-time event processing confirmed

---

## 🔍 Key Dashboard Searches

```bash
# Apache-related events
rule.groups:apache

# DVWA-specific activity  
data.srcip:* AND (dvwa OR login.php OR setup.php)

# Error events
rule.level:>=7

# Recent activity (last hour)
timestamp:[now-1h TO now]
```

---

## 📊 Expected Event Types

| Event Type | Rule Level | Description |
|------------|------------|-------------|
| HTTP GET/POST | 3 | Normal web requests |
| 404 Not Found | 5 | Missing resource access |
| 403 Forbidden | 7 | Access denied attempts |
| 500 Server Error | 8 | Application errors |
| Multiple failed logins | 10 | Potential brute force |

---

## ⚠️ Common Issues & Solutions

| Problem | Solution |
|---------|----------|
| No events in dashboard | Check agent status and restart if needed |
| Agent shows "Disconnected" | Verify network connectivity to Wazuh Manager |
| Events not parsed correctly | Confirm Apache log format in configuration |
| Dashboard login fails | Verify credentials and certificate acceptance |
| Missing log files | Ensure DVWA is generating traffic |

---

## 🎯 Advanced Configuration Options

**Custom Rule Creation (Instructor):**
```xml
<!-- Detect SQL injection attempts -->
<rule id="100001" level="12">
  <if_sid>31108</if_sid>
  <url>union|select|insert|delete|drop|exec</url>
  <description>Possible SQL injection attack on DVWA</description>
  <group>attack,sql_injection</group>
</rule>
```

---

## 📈 Next Steps

- **[Set 3: Configure Suricata for network-level monitoring](set3-suricata)**
- **[Set 4: Generate and analyze security events](set4-attacks)**
- **Advanced:** Create custom detection rules for specific threats

---

## 🎉 Excellent!

Wazuh is now monitoring your DVWA deployment and providing real-time security insights.

---

**Navigation:**
- **[← Set 1: Deployment](set1-deployment)** | **[Set 3: Suricata Configuration →](set3-suricata)**
