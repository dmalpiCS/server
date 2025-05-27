---
title: "Set 5: Advanced Threat Hunting and Forensics"
description: Professional-level threat hunting and forensic analysis techniques
layout: default
nav_order: 6
---

# 🔍 DVWA Set 5: Advanced Threat Hunting and Forensics

## 🎯 Objective
Develop advanced threat hunting skills using security data from previous attack scenarios and learn forensic analysis techniques for incident investigation.

---

## 👥 Role Requirements
- **AM Security (amsec)** and **PM Security (pmsec)** (Security teams focus)
- **Deploy teams** available for additional attack simulation if needed
- Instructor assistance for advanced configuration and analysis tools

---

## 📋 Advanced Analysis Steps

### Phase 1: Historical Data Analysis

```bash
# Analyze attack patterns from previous sets
cd /srv/logs/am/suricata/  # or /pm for PM team

# Count events by type over time
jq -r '[.timestamp, .event_type] | @csv' eve.json | \
  sort | uniq -c | head -20

# Identify attack timeframes
jq 'select(.event_type=="alert") | [.timestamp, .alert.signature] | @csv' eve.json | \
  sort | head -10

# Map attacker behavior
jq 'select(.event_type=="http") | [.timestamp, .src_ip, .http.url] | @csv' eve.json | \
  grep -E "(sql|script|union|select)" | sort
```

**💡 Historical Analysis:**
- Pattern recognition over time
- Attack timeline reconstruction
- Behavior correlation across events
- Trend identification

**💡 Data Mining Techniques:**
- Event frequency analysis
- Time-based clustering
- IP reputation correlation
- Attack signature patterns

**💡 Forensic Value:**
- Evidence preservation
- Attack attribution
- Timeline verification
- Impact assessment

### Phase 2: Advanced Query Techniques

```bash
# Complex event correlation
jq 'select(.event_type=="alert" and .alert.severity<=3) | 
    {timestamp, src_ip, signature: .alert.signature, category: .alert.category}' eve.json

# HTTP request analysis
jq 'select(.event_type=="http" and .http.status>=400) |
    {timestamp, src_ip, method: .http.http_method, url: .http.url, status: .http.status}' eve.json

# Failed vs successful attacks
jq 'select(.event_type=="http") | 
    if .http.status == 200 then "success" else "failed" end' eve.json | 
    sort | uniq -c

# Attack payload extraction
jq -r 'select(.event_type=="alert" and (.alert.signature | contains("SQL"))) | 
       .http.url' eve.json | head -10
```

**💡 Advanced Analytics:**
- Multi-field correlation
- Conditional logic queries
- Statistical analysis
- Payload inspection

**💡 Query Optimization:**
- Efficient field selection
- Pipeline processing
- Memory usage optimization
- Result formatting

**💡 Intelligence Gathering:**
- IOC extraction
- TTPs identification
- Campaign tracking
- Attribution clues

### Phase 3: Threat Hunting Hypotheses

**Develop and test hunting hypotheses:**

**Hypothesis 1: Persistent Attacker**
```bash
# Find IPs with multiple attack types
jq -r 'select(.event_type=="alert") | [.src_ip, .alert.category] | @csv' eve.json | \
  sort | uniq | awk -F, '{ip[$1]++; cat[$1","$2]++} END {for(i in ip) if(ip[i]>3) print i, ip[i]}'

# Analyze attack progression
jq 'select(.src_ip=="192.168.0.100") | [.timestamp, .event_type, .alert.signature // .http.url] | @csv' eve.json
```

**Hypothesis 2: Insider Threat**
```bash
# Look for unusual internal activity
jq 'select(.src_ip | startswith("192.168.")) | [.timestamp, .src_ip, .event_type] | @csv' eve.json | \
  sort | uniq -c | sort -nr

# After-hours activity
jq 'select(.timestamp | strptime("%Y
