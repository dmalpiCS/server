---
title: "Set 0: Project Overview & Role Setup"
description: Team structure, role definitions, and initial system access
layout: default
nav_order: 1
---

# 🔐 DVWA Set 0: Project Overview & Role Setup

## 📋 Project Overview

This project simulates a real-world security monitoring environment where development teams deploy vulnerable web applications (DVWA) while security teams monitor and analyze threats using enterprise-grade tools.

### 🎯 Learning Objectives
- Deploy containerized applications with proper logging
- Configure security monitoring with Wazuh and Suricata
- Analyze security events and threats in real-time
- Practice team-based access controls and role separation

---

## 👥 Team Structure & Role Rotation

### 📊 Team Composition Diagram

```
    ┌─────────────── TEAM COMPOSITION (3-4 people per team) ───────────────┐
    │                                                                      │
    │  🔵 AM TEAM                           🟣 PM TEAM                     │
    │  ┌─────────────────┐                  ┌─────────────────┐            │
    │  │ PRIMARY ROLES   │                  │ PRIMARY ROLES   │            │
    │  │ • amapp (dev)   │                  │ • pmapp (dev)   │            │
    │  │ • amdeploy      │                  │ • pmdeploy      │            │
    │  │ • amsec         │                  │ • pmsec         │            │
    │  └─────────────────┘                  └─────────────────┘            │
    │           │                                     │                    │
    │           └──────────┬─────────────────────────┘                    │
    │                      │                                              │
    │                      ▼                                              │
    │  ┌─────────────────────────────────────────────────────────────┐    │
    │  │                🏴‍☠️ PENTESTER STATION                      │    │
    │  │           Kali Linux Raspberry Pi 5 + Burp Suite          │    │
    │  │                                                             │    │
    │  │  • Primary operator rotates between teams                   │    │
    │  │  • Conducts external penetration testing                    │    │
    │  │  • Validates security controls                              │    │
    │  │  • Generates realistic attack scenarios                     │    │
    │  └─────────────────────────────────────────────────────────────┘    │
    └──────────────────────────────────────────────────────────────────────┘

           ┌─────────────── ROLE ROTATION STRATEGY ───────────────┐
           │                                                       │
           │  🔄 WHEN PRIMARY ROLE IS COMPLETE:                   │
           │                                                       │
           │  📱 Developers (amapp/pmapp)     →  🏴‍☠️ Pentesting      │
           │  🚀 Deployers (amdeploy/pmdeploy) →  🛡️ Security Support │
           │  🛡️ Security (amsec/pmsec)        →  📊 Analysis       │
           │  🏴‍☠️ Pentester                   →  🔄 Rotate teams    │
           │                                                       │
           │  💡 CROSS-TRAINING BENEFITS:                         │
           │  • Understand full attack lifecycle                  │
           │  • Appreciate different perspectives                 │
           │  • Build comprehensive security skills               │
           │  • Ensure continuous engagement                      │
           └───────────────────────────────────────────────────────┘
```

### 🎯 Role Definitions & Responsibilities

| Primary Role | Team | Core Responsibilities | Secondary Roles When Available |
|-------------|------|----------------------|--------------------------------|
| **amapp/pmapp** | Development | Code DVWA customizations, create vulnerable features | → Pentesting, Attack generation |
| **amdeploy/pmdeploy** | DevOps | Deploy containers, configure infrastructure | → Security monitoring, Log analysis |
| **amsec/pmsec** | Security | Monitor alerts, investigate incidents, tune detection | → Advanced analysis, Report writing |
| **Pentester** | External | External testing, attack simulation, control validation | → Rotate between AM/PM teams |
| **dm** | Instructor | System administration, sudo access, guidance | → All teams support |

---

## 🛠️ Available Tools & Access

### All Roles Have Access To:
- SSH terminal access
- NoMachine GUI access (dm, amapp, pmapp, amsec, pmsec only)
- Team-specific log directories in `/srv/logs/am/` or `/srv/logs/pm/`

### Role-Specific Tool Access:

#### 🔵 AM Team & 🟣 PM Team - Development Roles (amapp/pmapp, amdeploy/pmdeploy)
- Docker container management
- UFW firewall configuration
- Team work directories: `/srv/am/` or `/srv/pm/`
- Team log access: `/srv/logs/am/` or `/srv/logs/pm/`
- Code editing tools (VS Code via NoMachine)
- DVWA customization capabilities

#### 🔵 AM Team & 🟣 PM Team - Security Roles (amsec/pmsec)
- Wazuh Dashboard: `https://wazuh-indexer:443`
- Grafana Dashboard: `http://192.168.0.169:3000`
- Suricata log analysis
- Security event correlation
- Team log monitoring: `/srv/logs/am/` or `/srv/logs/pm/`
- Incident response tools

#### 🏴‍☠️ Pentester Station (Kali Linux Raspberry Pi 5)
- Burp Suite Professional
- OWASP ZAP
- Custom exploit development
- Network scanning tools (nmap, masscan)
- Web application testing frameworks
- Payload generation and encoding tools

---

## 🚪 Initial Login Instructions

### Step 1: Connect to Server via NoMachine

1. **Install NoMachine Client** on your Windows 11 machine:
   - Download from: https://www.nomachine.com/download
   - Install the client application (NOT the server)

2. **Create New Connection:**
   - Host: `192.168.0.169` (or your assigned server IP)
   - Port: `4000`
   - Protocol: `NX`

3. **Login with Your Role:**
   - Username: `<your-role>` (amdeploy, pmdeploy, amsec, or pmsec)
   - Password: `<your-role>` (same as username initially)

### Step 2: Change Your Password (REQUIRED)

```bash
# Change your password immediately after first login
passwd
# Enter current password (your role name)
# Enter new secure password twice
```

> ⚠️ **Security Note:** You MUST change your password on first login for security.

### Step 3: SSH Access (Optional)

If you prefer terminal access:

```bash
# From Windows PowerShell or terminal
ssh <your-role>@192.168.0.169
# Example: ssh amdeploy@192.168.0.169
```

---

## 📁 Directory Structure & Permissions

### Work Directories:
- **🔵 AM Team:** `/srv/am/` - Development workspace
- **🟣 PM Team:** `/srv/pm/` - Development workspace

### Log Directories:
- **🔵 AM Logs:** `/srv/logs/am/` - Team-specific monitoring
- **🟣 PM Logs:** `/srv/logs/pm/` - Team-specific monitoring

### Shared Monitoring:
- Wazuh Dashboard: Centralized security event monitoring
- Grafana: Performance and metrics visualization
- Suricata: Network intrusion detection

---

## 📊 Monitoring Infrastructure

### Security Stack Components:
1. **Wazuh Indexer** - Stores and indexes security events
2. **Wazuh Manager** - Processes and correlates security data
3. **Wazuh Dashboard** - Web interface for security analysis
4. **Suricata** - Network intrusion detection system
5. **Grafana** - Additional visualization and alerting

### Data Flow:
```
DVWA Container → Apache Logs → Wazuh Agent → Wazuh Manager → Wazuh Indexer → Dashboard
      ↓
Network Traffic → Suricata → Log Files → Wazuh Agent → Security Analysis
```

---

## 🎓 What You'll Learn

### Development Teams (amdeploy/pmdeploy):
- Container deployment and management
- Application logging configuration
- Network security basics
- DevSecOps practices
- **Secondary:** Penetration testing techniques, attack simulation

### Security Teams (amsec/pmsec):
- Security event analysis
- Threat detection and response
- Log correlation and investigation
- Security dashboard usage
- Incident response workflows
- **Secondary:** Advanced forensics, threat hunting automation

### Pentester:
- External penetration testing methodologies
- Web application security assessment
- Exploit development and chaining
- Security control validation
- Attack simulation and red teaming
- **Rotation:** Cross-team collaboration and knowledge transfer

---

## 📋 Project Progression

1. **[Set 1: Deploy DVWA with team-specific logging](set1-deployment)**
2. **[Set 2: Configure Wazuh to monitor application logs](set2-wazuh)**
3. **[Set 3: Set up Suricata network monitoring](set3-suricata)**
4. **[Set 4: Generate and analyze security events](set4-attacks)**
5. **[Set 5: Advanced threat hunting and response](set5-hunting)**

---

## 🆘 Getting Help

- **For sudo/admin tasks:** Contact instructor (dm role)
- **For role permissions:** Instructor will assist with system-level changes
- **For troubleshooting:** Check with teammates first, then instructor
- **Emergency:** All security alerts should be reported immediately

---

## 🚀 Next Steps

**Ready to begin? Proceed to [Set 1: Deploy DVWA with Team-Specific Logging](set1-deployment) for your role-specific deployment instructions!**

---

**Navigation:**
- **[← Home](index)** | **[Set 1: Deployment →](set1-deployment)**
