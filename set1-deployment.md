---
title: "Set 1: Deploy DVWA with Team-Specific Logging"
description: Container deployment and logging configuration for security monitoring
layout: default
nav_order: 2
---

# 🐳 DVWA Set 1: Deploy DVWA with Team-Specific Logging

## 🎯 Objective
Deploy DVWA using Docker with proper logging configuration that security teams can monitor.

---

## 👥 Role Requirements
- **AM Team (amdeploy)** or **PM Team (pmdeploy)** access required
- Instructor assistance needed for log directory setup (sudo required)

---

## 📋 Deployment Steps

### Step 1: Navigate to Your Team Directory

**🔵 AM Team:**
```bash
cd /srv/am
mkdir -p dvwa
cd dvwa
```

**🟣 PM Team:**
```bash
cd /srv/pm  
mkdir -p dvwa
cd dvwa
```

**💡 Explanation:** Each team has dedicated workspace. Keeps projects separated and organized. dvwa subdirectory for this specific project.

### Step 2: Request Log Directory Setup

**Ask instructor to run:**

**🔵 For AM Team:**
```bash
sudo mkdir -p /srv/logs/am/dvwa
sudo chown 33:suricata /srv/logs/am/dvwa  
sudo chmod 2770 /srv/logs/am/dvwa
```

**🟣 For PM Team:**
```bash
sudo mkdir -p /srv/logs/pm/dvwa
sudo chown 33:suricata /srv/logs/pm/dvwa
sudo chmod 2770 /srv/logs/pm/dvwa
```

**💡 Security Permissions:**
- UID 33 = Apache user inside container
- suricata group = security team access
- 2770 = group write + sticky bit
- Allows both logging and monitoring

> ⚠️ **Requires sudo - ask instructor**

### Step 3: Deploy DVWA Container

**🔵 AM Team:**
```bash
docker run -d --name am-dvwa \
  --restart unless-stopped \
  -p 8080:80 \
  -v /srv/logs/am/dvwa:/var/log/apache2 \
  vulnerables/web-dvwa
```

**🟣 PM Team:**
```bash
docker run -d --name pm-dvwa \
  --restart unless-stopped \
  -p 8081:80 \
  -v /srv/logs/pm/dvwa:/var/log/apache2 \
  vulnerables/web-dvwa
```

**💡 Container Configuration:**
- Different ports (8080/8081) prevent conflicts
- Volume mount connects container logs to host
- --restart ensures availability
- -d runs in background

**💡 Log Integration:**
- Apache logs go directly to team directories
- Security teams can monitor immediately

### Step 4: Configure Firewall Access

**🔵 AM Team:**
```bash
sudo ufw allow 8080/tcp comment "AM DVWA"
```

**🟣 PM Team:**
```bash
sudo ufw allow 8081/tcp comment "PM DVWA"  
```

**💡 Network Security:**
- Opens only necessary ports
- Comments help track rules
- Allows external testing access

> ⚠️ **Requires sudo - ask instructor**

### Step 5: Verify Deployment

```bash
# Check container status
docker ps | grep dvwa

# Test internal access
curl -I http://localhost:8080  # AM
curl -I http://localhost:8081  # PM

# Check log generation
ls -la /srv/logs/am/dvwa/      # AM
ls -la /srv/logs/pm/dvwa/      # PM
```

**💡 Health Checks:**
- Container should show "Up" status
- HTTP 200/302 response expected
- Log files should appear after first request

**💡 Troubleshooting:**
- If container fails: check Docker logs
- If no logs: verify volume mount
- If access denied: check permissions

### Step 6: Initial DVWA Setup

1. **Access DVWA in browser:**
   - **🔵 AM:** `http://192.168.0.169:8080`
   - **🟣 PM:** `http://192.168.0.169:8081`

2. **Click "Create / Reset Database"**

3. **Login with defaults:**
   - Username: `admin`
   - Password: `password`

4. **Set Security Level to "Low"** (for initial testing)

**💡 Application Setup:**
- Database creation required for DVWA
- Default credentials are intentionally weak
- Low security enables all vulnerabilities
- Perfect for security testing

**💡 First Logs Generated:**
- Setup process creates initial log entries
- Security team can verify monitoring works

---

## ✅ Success Criteria

- [ ] Container running and accessible via web browser
- [ ] Log files being created in `/srv/logs/[team]/dvwa/`
- [ ] DVWA database setup completed
- [ ] Application responds to HTTP requests
- [ ] Firewall rule configured for team port

---

## 🔍 Verification Commands

```bash
# Container health
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Log monitoring
tail -f /srv/logs/am/dvwa/access.log     # AM team
tail -f /srv/logs/pm/dvwa/access.log     # PM team

# Service availability  
nmap -p 8080,8081 localhost
```

---

## ⚠️ Common Issues & Solutions

| Problem | Solution |
|---------|----------|
| Permission denied on logs | Ask instructor to fix ownership/permissions |
| Container won't start | Check if port already in use: `sudo lsof -i :8080` |
| Can't access from browser | Verify firewall rule and container port mapping |
| No log files created | Generate traffic by visiting the web application |

---

## 📈 Next Steps

Once DVWA is deployed successfully:
- **Security teams** proceed to **[Set 2: Configure Wazuh Monitoring](set2-wazuh)**
- **Development teams** can deploy additional instances or variations
- Begin generating test traffic for security analysis

---

## 🎉 Congratulations!

You've successfully deployed a monitored vulnerable web application ready for security analysis.

---

**Navigation:**
- **[← Set 0: Overview](set0-overview)** | **[Set 2: Wazuh Configuration →](set2-wazuh)**
