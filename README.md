# 🖥️ Secure Linux Endpoint Lab

## 📌 Overview
The **Secure Linux Endpoint Lab** is a hands-on project that demonstrates how to **harden and monitor a Linux system** using **open-source tools**.  
It highlights skills in **system administration** and **SOC engineering** by focusing on endpoint protection, log analysis, and attack detection.  

---

## 🎯 Objectives
- Configure and harden a Linux VM (Ubuntu/Debian)  
- Implement **endpoint security tools** (Auditd, Fail2Ban, ClamAV, AIDE, Suricata, Wazuh agent)  
- Simulate attacks (brute force, malware, unauthorized file changes)  
- Detect, log, and respond to incidents  

---

## 🏗️ Lab Setup
- **Virtualization**: VirtualBox / VMware / Proxmox  
- **OS**: Ubuntu Server 22.04 LTS (recommended)  
- **Network**: NAT or Bridged for connectivity  
- **Tools Installed**:  
  - 🔐 **Fail2Ban** → SSH brute force protection  
  - 🔑 **Auditd** → Activity logging  
  - 🛡️ **ClamAV** → Malware detection  
  - 📂 **AIDE** → File integrity monitoring  
  - 🌐 **Suricata** → Network intrusion detection  
  - 📊 **Wazuh Agent** → Log collection & SOC monitoring  

---

## 🔐 Security Hardening Steps

### 1. System Hardening
See details in [system-hardening/README.md](/system-hardening/README.md)  
Includes:
- Disable root login over SSH  
- Enforce SSH key authentication + Fail2Ban  
- Configure firewall (UFW/iptables)  
- Apply automatic updates & patches  
- Remove unnecessary services and packages  

### 2. User & Access Management
See details in [user-access-management/README.md](/user-access-management/README.md)  
Includes:
- Create admin user with sudo privileges  
- Enforce password policies (PAM)  
- Implement least privilege access (RBAC)  

### 3. Endpoint Protection Tools
See details in [endpoint-protection/README.md](/endpoint-protection/README.md)  
Includes:
- **Audit & Monitoring:**  
    - Auditd (system activity logging)  
    - Syslog centralized logging  
- **Malware & Threat Detection:**  
    - ClamAV (antivirus)  
    - Rkhunter (rootkit detection)  
- **Intrusion Detection:**  
    - Wazuh agent (or OSSEC agent) installed on VM  

### 4. File & System Integrity
See details in [file-system-integrity/README.md](/file-system-integrity/README.md)  
Includes:
- AIDE (Advanced Intrusion Detection Environment)  
- Tripwire (optional alternative)  

### 5. Network Security
See details in [network-security/README.md](/network-security/README.md)  
Includes:
- IDS with Suricata (local rules for endpoint traffic monitoring)  
- Port scan detection (psad)