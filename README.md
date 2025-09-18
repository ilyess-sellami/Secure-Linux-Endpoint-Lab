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
  - 🔐 Fail2Ban → SSH brute force protection  
  - 🔑 Auditd → Activity logging  
  - 🛡️ ClamAV → Malware detection  
  - 📂 AIDE → File integrity monitoring  
  - 🌐 Suricata → Network intrusion detection  
  - 📊 Wazuh Agent → Log collection & SOC monitoring  

---

## 🔐 Hardening Checklist
1. Disable root SSH login  
2. Enforce SSH key-based authentication  
3. Configure UFW firewall rules  
4. Remove unused packages/services  
5. Apply automatic updates  
6. Create non-root admin user with sudo  

➡️ Detailed steps: [docs/hardening.md](docs/hardening.md)  

---

## ⚔️ Attack Scenarios
Simulated attacks to validate the endpoint’s security:  

- **SSH Brute Force** → Detected & blocked by Fail2Ban + Auditd logs  
- **Malware Test File (EICAR)** → Detected by ClamAV  
- **Unauthorized File Change** → Detected by AIDE  
- **Network Scan** → Detected by Suricata  

➡️ Full details: [docs/attack-scenarios.md](docs/attack-scenarios.md)  

---

## 📊 SOC Monitoring
The endpoint integrates with **Wazuh** (or ELK) for centralized monitoring:  
- Collect system logs  
- Correlate IDS/IPS alerts  
- Generate security events dashboards  

➡️ Setup guide: [docs/monitoring.md](docs/monitoring.md)  

---

## 📸 Screenshots
Proof of hardening & detections available in: [screenshots/](screenshots/)  

Examples:  
- Fail2Ban blocking SSH brute force  
- ClamAV catching EICAR test file  
- AIDE integrity alert  

---

## 🚀 Outcomes
By completing this project, you will:  
- Show expertise in **Linux system administration & security hardening**  
- Demonstrate **endpoint monitoring & SOC detection** skills  
- Build a **portfolio-ready cybersecurity project**  

---

## 📂 Repository Structure
