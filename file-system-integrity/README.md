# 4. File & System Integrity

File and system integrity monitoring ensures that critical files and directories are not tampered with by attackers or malware.  
This module uses **AIDE (Advanced Intrusion Detection Environment)** and optionally **Tripwire** to monitor changes and maintain system integrity.

---

## 4.1 AIDE (Advanced Intrusion Detection Environment)

**AIDE** is an open-source tool that creates a database of file attributes and checks for unauthorized changes.

**Installation:**
```bash
sudo apt update
sudo apt install aide -y
```

**Initialize AIDE database:**
```bash
sudo aideinit
```