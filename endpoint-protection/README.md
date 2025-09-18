# 3. Endpoint Protection Tools

Endpoint protection ensures that the system is continuously monitored, malware is detected, and potential intrusions are identified.  
This helps maintain the integrity, availability, and confidentiality of the Linux endpoint.

## 3.1 Audit & Monitoring


Audit & Monitoring ensures all system activities are tracked and logged for security analysis, anomaly detection, and compliance.  
This phase focuses on **Auditd** for detailed system auditing and **Syslog** for centralized log collection.

### 3.1.1 Auditd (System Activity Logging)

**Auditd** is the Linux Audit Daemon, responsible for tracking system events such as user logins, file access, and command executions.

**Install Auditd**

```bash
sudo apt update
sudo apt install auditd audispd-plugins -y
```

**Enable and start the service**

```bash
sudo systemctl enable auditd
sudo systemctl start auditd
```

**Enable and start the service**

```bash
sudo systemctl enable auditd
sudo systemctl start auditd
```

**Verify service status**

```bash
sudo systemctl status auditd
```

**Example: Monitor changes to /etc/passwd**

```bash
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
```
- `-w` → watch file
- `-p wa` → monitor write and attribute changes
- `-k` → assign a key for easier searching

**View audit logs**

```bash
sudo ausearch -k passwd_changes
```

### 3.1.2 Syslog (Centralized Logging)

**Syslog** collects and stores system logs, which can also be forwarded to a central logging server for monitoring.

**Install Syslog**

```bash
sudo apt install rsyslog -y
```

**Enable and start the service**

```bash
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

**Verify service status**

```bash
sudo systemctl status rsyslog
```

**Forward logs to a central server**

```bash
sudo nano /etc/rsyslog.d/50-default.conf
```

Add on the top file this:
```bash
*.* @@central-logging-server-ip:514
```

**Restart rsyslog to apply changes**

```bash
sudo systemctl restart rsyslog
```

**✅ Why this is important:**

- **Auditd** provides detailed tracking of system events, enabling detection of unauthorized access or configuration changes.
- **Syslog** ensures logs are collected centrally, making analysis, alerting, and compliance easier.
- Together, they provide **real-time monitoring, accountability, and incident response capabilities** for the Linux endpoint.
