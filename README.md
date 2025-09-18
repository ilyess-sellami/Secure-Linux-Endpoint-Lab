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

**1. System Hardening**

- Disable root login over SSH
- Enforce SSH key authentication + Fail2Ban
- Configure firewall (UFW/iptables)
- Apply automatic updates & patches
- Remove unnecessary services and packages

**2. User & Access Management**

- Create admin user with sudo privileges
- Enforce password policies (PAM)
- Implement least privilege access (RBAC)

**3. Endpoint Protection Tools**

- Audit & Monitoring:
    - Auditd (system activity logging)
    - Syslog centralized logging
- Malware & Threat Detection:
    - ClamAV (antivirus)
    - Rkhunter (rootkit detection)
- Intrusion Detection:
    - Wazuh agent (or OSSEC agent) installed on VM

**4. File & System Integrity**

- AIDE (Advanced Intrusion Detection Environment) for file integrity monitoring
- Tripwire (optional alternative)

**5. Network Security**

- IDS with Suricata (local rules for endpoint traffic monitoring)
- Port scan detection (psad)

---

## 1. System Hardening

System hardening is the process of securing a Linux endpoint by reducing its attack surface, enforcing strong access controls, and applying security best practices.  
This includes disabling risky defaults, configuring firewalls, enforcing secure authentication, removing unnecessary services, and keeping the system up to date with patches.  

The goal is to make the system more resilient against unauthorized access, malware, and potential breaches while ensuring proper monitoring and accountability.

### 1.1 Disable Root Login over SSH

Direct root login over SSH is a common attack vector. Disabling it improves security by enforcing the principle of least privilege and making unauthorized access harder.

**1.1.1 Create a non-root admin user**

```bash
sudo adduser adminuser
sudo usermod -aG sudo adminuser
```

**1.1.2 Edit SSH configuration**

Edit the ssh configuration file:
```bash
sudo nano /etc/ssh/sshd_config
```

Set the following:

```nginx
PermitRootLogin no
```

**1.1.3 Restart SSH service**

```bash
sudo systemctl restart ssh
```

**✅ Why this is important:**

- Prevents attackers from targeting the root account directly.
- Forces use of individual user accounts, improving **accountability and audit logging**.
- Reduces the attack surface for brute-force or password-guessing attempts.

### 1.2 Enforce SSH Key Authentication + Fail2Ban

SSH key-based authentication is a secure alternative to passwords. Combined with Fail2Ban, it protects the server against brute-force attacks.

**1.2.1 Generate SSH Key Pair (on local machine)**

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```
- Accept default location (`~/.ssh/id_ed25519`).
- Optionally, set a passphrase for added security.

**1.2.2 Copy Public Key to Server**

```bash
ssh-copy-id adminuser@<VM_IP>
```
- Replaces `<VM_IP>` with your server’s IP.
- This appends your public key to `/home/adminuser/.ssh/authorized_keys`.

**1.2.3 Verify SSH Key Login**

```bash
ssh adminuser@<VM_IP>
```
- You should **log in without entering a password**.

**1.2.4 Disable Password Authentication (Optional)**

Edit the ssh configuration file:
```bash
sudo nano /etc/ssh/sshd_config
```

Set the following:
```nginx
PasswordAuthentication no
```

Restart the ssh service:
```bash
sudo systemctl restart ssh
```

**1.2.5 Install and Configure Fail2Ban**

```bash
sudo apt update && sudo apt install fail2ban -y
sudo nano /etc/fail2ban/jail.local
```

- Example configuration for SSH:
```ini
[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
```

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
sudo fail2ban-client status sshd
```

- You should see like this output:

```bash
Status for the jail: sshd
|- Filter
|  |- Currently failed:	0
|  |- Total failed:	0
|  `- Journal matches:	_SYSTEMD_UNIT=sshd.service + _COMM=sshd
`- Actions
   |- Currently banned:	0
   |- Total banned:	0
   `- Banned IP list:	
```

**✅ Why this is important:**

- **SSH keys** are much harder to brute-force than passwords.
- **Fail2Ban** automatically blocks IPs after repeated failed login attempts.
- Together, they **greatly reduce the risk of unauthorized access** and protect the server from brute-force attacks.

### 1.3 Configure Firewall (UFW / iptables)

A firewall is a critical layer of defense that controls which network traffic is allowed to reach the system.  
By default, all unnecessary connections should be denied, and only essential services explicitly permitted. 

**1.3.1 Install UFW (if not already installed)**

```bash
sudo apt update
sudo apt install ufw -y
```

**1.3.2 Set Default Policies**

Deny everything by default, then allow only what’s needed:
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

**1.3.3 Allow Only Secure Services**

```bash
sudo ufw allow ssh       # Allow SSH
sudo ufw allow 80/tcp    # Allow HTTP (if you plan a web server)
sudo ufw allow 443/tcp   # Allow HTTPS
```

**1.3.4 Enable the Firewall**

```bash
sudo ufw enable
```

Confirm:
```bash
sudo ufw status verbose
```

Expected output:
```bash
Status: active
To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
```

**1.3.5 Add Rate Limiting (Extra Security)**

To slow down brute force attacks on SSH:
```bash
sudo ufw limit ssh/tcp
```

**1.3.6 (Optional) Iptables Extra Hardening**

If you want advanced control beyond UFW:
```bash
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
```
This blocks IPs with more than 3 SSH attempts in 60 seconds.

**✅ Why this is important:**

- **Restricts access** by only allowing essential services (SSH, HTTP, HTTPS).  
- **Reduces attack surface** by blocking unused and vulnerable ports.  
- **Mitigates brute-force attempts** with rate limiting on SSH.  

### 1.4 Apply automatic updates & patches

Keeping a server updated is **critical for security**. Most exploits target known vulnerabilities, and unpatched systems are the easiest targets. As a system administrator, enabling automatic updates ensures that security patches are applied quickly without manual intervention.

**1.4.1 Install the Unattended-Upgrades package**

```bash
sudo apt update
sudo apt install unattended-upgrades apt-listchanges -y
```

**1.4.2 Enable Automatic Updates**

Run the configuration tool:
```bash
sudo dpkg-reconfigure --priority=low unattended-upgrades
```
- Select **Yes** when asked to automatically download and install stable updates.

**1.4.3 Verify the Configuration**

Check the configuration file:
```bash
cat /etc/apt/apt.conf.d/20auto-upgrades
```

You should see something like:
```bash
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

**✅ Why this is important:**

- **Closes known vulnerabilities** quickly by applying patches.
- **Reduces human error** — no need to remember manual updates.
- **Minimizes attack window** before an exploit can be used.
- **Keeps the system compliant** with best security practices.

### 1.5 Remove Unnecessary Services and Packages

Minimizing the number of installed services is one of the most effective hardening practices.
Every running service is a potential entry point for attackers, so disabling or removing unused software reduces risk.

**1.5.1 List Active Services**

Check what’s running:
```bash
sudo systemctl list-unit-files --type=service --state=enabled
```
This shows which services start automatically at boot.

**1.5.2 Disable Unnecessary Services**

If you find a service you don’t need (example: `cups` for printing), disable and stop it:
```bash
sudo systemctl disable cups
sudo systemctl stop cups
```

**1.5.3 Remove Unneeded Packages**

Check installed packages and remove unused ones:
```bash
sudo apt list --installed
sudo apt remove --purge <package-name>
```
**1.5.4 Clean Up**

Remove residual config files and unused dependencies:
```bash
sudo apt autoremove -y
sudo apt autoclean -y
```

**✅ Why this is important:**

- **Reduces attack surface** by eliminating unnecessary software.
- **Frees system resources** (CPU, RAM, storage).
- **Prevents vulnerabilities** from unused but exploitable services.
- **Simplifies monitoring** by keeping only essential services active.

---

## 2. User & Access Management

User and access management is the practice of controlling who can access the system, what they can do, and how their actions are tracked.  
It ensures that only authorized users are granted access, with the principle of least privilege applied to minimize risk.

This includes creating individual user accounts, enforcing strong password and key-based authentication policies, using groups and roles to manage permissions, and monitoring user activity through logs.  

The goal is to prevent unauthorized access, limit potential damage from compromised accounts, and maintain accountability for every action performed on the system.

### 2.1 Create Admin User with Sudo Privileges

Instead of using the `root` account directly (which is risky), we create a dedicated **admin user** with **sudo privileges**.

This ensures all administrative actions are logged, and root access is only obtained when explicitly required.

**2.1.1 Create a New User**

```bash
sudo adduser adminuser
```
You’ll be prompted to set a password and optional details (name, room number, etc.).

**2.1.2 Add the User to the Sudo Group**

```bash
sudo usermod -aG sudo adminuser
```

**2.1.3 Verify Sudo Access**

Switch to the new user:
```bash
su - adminuser
```

Run a sudo command:
```
sudo whoami
```

Expected output:
```bash
root
```

**✅ Why this is important:**

- **Avoids direct root login**, reducing exposure to brute-force attacks.
- **Provides accountability** since each admin has their own account.
- **Enforces least privilege**, as normal tasks can be run without root.
- **Improves security monitoring** by logging all privileged actions through `sudo`.

### 2.2 Enforce Password Policies (PAM)

To strengthen authentication security, we use **PAM (Pluggable Authentication Modules)** to enforce **strong password policies**.
This ensures that user passwords are not weak, reused, or easily guessable, making brute-force and credential-stuffing attacks less effective.

**2.2.1 Install the `libpam-pwquality` Module**

```bash
sudo apt install libpam-pwquality -y
```

**2.2.2 Configure Password Policies**

Edit the PAM configuration file:
```bash
sudo nano /etc/pam.d/common-password
```

Find the line containing:
```ruby
password   requisite    pam_pwquality.so retry=3
```

Modify or add rules such as:
```ruby
password   requisite    pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
```

Explanation:

- `minlen=12` → minimum 12 characters
- `ucredit=-1` → at least 1 uppercase letter
- `lcredit=-1` → at least 1 lowercase letter
- `dcredit=-1` → at least 1 digit
- `ocredit=-1` → at least 1 special character

**2.2.3 Configure Password Expiration & History**

Edit `/etc/login.defs`:
```bash
sudo nano /etc/login.defs
```

Recommended settings:
```nginx
PASS_MAX_DAYS   90      # Force password change every 90 days
PASS_MIN_DAYS   7       # Prevent immediate password changes
PASS_WARN_AGE   14      # Warn users 14 days before expiry
```

Enforce password history (prevent reuse):

```bash
sudo nano /etc/pam.d/common-password
```

Add:
```ruby
password required pam_unix.so remember=5
```

**2.2.4 Test the Policy**

Change a password:
```bash
passwd adminuser
```
Try weak passwords and confirm they’re rejected.

**✅ Why this is important:**

- **Prevents weak passwords** that attackers can easily guess.
- **Forces password rotation** to reduce risk of compromised accounts.
- **Stops password reuse**, limiting impact of leaked credentials.
- **Adds multiple layers of complexity** (uppercase, digits, symbols) making brute-force attacks far less effective.
