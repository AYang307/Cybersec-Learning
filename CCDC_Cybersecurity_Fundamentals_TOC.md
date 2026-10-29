# CCDC Core Cybersecurity Knowledge: Universal Table of Contents

> **Target Audience:** Absolute beginner preparing for any role on a Collegiate Cyber Defense Competition (CCDC) Blue Team.  
> **Purpose:** A structured roadmap covering the universal defensive foundations required across Linux, Windows, Network, and Injects roles.

---

## The CCDC Mindset: Defense Under Active Fire

In CCDC, you inherit an enterprise network that is **already vulnerable, misconfigured, and likely backdoored**. You are evaluated simultaneously on:
1. **Service Availability (Uptime SLA):** Scored automatically every few minutes (HTTP, HTTPS, DNS, SMTP, SSH, etc.).
2. **Business Injects:** Time-sensitive tasks assigned by the White Team (management/clients).
3. **Defense & Incident Response:** Preventing and detecting unauthorized Red Team access without taking down your own scored services.

Every team member—regardless of specialization—must understand the core fundamentals below.

---

## Module 0: The CCDC Crucible & Operational Discipline
*Understand the competition mechanics, scoring incentives, and team survival rules.*

- **0.1 Competition Architecture & Roles**
  - The four teams: Blue (defenders/you), Red (adversaries), White (judges/evaluators), Orange (customers/end-users).
  - Scoring engine mechanics: How automated polling verifies service uptime and marks SLA failures.
  - The fatal beginner mistake: Securing a machine by unplugging it or blocking all ports (instant 0 points).
- **0.2 The First 15 Minutes ("The Golden Hour")**
  - The initial triage checklist: changing default passwords, inventorying interfaces, taking critical file backups.
  - Communication protocol: How to report compromised systems, active attacks, and broken services to your lead.
- **0.3 Change Control Under Fire**
  - "Rule of Two": Never change an IP, firewall rule, or service config without announcing it to the team.
  - Quick documentation: Shared spreadsheets, IP schemes, service matrices, and credential vaults.

---

## Module 1: Computer Networking & Scored Service Protocols
*You cannot defend what you cannot route. Understand how traffic moves between Blue and Orange/Red.*

- **1.1 IP Fundamentals & Subnetting**
  - IPv4 addresses, CIDR notation (`/24`, `/28`), subnets, and broadcast addresses.
  - Default gateways, routing tables (`route -n`, `Get-NetRoute`), and DNS resolution order.
  - Local loopback (`127.0.0.1`), private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and public IPs.
- **1.2 Scored Service Protocols & Standard Ports**
  - Web: HTTP (80/tcp), HTTPS (443/tcp), common alternatives (8080, 8443).
  - Name resolution: DNS (53/udp and 53/tcp).
  - Remote administration: SSH (22/tcp), RDP (3389/tcp), WinRM (5985/5986).
  - Email: SMTP (25/587), IMAP (143/993), POP3 (110/995).
  - Directory & Storage: LDAP (389/tcp), LDAPS (636/tcp), Kerberos (88/tcp/udp), SMB (445/tcp).
- **1.3 Packet Flow & Protocol Mechanics**
  - The TCP 3-way handshake (`SYN`, `SYN-ACK`, `ACK`) and connection states (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`).
  - UDP connectionless behavior and common spoofing risks.
  - Layer 2 vs. Layer 3: ARP, MAC addresses, and default gateway resolution.
- **1.4 Network Traffic Inspection Tools**
  - Packet captures under pressure: `tcpdump` syntax basics (`tcpdump -i eth0 port 80 -n`).
  - Reading PCAPs in Wireshark: Filtering by IP, port, and following TCP streams.
  - Basic reachability testing: `ping`, `traceroute`/`tracert`, `curl -Iv`, `nc`/`ncat`, and `Test-NetConnection`.

---

## Module 2: Operating System Internals (Linux & Windows Parity)
*Master the two OS families that host every scored service.*

- **2.1 File System Structure & Core Directories**
  - Linux: Root hierarchy (`/etc` for configs, `/var/log` for telemetry, `/var/www` for web roots, `/bin` & `/sbin` for binaries).
  - Windows: System root (`C:\Windows\System32`), user profiles (`C:\Users`), program storage (`C:\Program Files`, `C:\ProgramData`).
  - Hidden files & file extensions: Dotfiles in Linux (`.bashrc`), hidden files and alternate data streams (ADS) in Windows.
- **2.2 Permissions & Access Control Models**
  - Linux POSIX: Read, Write, Execute (`rwx`) for User, Group, Others; numeric notation (`chmod 750`); SUID/SGID bits (`chmod +s`).
  - Windows NTFS: Discretionary Access Control Lists (DACLs), permission inheritance, `icacls`, and ownership.
  - Least privilege: Why web servers (`www-data`, `IUSR`) should never have root or Administrator privileges.
- **2.3 Process Lifecycle & Execution**
  - Process IDs (PID, PPID), parent-child process relationships.
  - How processes launch: fork/exec in Linux, `CreateProcess` in Windows.
  - Suspicious parentage: e.g., `cmd.exe` or `/bin/bash` spawned as a child of `w3wp.exe` (IIS) or `apache2`.
- **2.4 Service Management Frameworks**
  - Linux: `systemctl` (`status`, `stop`, `restart`, `disable`, `mask`) and unit file locations (`/etc/systemd/system`).
  - Windows: `services.msc`, `sc.exe`, `Get-Service`, and Windows Service startup types.

---

## Module 3: Authentication, Identity, & Credential Hygiene
*Red Team's primary entry ticket is stolen, reused, or default credentials.*

- **3.1 Password Stores & Hashing**
  - How passwords are saved: One-way hashing (SHA-512, bcrypt, NTLM) vs. encryption.
  - Linux: `/etc/passwd` (world-readable user list) vs. `/etc/shadow` (restricted password hashes).
  - Windows: SAM database (local accounts) and `NTDS.dit` (Active Directory domain database).
- **3.2 Rapid Password Cycling & Policy Enforcement**
  - Enforcing strong passwords on all users immediately.
  - Linux: `chpasswd`, `passwd`, locking accounts (`passwd -l`).
  - Windows: `net user <username> <newpassword>`, PowerShell `Set-LocalUser`.
- **3.3 Remote Access Hardening**
  - SSH (`/etc/ssh/sshd_config`): Disabling `PermitRootLogin`, disabling password auth in favor of ED25519 keys, changing default ports.
  - RDP: Enforcing Network Level Authentication (NLA), restricting allowed users.
- **3.4 Active Directory Basics (For Every Team Member)**
  - What is a Domain Controller (DC) vs. a domain-joined member server.
  - Domain Admins vs. Local Admins: Why you never log in to a workstation with Domain Admin credentials.
  - Kerberos tickets & pass-the-hash attacks in plain terms.

---

## Module 4: Rapid Baseline & System Inventory
*If you don't know what is running, you cannot know what is malicious.*

- **4.1 Network Socket Auditing (Listening Ports)**
  - Linux commands: `ss -tulpn`, `netstat -antup`, `lsof -i :<port>`.
  - Windows commands: `Get-NetTCPConnection -State Listen`, `netstat -ano | findstr LISTENING`.
  - Correlating open ports to PIDs and legitimate service binaries.
- **4.2 Running Process Inspection**
  - Linux: `ps aux`, `top`/`htop`, inspecting `/proc/<PID>/exe` and `/proc/<PID>/cmdline`.
  - Windows: Task Manager details tab, `Get-Process`, Sysinternals Process Explorer, PowerShell `Get-CimInstance Win32_Process`.
  - Identifying anomalous process names (typosquatting like `svch0st.exe` or `sysd`).
- **4.3 User & Group Auditing**
  - Finding all accounts with administrative power:
    - Linux: `sudoers` file (`/etc/sudoers`, `/etc/sudoers.d/`), checking group `wheel` or `sudo`.
    - Windows: `Get-LocalGroupMember -Group "Administrators"`, `Get-ADGroupMember "Domain Admins"`.
  - Detecting backdoor accounts created in minute 5.

---

## Module 5: Initial Hardening & Rapid Remediation
*Closing the open windows while keeping the front door open for scoring.*

- **5.1 Host-Based Firewalls (The Lifesaver)**
  - Linux `iptables` / `nftables` / `ufw`:
    - Drop all incoming traffic except scored ports (`80`, `443`, etc.) and management IP.
    - Essential rules: Allow `ESTABLISHED,RELATED`, allow loopback `127.0.0.1`.
  - Windows Defender Firewall with Advanced Security:
    - Setting Inbound rules to block by default; explicitly whitelisting scored ports and scoring engine IPs.
- **5.2 Disabling Unscored & Insecure Protocols**
  - Shutting down Telnet (23), FTP (21), rsh/rlogin, LLMNR, NetBIOS, SMBv1.
  - Disabling anonymous file shares and guest accounts.
- **5.3 File Integrity & Critical Backups**
  - Taking immediate cold backups of configuration files (`/etc`, web roots, databases) to an offline drive or share.
  - Quick hashing of critical binaries (`sha256sum /bin/login /bin/passwd /bin/sshd`).

---

## Module 6: Persistence Hunting (How Red Team Stays Inside)
*Red Team plants backdoors within minutes. Learn where they hide.*

- **6.1 Linux Persistence Mechanisms**
  - Scheduled tasks: `/etc/crontab`, `/etc/cron.*`, user crontabs (`crontab -l`), `systemd` timers.
  - Shell startup files: `~/.bashrc`, `~/.profile`, `/etc/profile`, `/etc/bash.bashrc`.
  - SUID binaries: Finding newly created or modified SUID files (`find / -perm -4000 2>/dev/null`).
  - SSH authorized keys: Rogue keys in `~/.ssh/authorized_keys` and `/root/.ssh/authorized_keys`.
  - Pluggable Authentication Modules (PAM): Backdoored `pam_unix.so` accepting master passwords.
- **6.2 Windows Persistence Mechanisms**
  - Scheduled Tasks: `schtasks /query`, checking Task Scheduler for hidden triggers.
  - Registry Run Keys:
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - Startup Folders: `shell:startup` and `shell:common startup`.
  - Malicious Services: Unquoted service paths, services pointing to temp files (`C:\Windows\Temp\payload.exe`).
- **6.3 Web Shells & Injected Backdoors**
  - What a web shell looks like (`eval($_POST['cmd']);`, `Runtime.getRuntime().exec()`).
  - Searching web directories for recently modified files (`find /var/www/html -mmin -60`).
  - Grepping for suspicious PHP/ASP execution functions (`system`, `shell_exec`, `passthru`, `base64_decode`).
- **6.4 Active Session & Reverse Shell Termination**
  - Finding active foreign connections (`ESTABLISHED` connections to unknown public IPs).
  - Killing malicious processes: `kill -9 <PID>` in Linux, `Stop-Process -Id <PID> -Force` in Windows.
  - Blocking outbound malicious callback ports at the host firewall.

---

## Module 7: Log Analysis & Detection Under Pressure
*Catching attacks as they happen without drowning in noise.*

- **7.1 Linux Log Inspection**
  - Key log files: `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS) for authentication.
  - Web logs: `/var/log/apache2/access.log` and `/var/log/nginx/access.log`.
  - Real-time tailing: `tail -f /var/log/auth.log | grep -i "failed"`.
  - `journalctl` essentials (`journalctl -u ssh -f`, `journalctl -xe`).
- **7.2 Windows Event Log Triaging**
  - The critical security event IDs every defender must memorize:
    - **4624:** Successful logon (Logon Type 3 = Network, Logon Type 10 = RDP, Logon Type 2 = Interactive).
    - **4625:** Failed logon attempt (brute-force detection).
    - **4672:** Special privileges assigned to new logon (admin elevation).
    - **4698 / 4702:** Scheduled task created or updated.
    - **7045 / 4697:** New service installed.
  - Quick querying via PowerShell: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}`.

---

## Module 8: Incident Handling, Recovery, & Injects
*Keeping services alive, recovering from crashes, and satisfying White Team.*

- **8.1 Triage & Safe Containment**
  - "Do not panic-reboot": Why rebooting can trigger destructive persistence, wipe volatile memory, or brick bootloaders.
  - Surgical network containment: Restricting a compromised host's outbound traffic while preserving inbound scoring.
- **8.2 Service Recovery Playbooks**
  - Restoring corrupted configuration files from pre-made backups.
  - Database recovery basics: Dumping and restoring MySQL (`mysqldump`) and MSSQL.
  - Web server configuration syntax checks (`apache2ctl configtest`, `nginx -t`).
- **8.3 Business Injects Management**
  - Anatomy of a CCDC inject: Requirements, deliverables, deadlines, and formatting.
  - Technical injects: Adding user accounts, configuring a backup server, deploying an SSL certificate.
  - Executive injects: Writing an incident disclosure memo for the Board of Directors.
- **8.4 Incident Reports (IRs)**
  - How to write an official CCDC Incident Report:
    - Executive Summary
    - Timeline of Events
    - Affected Assets and IP Addresses
    - Threat Actor Actions / Indicators of Compromise (IoCs)
    - Containment & Remediation Actions Taken

---

## Module 9: Hands-On Practice & Automation
*Developing muscle memory before competition day.*

- **9.1 Essential Defensive One-Liners & Scripts**
  - Bash: Quick user audit, SSH key wiper, password mass-rotator.
  - PowerShell: Service restarter, active connection monitor, local admin auditor.
- **9.2 Building a Personal CCDC Home Lab**
  - Setting up an isolated virtual environment (VirtualBox, VMware, or Proxmox).
  - Deploying a vulnerable Linux box (e.g., Ubuntu with weak WordPress) and a Windows Domain Controller.
  - Simulating automated scoring with simple health-check scripts.

---

## How to Explore Any Topic in Detail

You can dive into any specific module or topic above using hands-on interactive tutorials. Whenever you are ready to master a specific practical skill from this TOC, simply ask for it or run:

- `/lathe <topic>` (for example: `/lathe how to hunt persistence on Linux for CCDC` or `/lathe how to secure and baseline a Windows Server for CCDC`)
