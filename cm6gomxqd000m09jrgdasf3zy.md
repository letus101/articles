---
title: "Steps to Integrate Wazuh, TheHive, and Shuffle in a SOC Automation Lab"
seoTitle: "Integrating Wazuh, TheHive, and Shuffle in SOC"
seoDescription: "Integrate Wazuh, TheHive, and Shuffle in a SOC lab for automated incident detection, enrichment, and response workflows"
datePublished: Tue Jan 28 2025 16:19:03 GMT+0000 (Coordinated Universal Time)
cuid: cm6gomxqd000m09jrgdasf3zy
slug: steps-to-integrate-wazuh-thehive-and-shuffle-in-a-soc-automation-lab
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1738081220305/e8be7608-8b9c-41a6-ab1e-c2ba046e37d1.jpeg
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1738081099762/161a4387-b89b-4e72-9ceb-9d105f69894c.jpeg
tags: hacking, it, cybersecurity-1, blueteam

---

## Introduction

In this post, I'll walk you through building a comprehensive Security Operations Center (SOC) automation lab that integrates Wazuh SIEM/XDR, TheHive for case management, and Shuffle for SOAR capabilities. This setup demonstrates how to automate security incident detection, enrichment, and response workflows in a controlled environment.

## Architecture Overview

#### *<mark>Logical Diagram of the SOC Automation Lab</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738078996039/33505789-2627-4cde-90f7-c3efb2bfde92.jpeg align="center")

The lab consists of the following components:

1. Windows 10 client with Wazuh agent and Sysmon
    
2. Wazuh Manager server (Ubuntu 22.04)
    
3. TheHive server (Ubuntu 22.04)
    
4. Shuffle for SOAR
    
5. Windows 10 SOC analyst workstation
    

The workflow follows these steps:

1. The Windows 10 client runs a Wazuh agent that monitors security events through Sysmon
    
2. The Wazuh Manager processes these events and generates alerts based on predefined rules
    
3. Alerts are forwarded to Shuffle for automation and orchestration
    
4. Shuffle enriches the alerts with threat intelligence and forwards them to TheHive
    
5. TheHive creates cases for analyst investigation
    
6. SOC analysts receive email notifications and can begin their investigation
    

## Setting Up the Environment

### 1\. Windows 10 Client Configuration

#### *<mark>Windows 10 Client with Sysmon Installed</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079217186/c4b0b643-3ac6-4d79-8ad7-c946f0568ecd.png align="center")

First, I set up a Windows 10 VM and installed Sysmon for enhanced logging capabilities. This provides detailed system activity monitoring that will be crucial for our security monitoring.

### 2\. Wazuh Manager Installation

#### *<mark>Wazuh Installed on Ubuntu 22.04</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079240610/4be09cde-dbce-4368-8005-40d6c4957ca4.png align="center")

On an Ubuntu 22.04 server, I installed Wazuh using the official installation script:

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a -i
```

#### *<mark>Wazuh Dashboard Overview</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079275354/2046a0fe-4767-42f9-a1c5-1dbd6feaf16b.png align="center")

### 3\. TheHive Setup

TheHive installation required several prerequisites and components:

1. Java installation
    

```bash
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

2. Cassandra database
    

```bash
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

3. Elasticsearch
    

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

4. TheHive application
    

```bash
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

#### *<mark>TheHive Dashboard Overview</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079292076/67968b3d-ff37-4039-aea4-9c482107c66b.png align="center")

### 4\. Agent Deployment

#### *<mark>Creating a Wazuh Agent</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079321374/e3040222-9f85-4546-af85-d1db98b87024.png align="center")

#### *<mark>Installing the Wazuh Agent on Windows 10</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079334382/a1cee5b2-9225-4a2a-8d6c-9e47f26a46db.png align="center")

#### *<mark>Added Agent on Wazuh Dashboard</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079350422/b6e2266c-81cc-4a07-b88c-cdd0c93ef00c.png align="center")

I deployed the Wazuh agent to the Windows 10 client and configured it to use Sysmon for enhanced monitoring capabilities.

## Testing and Validation

To validate the setup, I used Mimikatz as a test case for detecting malicious activity:

1. Modified the Wazuh agent configuration to properly ingest Sysmon logs
    
2. Configured the Wazuh manager to log all changes
    
3. Updated filebeat.yml for complete log ingestion
    
4. Created a custom index in Wazuh for comprehensive log searching
    

#### *<mark>Viewing Security Events in Wazuh</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079391572/0b789396-eaef-4b78-92fc-50d1b46dd06c.png align="center")

#### *<mark>Wazuh Agent Configuration File</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079418849/be7dd6b0-54e9-43c0-be1a-0f85cfa90103.png align="center")

#### *<mark>Wazuh Dashboard Showing Sysmon Events</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079440935/784d53c4-ca95-471a-ad43-136b3cefb986.png align="center")

#### *<mark>Mimikatz Installed on Windows 10</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079463090/4c24350a-ec91-46c6-9fe7-31bd49f98d71.png align="center")

#### *<mark>Wazuh Manager Configuration for Logging All Events</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079505315/87bbd6f6-f006-4b39-b673-78794e330af8.png align="center")

#### *<mark>Filebeat Configuration for Wazuh Logs</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079523265/7bab2371-578c-4fa5-8381-b4cb82d4d686.png align="center")

#### *<mark>Index Creation for Wazuh Logs</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079541894/c7b0ab4d-4417-46bf-9f08-84728b24d5f0.png align="center")

#### *<mark>Wazuh Dashboard Showing Mimikatz Events</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079556239/9dd43f8f-74e2-4235-a3ad-57da7c6a8f84.png align="center")

#### *<mark>Custom Rule for Mimikatz in Wazuh</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079571794/d0431def-4bf2-4a38-b6fd-b5c4a1d6769e.png align="center")

#### *<mark>Security Alert for Mimikatz in Wazuh</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079587450/597318df-8e9a-4d44-beaf-ef9449b2039d.png align="center")

## Implementing SOAR with Shuffle

### Workflow Creation

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079610227/094c5aff-113d-43d1-925f-5ed162cf955d.png align="center")

1. Created a Shuffle account
    
2. Implemented a webhook for Wazuh alerts
    
3. Added integration tags to the Wazuh manager configuration
    

#### *<mark>Wazuh Integration with Shuffle</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079640925/cd6304d4-12de-405c-b239-a4992d3fafd0.png align="center")

#### *<mark>Testing Mimikatz Alert in Shuffle</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079655895/cbc9ccb0-4585-4856-ad9e-8912b06f15c9.webp align="center")

### Alert Enrichment

#### *<mark>Regex to Capture SHA256 in Shuffle</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079683239/46af9a4a-f1fc-492d-a0cb-2eed248b4e11.webp align="center")

#### *<mark>SHA256 Results</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079701324/ea629d83-e88f-4846-a074-c9f0e5a47ab0.webp align="center")

#### *<mark>VirusTotal node added to the workflow</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079720341/5285d80c-747e-4ee2-a049-5cf6a9301f44.webp align="center")

#### *<mark>Reputation Score from VirusTotal</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079734109/6861ead2-29df-4fd6-ae11-4411046f5b5b.webp align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079764186/f2733978-3b48-4e54-a6e9-5b8e8d2e9879.webp align="center")

The workflow includes:

* Parsing SHA256 hashes from alerts using regex
    
* VirusTotal integration for threat intelligence enrichment
    
* Automated case creation in TheHive
    

### TheHive Integration

#### *<mark>Alerts in TheHive Case Management Platform</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079753031/999f4485-209d-4a41-9d8e-2c9431a7c417.webp align="center")

1. Created a dedicated organization and service account
    
2. Generated API keys for Shuffle integration
    
3. Configured alert fields mapping
    

### Email Notifications

#### *<mark>Configuring the Email Node in Shuffle</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079778743/008618d9-9b66-45a9-9402-703c3b59f182.webp align="center")

#### *<mark>Email Notification Received by Analyst</mark>*

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1738079789582/8741a1a3-212b-43be-bc8d-51bb7484efa5.webp align="center")

Implemented email notifications using SquareX disposable email service for testing, including:

* Computer name
    
* Event timestamp
    
* Alert details
    
* Threat severity
    

## Conclusion

This lab demonstrates a fully functional SOC automation workflow, from initial detection through to analyst notification. The integration between Wazuh, Shuffle, and TheHive provides a solid foundation for automated security operations, with room for additional customization and expansion.

Key benefits of this setup include:

* Automated threat detection and alerting
    
* Threat intelligence enrichment
    
* Streamlined case management
    
* Immediate analyst notification
    
* Customizable response workflows
    

Future improvements could include adding more threat intelligence sources, implementing automated response actions, and expanding the detection rules.