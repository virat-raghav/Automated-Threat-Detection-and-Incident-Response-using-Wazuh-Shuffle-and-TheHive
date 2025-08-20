# Automated-Threat-Detection-and-Incident-Response-using-Wazuh-Shuffle-and-TheHive

## Description 

This project demonstrates an integrated security automation pipeline combining Wazuh, Shuffle, TheHive, and VirusTotal to enable proactive threat detection and automated incident response. Wazuh acts as the SIEM, detecting malicious activities such as Mimikatz execution on Windows endpoints and unauthorized SSH login attempts on servers. Detected events are forwarded to Shuffle, which automates alert processing, enriches IOCs with VirusTotal, and notifies SOC analysts via email for quick awareness. TheHive functions as the incident management and case tracking platform, enabling analysts to investigate and manage alerts efficiently. In addition, the workflow includes automated response actions such as blocking brute-force SSH attacks, strengthening the overall defensive posture of the environment.

## Setup

This project is hosted on-premises using virtual machines managed with QEMU/Virtual Machine Manager. However, it can also be deployed on any major cloud provider. The environment includes:

* Ubuntu 22.04 Server – hosting the Wazuh Manager

* Ubuntu 22.04 Server – hosting TheHive

* Windows 10 Pro – used for generating telemetry and simulating attacks

## Security Tools

* Wazuh – Open-source security monitoring platform for threat detection, log analysis, and compliance management. It collects events from endpoints/servers and generates alerts.

* Shuffle – Open-source SOAR platform that automates alert processing, enrichment, and response actions through customizable workflows.

* TheHive – Open-source Security Incident Response Platform (SIRP) designed for SOC teams to investigate, track, and collaborate on security incidents.

* VirusTotal – Online malware scanning and threat intelligence service that enriches IOCs (Indicators of Compromise) by analyzing files, URLs, and domains with multiple antivirus engines.

## Flow Diagram

![FlowDiagram](https://github.com/user-attachments/assets/bed03f2b-5c0b-477d-a210-6745fef85da1)

## Windows Client Setup

* Download the Windows ISO file and set up a Windows 10 Pro virtual machine.

* Download Sysmon from the Microsoft Sysinternals website: [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

* Download a recommended Sysmon configuration file from Olaf Hartong’s repository: [sysmonconfig.xml](https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml)

* Place both Sysmon.zip (after extracting) and sysmonconfig.xml in the same directory.

* Open PowerShell as Administrator. Navigate to the directory where Sysmon was extracted. Run the following command to install Sysmon with the configuration file:
 
   ``` 
   sysmon64.exe -i sysmonconfig.xml
   ```

