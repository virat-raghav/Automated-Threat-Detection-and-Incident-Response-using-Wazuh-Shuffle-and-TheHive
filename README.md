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
 
   ```bash
   sysmon64.exe -i sysmonconfig.xml
   ```
   
### Downloading Mimikatz

To download mimikatz to our agent, exclude the Downloads folder from Windows Defender scans. 

Go to Windows Security > Virus & threat protection > Manage Settings > Add or remove exclusions > Add an exclusion and select the Downloads folder.

Download it from: [Mimikatz](https://github.com/gentilkiwi/mimikatz/releases) 

Open the directory where Mimikatz is downloaded on the powershell terminal and execute it:

    .\mimikatz.exe

## Wazuh Setup

 1. Create a new Ubuntu 22.04 Server VM with the minimum following specs:

    CPU: 2 cores

    Memory: 2 GB

    Storage: 75 GB

 2. Update and upgrade the system:

    ```bash
    sudo apt update && sudo apt upgrade -y
    ```
    
 3. Install Wazuh Manager

    Run the following to download and install Wazuh:

    ```bash
    curl -so wazuh-install.sh https://packages.wazuh.com/4.3/wazuh-install.sh && bash ./wazuh-install.sh -a
    ```
    
    Once installation completes, note down the default credentials provided.

4. Access the Wazuh Console

    Open your browser and navigate to:

    ```bash
    https://<your_ubuntu_server_ip>
    ```
    
    Log in using the default credentials.

5. Deploy a New Agent (Windows Client)

    * In the Wazuh Console, go to “Deploy new agent”. Select Windows option.

    * Enter the Wazuh Manager IP address as server address.

    * Copy the agent installation command provided by Wazuh.
    
    <img width="1567" height="589" alt="2025-08-20_19-44" src="https://github.com/user-attachments/assets/97e875d1-31d4-4417-9e27-55b0f863e75a" />

    On your Windows client, open PowerShell as Administrator and run the copied command to install the Wazuh Agent.

6. Verify the Agent Connection

    * Return to the Wazuh Console.

    * Refresh the Agents view, you should now see the Windows client listed as a connected agent.

      <img width="1908" height="744" alt="2025-08-09_22-56" src="https://github.com/user-attachments/assets/1a7c6b14-7dd5-4291-956d-a8383730c190" />

## Wazuh Configuration

This section configures telemetry collection, archives full logs for hunting, and creates a custom rule to alert on Mimikatz activity, even when the binary is renamed.

### Agent Telemetry via Sysmon

Configure the Windows Wazuh Agent to ingest Sysmon logs so Mimikatz activity is captured with rich process telemetry.

  1. Edit the agent config:

        * Open: C:\Program Files (x86)\ossec-agent\ossec.conf

        * Use a text editor (e.g., Notepad as Administrator).

   2. Get the Sysmon channel name:

        * Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational > Properties.

        * Copy Full Name: Microsoft-Windows-Sysmon/Operational.

   3. Configure Log Analysis to use Sysmon:

        * In ossec.conf, in the Log Analysis section:

            * Remove existing Application/System/Security localfile entries.

            * Add:
          
              ```bash
              <localfile>
                <location>Microsoft-Windows-Sysmon/Operational</location>
                <log_format>eventchannel</log_format>
              </localfile>
     
             Note: With this change, the agent forwards only Sysmon events to Wazuh Manager.

   4. Restart the Wazuh Agent service on Windows:

        * Open Services, restart the Wazuh agent.

   5. Verify ingestion in Wazuh:

        * In Wazuh Dashboard: Explore > Discover.

        * Search for “sysmon” and confirm events are preseent.

### Enable Full Log Archiving on Wazuh Manager

By default, Wazuh primarily exposes events that match rules. Enable full archiving to retain all events for hunting and for rules that key on detailed fields.

   1. Edit Wazuh Manager config:

        * SSH to the Wazuh server and type in :

            ```bash
            sudo nano /var/ossec/etc/ossec.conf

        * Apply changes to enable log archiving.
      
          <img width="833" height="523" alt="image" src="https://github.com/user-attachments/assets/6e182b78-40b0-411b-b045-347be623b861" />


   2. Save and restart the manager:

        ```bash
        sudo systemctl restart wazuh-manager.service

        sudo systemctl status wazuh-manager.service

With these changes, archived logs are stored under: /var/ossec/logs/archives

### Configure Filebeat to Ship Archives

Ensure Filebeat ships the archived logs so they can be searched in the Wazuh Dashboard.

   1. Edit Filebeat configuration:

        ```bash
        sudo nano /etc/filebeat/filebeat.yml
        ```
        <img width="688" height="614" alt="image" src="https://github.com/user-attachments/assets/e1972381-d723-4e2d-8ab8-89645ee1dfe6" />


   2. Restart Filebeat:

        ```bash
        sudo systemctl restart filebeat

### Create an Archives Index Pattern

Create a dedicated index pattern to search all archived logs, not only alerts.

   1. In Wazuh Dashboard:

        * Navigate to: Dashboard Management > Index Patterns > Create Index Pattern.

        * Give the name: wazuh-archives-*
      
          <img width="1717" height="460" alt="2025-08-21_00-56" src="https://github.com/user-attachments/assets/17dfcbe3-9c80-4b4c-93a0-6d7a8e56c0f2" />

        * Select Time field: timestamp.
          
        * Create the index pattern.

   2. Validate:

        * Re-run Mimikatz on the Windows agent.

        * In Discover, switch index to wazuh-archives-* and confirm Sysmon events showing Mimikatz execution are visible.
          
          <img width="1904" height="855" alt="2025-08-11_22-24" src="https://github.com/user-attachments/assets/8b975d1a-9ee2-4eb2-afef-6438b53f549c" />

### Custom Alert Rule for Mimikatz

Create a local custom rule to alert on Mimikatz, including renamed binaries via the originalFileName field.

  * In the Wazuh Manager navigate to: Wazuh Dashboard > Server Management > Rules > Custom Rules.

  * Edit the local_rules.xml by adding the rule (ensure correct indentation):
    
  ```bash
  <rule id="100002" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz.exe</field>
    <description>Mimikatz Usage Detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
 ```
   <img width="921" height="808" alt="2025-08-11_23-54" src="https://github.com/user-attachments/assets/038649a6-c6dd-44de-abcb-ec61ec97b0f1" />

 * Save changes and confirm restart when prompted.

### Testing

   * Rename mimikatz.exe to a different filename, here I named catsandcows.exe.

   * Execute it on PowerShell on the Windows host.

   * In Wazuh Dashboard, navigate to Threat Intelligence> Threat Hunting> Events
     
     <img width="1910" height="988" alt="2025-08-12_01-12" src="https://github.com/user-attachments/assets/d2d8b65a-4f63-42b0-a267-33903607987a" />

       Renamed Mimikatz is successfully detected by our custom rule.




 

