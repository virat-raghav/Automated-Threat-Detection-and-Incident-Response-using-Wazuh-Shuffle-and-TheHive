# Automated-Threat-Detection-and-Incident-Response-using-Wazuh-Shuffle-and-TheHive

## Description 

This project demonstrates an integrated security automation pipeline combining Wazuh, Shuffle, TheHive, and VirusTotal to enable proactive threat detection and automated incident response. Wazuh acts as the SIEM, detecting malicious activities such as Mimikatz execution on Windows endpoints and unauthorized SSH login attempts on servers. Detected events are forwarded to Shuffle, which automates alert processing, enriches IOCs with VirusTotal, and notifies SOC analysts via email for quick awareness. TheHive functions as the incident management and case tracking platform, enabling analysts to investigate and manage alerts efficiently. In addition, the workflow includes automated response actions such as blocking brute-force SSH attacks, strengthening the overall defensive posture of the environment.

## Setup

This project is hosted on-premises using virtual machines managed with QEMU/Virtual Machine Manager. However, it can also be deployed on any major cloud provider. The environment includes:

* Ubuntu 24.04 Server – hosting the Wazuh Manager

* Ubuntu 24.04 Server – hosting TheHive

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

 1. Create a new Ubuntu Server VM with the minimum following specs:

    CPU: 2 cores

    Memory: 2 GB

    Storage: 75 GB

 2. Update and upgrade the system:

    ```bash
    sudo apt update && sudo apt upgrade -y
    ```
    
 3. Install Wazuh Manager

    Run the following command to download and install Wazuh:

    ```bash
    curl -so wazuh-install.sh https://packages.wazuh.com/4.3/wazuh-install.sh && bash ./wazuh-install.sh -a
    ```
    
    Once installation completes, note down the default credentials provided.

4. Access the Wazuh Console

    Open your browser and navigate to:

    ```bash
    https://<your_ubuntu_server_ip>
    ```
    
    Login using the default credentials.

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

## TheHive Setup

Prerequisites (VM Specs)

   * OS: Ubuntu Server (22.04/24.04)
     
   * CPU: 2 cores

   * RAM: 3GB

   * Storage: 75GB

Update system first:

```bash
sudo apt update && sudo apt upgrade -y
```
Install Base Dependencies

```bash
sudo apt install -y wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```
Install Java

```bash
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install -y java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

Verify the installation by running:

```bash
java -version
```

### Install Apache Cassandra

```bash
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install -y cassandra
```

Configure Cassandra by modifying settings within the file (use Ctrl+W to search for keywords):

```bash
sudo nano /etc/cassandra/cassandra.yaml
```

Change these following:

   * cluster_name: set a name (e.g., thehive-cluster)

   * listen_address: <TheHive_IP>

   * rpc_address: <TheHive_IP>

   * seeds: "<TheHive_IP>:7000"

Next Save the changes with Ctrl+X and press Y. Now, stop Cassandra server and remove the files located at `/var/lib/cassandra` that came with theHive package installation:

```bash
sudo systemctl stop cassandra
sudo rm -rf /var/lib/cassandra/*
```

Restart the service and ensure it is active and running:

```bash
sudo systemctl start cassandra
sudo systemctl enable cassandra
sudo systemctl status cassandra
```

<img width="961" height="348" alt="2025-08-21_15-30" src="https://github.com/user-attachments/assets/de6fc7e3-b3ec-4eb1-9465-8a81f2ede99a" />

### Install Elasticsearch

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt install -y apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install -y elasticsearch
```

Configure Elasticsearch by modifying settings within the file:

```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Change these following::

   * cluster.name: e.g., thehive-es

   * node.name: uncomment it

   * network.host: <TheHive_IP>

   * http.port: 9200

   * cluster.initial_master_nodes: ["node-1"]

Save the file. Then start and enable Elasticsearch service and check if it is running:

```bash
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl status elasticsearch
```

<img width="930" height="310" alt="2025-08-21_15-41" src="https://github.com/user-attachments/assets/5336ee31-99d4-46e8-8428-8c6021bd58f7" />

### Install TheHive 5

```bash
wget -O /tmp/thehive_5.5.7-1_all.deb https://thehive.download.strangebee.com/5.5/deb/thehive_5.5.7-1_all.deb
sudo apt install -y /tmp/thehive_5.5.7-1_all.deb
sudo apt update
```

Ensure TheHive user owns the storage directory (default: /opt/thp):

```bash
sudo ls -la /opt/thp
sudo chown -R thehive:thehive /opt/thp
```

Configure TheHive by modifying settings within the file:

```bash
sudo nano /etc/thehive/application.conf
```

Set:

   * db.janusgraph_hostname = <TheHive_IP>

   * db.janusgraph_cluster-name = <Cassandra_cluster_name_from_cassandra.yaml>

   * index.search_hostname = <TheHive_IP> 

   * application.baseUrl = "http://<TheHive_IP>:9000"

Note: Use http unless you’ve configured TLS/reverse proxy.

Start Services and Verify:

```bash
sudo systemctl start thehive
sudo systemctl enable thehive
sudo systemctl status thehive
```

<img width="1015" height="281" alt="2025-08-21_16-15" src="https://github.com/user-attachments/assets/efec8579-b9b9-41f3-956e-b85feaea0d48" />

Ensure all services are active:

```bash
sudo systemctl start cassandra elasticsearch thehive
sudo systemctl enable cassandra elasticsearch thehive
sudo systemctl status cassandra elasticsearch thehive
```

Access TheHive on your browser with:

   * URL: http://<TheHive_IP>:9000

   * Default credentials: admin@thehive.local / secret

<img width="1770" height="713" alt="2025-08-21_16-23" src="https://github.com/user-attachments/assets/2c423c79-0ef4-4fa9-b2a9-29d98b3ea367" />

## Integrating Shuffle (SOAR)

### Create a Workflow in Shuffle

- Sign up and log in to [Shuffle](https://shuffler.io/), then create and name a new Workflow.
  
- Drag a Webhook into the canvas and connect it to the “Change Me” function; rename the Webhook to “Wazuh Alerts.”
  
  <img width="1271" height="1023" alt="2025-08-12_20-19" src="https://github.com/user-attachments/assets/27569ab5-0516-4801-b198-e0a1786a582f" />

  The Webhook will receive alerts from Wazuh into this workflow.
  
- Configure the “Change Me” function:
  
  - Find Actions: keep “Repeat back to me.”
    
  - Call: remove “Hello World,” click + and choose Runtime Argument so incoming Webhook alerts are echoed back.

    <img width="1291" height="983" alt="2025-08-21_19-46" src="https://github.com/user-attachments/assets/10ebc706-ffee-498f-a3e9-4db3117fa1aa" />

 
Save the workflow, then proceed to configure Wazuh.

### Send Wazuh Alerts to Shuffle

- On the Wazuh server, edit ossec.conf and add an integration pointing to the Shuffle Webhook:
  
  - Path: /var/ossec/etc/ossec.conf
    
  ```bash
    <integration>
      <name>shuffle</name>
      <hook_url>WEBHOOK_URI</hook_url>
      <rule_id>100002</rule_id>
      <alert_format>json</alert_format>
    </integration>
  ```
  <img width="1030" height="263" alt="2025-08-21_19-54" src="https://github.com/user-attachments/assets/3bd638e8-dc79-4b6c-9653-04bce72a63cf" />

- This forwards alerts from rule_id 100002 (Mimikatz detected) to Shuffle.
  
- Save and restart the Wazuh manager service.
  
- Re-run the Mimikatz test (e.g., catsandcows.exe) on the Windows agent to generate an alert.

In Shuffle, click the Webhook and press START, then open Show Executions to confirm events are arriving; the execution arguments should show a Mimikatz-related alert.

<img width="1264" height="1030" alt="2025-08-12_20-21" src="https://github.com/user-attachments/assets/a81beda0-8174-43c9-8eb4-fba8d008a70d" />

### IOC Enrichment with VirusTotal

Extract the SHA256 from the alert and query VirusTotal for a reputation report.

1) Extract SHA256 via Regex
   
- Update the “Change Me” step:
  
  - Find Actions: set to “Regex capture group”
    
  - Input data: choose the hashes field from Runtime Arguments ($exec.text.win.eventdata.hashes).
    
  - Regex: SHA256=([A-Fa-f0-9]{64})
  
    <img width="1196" height="987" alt="2025-08-12_20-53" src="https://github.com/user-attachments/assets/d07de70e-626a-4f32-ac94-5715673bb684" />

- Test by running “Rerun Workflow” and verify only the SHA256 value is returned.
  
  <img width="887" height="483" alt="2025-08-12_20-58" src="https://github.com/user-attachments/assets/23a48cd4-2f6c-4139-a835-7c0873559976" />


2) Integrate VirusTotal
   
- Obtain the VirusTotal API key from your account.
  
- In Shuffle, drag the VirusTotal app into the workflow and complete authentication (VirusTotal API key and URL).
  
- Set Find Action to “Get a hash report,” and set Id to the regex value we set before.

  <img width="1183" height="933" alt="2025-08-12_21-15" src="https://github.com/user-attachments/assets/095f057a-5ea6-44bf-b424-286b95436938" />
  
- Save and rerun the workflow; the execution should include the VirusTotal file report with reputation details.
  
<img width="986" height="761" alt="2025-08-21_20-42" src="https://github.com/user-attachments/assets/8e35e300-49aa-4258-ba49-8be9bc46d716" />

<img width="1543" height="898" alt="2025-08-12_21-30" src="https://github.com/user-attachments/assets/77cadba0-fd0b-440e-b236-df8bed2c77cc" />

### TheHive Integration

1. Prepare TheHive for Alerts
   
- Sign in to TheHive at http://<thehive_ip>:9000 and create a new organization to receive alerts from Shuffle.
  
- Add two users in this organization:
  
  - Normal user (for monitoring):
    
    - Login: virat@test.com
      
    - Name: virat
      
    - Profile: analyst
      
  - Service account (for API access from Shuffle):
    
    - Login: shuffle@test.com
      
    - Name: SOAR
      
    - Profile: analyst
      
      <img width="1853" height="563" alt="2025-08-22_13-38" src="https://github.com/user-attachments/assets/ff033c47-eab8-4f52-ba25-503f025c0275" />

- Set a password for the virat user: Preview → Set a new password → Confirm.
  
- Generate an API key for the shuffle SOAR user: Preview → API Key → Create → Confirm.

### Create Alerts from Shuffle

- In Shuffle, add the TheHive app to the workflow by connecting it to the VirusTotal icon.

- Configure the action:
  
  - Find action: Create alert  
  - Go to Advanced → Body (JSON), remove the existing JSON and add the one below (You can edit to your choice):
 ```bash
{
  "severity": 2,
  "summary": "Mimikatz detected on host: $exec.text.win.system.computer with process ID: $exec.text.win.system.processID and the command Line: $exec.text.win.eventdata.commandLine",
  "tags": ["T1003"],
  "title": "$exec.title",
  "description": "Mimikatz detected on host: $exec.text.win.system.computer and user: $exec.text.win.eventdata.user",
  "date": "$exec.text.win.eventdata.utcTime",
  "flag": false,
  "pap": 2,
  "source": "Wazuh",
  "sourceRef": "$exec.rule_id",
  "status": "New",
  "tlp": 2,
  "type": "internal"
}
```

### Enable External Access to TheHive (ngrok workaround)

 Shuffle won't reach TheHive on port 9000 on your LAN so expose it via ngrok:  
 
- Create an account in the [ngrok](https://dashboard.ngrok.com/login) website and follow these steps:
 
  - To Install:
    
    ```bash
    snap install ngrok
    ```
     
  - You get the authentication token, use it to authenticate ngrok:
    
    ```bash
     ngrok config add-authtoken <token>
    ```
    
  - Allow LAN access to 9000 (optional, adjust CIDR as needed):

   ```bash 
    sudo ufw allow from <192.168.1.0/24> to any port 9000 proto tcp
   ```
  - Start tunnel: ngrok http <thehive_ip>:9000

    <img width="1141" height="399" alt="2025-08-22_15-10" src="https://github.com/user-attachments/assets/c54b2603-9ba1-4627-bcff-152d2d88403f" />

- In Shuffle’s TheHive app settings, use the ngrok URL and authenticate with the API key from the shuffle SOAR user.
  
  <img width="1248" height="865" alt="2025-08-22_15-18" src="https://github.com/user-attachments/assets/bfe3f333-dd49-4325-a805-d2f50dac55c4" />

   Note: Without a static ngrok domain, the URL must be updated each time ngrok restarts.

- Log in to TheHive as virat@test.com and rerun the Shuffle workflow to see the alerts in thehive instance.
  
  <img width="1858" height="1045" alt="2025-08-22_13-42" src="https://github.com/user-attachments/assets/2911dab8-4b2d-4de1-924a-ccacae1f7114" />

  <img width="1371" height="719" alt="2025-08-19_13-08" src="https://github.com/user-attachments/assets/9ad78e7b-b04a-4f07-8692-6e3441b61448" />

  The alerts appear successfully  in TheHive for the Mimikatz detection.

### Notify Analysts by Email

- Add the Email app to the Shuffle workflow (after VirusTotal/TheHive as desired).
  
- Configure:
  
  - Recipients: analyst email address (I used a disposable mail from [DisposableMail](https://www.disposablemail.com/))
    
  - Subject/Body: customize with key IOC details and host/user context
 
- The final Workflow should look like this:

  <img width="1351" height="987" alt="2025-08-22_16-06" src="https://github.com/user-attachments/assets/5acc9455-d509-40cb-b5f5-02cee58f391e" />
     
- Save the workflow and rerun.

   <img width="1515" height="641" alt="2025-08-19_15-18" src="https://github.com/user-attachments/assets/5c8b7eee-d207-4d63-9393-c0dfa6882d3d" />

- Verify delivery in Shuffle’s execution logs and confirm receipt in the email inbox.

<img width="635" height="206" alt="2025-08-19_15-19" src="https://github.com/user-attachments/assets/e52ad52f-9f26-4e54-a1bd-8402f0a480f7" />


 

