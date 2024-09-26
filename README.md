# Azure Sentinel HoneyPot Lab

## Objective

The Azure Sentinel Lab objectives are aimed to gain practical hands-on with Azure environment and Services, like Sentinel or Log Analytics, as well as understanding the benefits of Honeypots for cybersecurity defenses.
A honeypot serves as an intentionally vulnerable system designed to attract potential attackers, thereby enabling the collection of valuable information to analyze and mitigate cyber threats.

![Azure_Sentinel_HoneyPot drawio](https://github.com/user-attachments/assets/de37dfd7-f2b7-40dd-8eaa-2756b76ee885)
*Ref 1: Azure Lab Overview*

### Skills Learned

- Demonstrate proficiency in deploying T-Pot, an open-source honeypot solution, on Azure to enhance security measures.
- Utilize Azure services to set up Windows & Linux instances and configure network settings to support T-Pot installation and operation.
- Showcase expertise in Linux operating systems, cloud technologies, network security principles, and access control configurations in Azure.
- Monitor and analysis of honeypot data to gain insights into attacker tactics, techniques, and procedures (TTPs) through Kinana.
- Logstash integration with Azure Sentinel to provide TPot insights on various Threats and Attacks and create Dashboards, and query data.
- Sysmon integration with Azure Sentinel for additional log details on Windows endpoint.

### Tools Used

- Azure Services: Sentinel, Log Analytics Workspace, Workbooks, Network Security Groups, Data Collection Rules/Data Collection Endpoint
- Powershell
- Logstash
- Kibana
- 3rd Party Geolocation API (https://ipgeolocation.io/)
- Sysmon

## Steps


1. Azure Configuration and provisionning of first HoneyPot VM (Windows 10 with RDP Service open on the Internet)
2. We create a new Log Analytics workspace that will gather Logs of the HoneyPot and that will be used by Azure Sentinel (SIEM)
3. Next, on Microsoft Defender we enable Defender for Servers and collect All Events.
4. We connect the LogAnalytics to our Win10 VM.
5. Once the VM is started, we disable the Windows Firewall completely.
6. Afterwards, we signup for the Geolocation IP API and configure the Powershell script available at: https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1
7. We then create a custom log in the LogAnalytics in Azure to show our newly enriched alerts, and we wait a few minutes until logs are processed and forwarded to the Platform.
8. Once logs available, we can query them using the previously created Custom Log Table.
9. We create a new Workbook in Azure, and we paste our Kusto query to retrieve the data.
   Mine looked like the following:
   
`RDP_AUTH_FAIL_GEOIP_CL 
 | extend username = extract(@"username:([^,]+)", 1, RawData), timestamp = extract(@"timestamp:([^,]+)", 1, RawData), 
 latitude = extract(@"latitude:([^,]+)", 1, RawData), longitude = extract(@"longitude:([^,]+)", 1, RawData), 
 sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData), state = extract(@"state:([^,]+)", 1, RawData), 
 label = extract(@"label:([^,]+)", 1, RawData), destination = extract(@"destinationhost:([^,]+)", 1, RawData), 
 country = extract(@"country:([^,]+)", 1, RawData) | where destination != "samplehost" | where sourcehost != "" 
 | summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude`

10. By adjusting the workbook, we select a Map type and make sure to provide the latitude/longitude. That's it.

The following Steps are dedicated to the configuration and steps made to install the TPOT Server and forward some logs to Sentinel.

11. We create a new Linux VM. At least 8GB RAM will be necessary fo this one.
12. Once provisionned, we simply follow the TPOT installation on the official GitHub link: https://github.com/telekom-security/tpotce. The installation is straightforward.
13. After a reboot, TPot is ready and various dashboards and metrics are accessible through Kibana.

I was interested in forwarding some of these attack and threat logs to my freshly configured Log Analytics/Sentinel instance. The easiest way was to forward data through Logstash.
I could provision an additional VM for Logstash purposes only along with Filebeat on TPOT, but in order to first test the integration, I decided to move on with Logstash installed directly on the TPOT Server.

14. We download and install the Logstash version 8.14.0, available on the official Elastic site. Installation steps are described there as well.



