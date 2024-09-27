# Azure Sentinel HoneyPot Lab

## Objective

The Azure Sentinel Lab objectives are aimed to gain practical hands-on with Azure environment and Services, like Sentinel or Log Analytics, as well as understanding the benefits of Honeypots for cybersecurity defenses.
A honeypot serves as an intentionally vulnerable system designed to attract potential attackers, thereby enabling the collection of valuable information to analyze and mitigate cyber threats.

![Azure_Sentinel_HoneyPot drawio](https://github.com/user-attachments/assets/de37dfd7-f2b7-40dd-8eaa-2756b76ee885)</br>
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
- Spiderfoot for additional OSINT on attackers
- Atomic RedTeam (https://github.com/redcanaryco/atomic-red-team)

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
 | summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude
 `

10. By adjusting the workbook, we select a Map type and make sure to provide the latitude/longitude. That's it.

![Sentinel_workbook1](https://github.com/user-attachments/assets/08e33540-3e73-4625-b0f7-a53d16998c5f)</br>
*Ref 2: Custom Map created with logs of failed RDP Auth in our Win10 VM*

11. Additionally, we can install Sysmon and forward event data to our Sentinel for further insights.
12. Once Sysmon installed on our Win10 VM, we create a new Data Collection Rule. We specify the XPATH for Sysmon logs.
13. Then, we just need to wait for the logs to come by to our Analytics. We can check if they are present by running the following query.
`Event
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| take 10
`
14. In Sentinel, we use the following query available <a href="https://raw.githubusercontent.com/OTRF/OSSEM/master/resources/parsers/SysmonKQLParserV13.22.txt">here</a>. Itparses the Sysmon logs accordingly within Analytics.
We save it as a function.
15. We can use the Sysmon function and filter the query easily with Kusto (KQL) in Sentinel to check for malicious processes and executions.
16. Installing Atomic RedTeam allows to generate interesting data for Sysmon to push and for us to analyze afterwards. (https://github.com/redcanaryco/atomic-red-team)
I decided to launch the T0003 Creds Dumping technique to verify that we successfully gather all the data for analysis.

![query_sysmon_1](https://github.com/user-attachments/assets/bad04a86-324a-47e6-acbd-c535a5b3c58c)</br>
*Ref 3: Sysmon logs forwarded to Azure Logs - Atomic RedTeam T1003 Creds Dumping attack*

![query_sysmon_2](https://github.com/user-attachments/assets/96b305d2-09d3-489c-895a-b3f23a801c2c)</br>
*Ref 4: Sysmon logs forwarded to Azure Logs - Atomic RedTeam T1003 Creds Dumping attack (continued)*

![query_sysmon_3](https://github.com/user-attachments/assets/25f9dcd8-595a-4623-8271-292b484f114b)</br>
*Ref 5: Sysmon logs forwarded to Azure Logs - Atomic RedTeam T1003 Creds Dumping attack (continued)*

The following Steps are dedicated to the configuration and steps made to install the TPOT Server and forward some logs to Sentinel.

11. We create a new Linux VM. At least 8GB RAM will be necessary fo this one.
12. Once provisionned, we simply follow the TPOT installation on the official GitHub link: https://github.com/telekom-security/tpotce. The installation is straightforward.
13. After a reboot, TPot is ready and various dashboards and metrics are accessible through Kibana.

![tpot_kibana1](https://github.com/user-attachments/assets/87e75076-56ce-4319-8d89-3f9cb8d36a2c)</br>
*Ref 6: Main TPot Dashboard*

![tpot_kibana2](https://github.com/user-attachments/assets/b0f91206-034d-401e-9228-82108b059fb9)</br>
*Ref 7:  Main TPot Dashboard (continued)*

![map_tpot](https://github.com/user-attachments/assets/29bb2452-4248-4c36-9ae4-e1494440fe76)</br>
*Ref 8: Overview of Location Attacks and Types*

I was interested in forwarding some of these attack and threat logs to my freshly configured Log Analytics/Sentinel instance. The easiest way was to forward data through Logstash.
I could provision an additional VM for Logstash purposes only along with Filebeat on TPOT, but in order to first test the integration, I decided to move on with Logstash installed directly on the TPOT Server.

14. We download and install the Logstash version 8.14.0, available on the official Elastic site. Installation steps are described there as well.
15. Next, we need to install a Logstash Plugin to be able to forward our logs to Sentinel. (https://learn.microsoft.com/en-us/azure/sentinel/connect-logstash-data-connection-rules#install-the-plugin)
16. Once the install successful, we need to generate a sample JSON data via the Logstash pipeline. This sample is used to create our custom Data Collection Rule in the next steps.
17. First, we create the Data Collection Endpoint to which Logstash will push the logs.
18. We create a new DCR in Azure, specifying our previously created endpoint and the sample log file in the JSON format.
19. It is needed to use the Transformation editor to populate a mandatory Timestamp field in the DCR wizard.
`source
| extend TimeGenerated = ls_timestamp
`
21. An application needs to be created, in order to retrieve a clientID, tenantID and a secretkey.
22. Once the app created and the identifiers noted down, we assign the "Monitoring Metrics Publisher" role through the Azure Access Control.
23. Then, on the Server, we edit the previous Logstash pipeline and save it inside /etc/logstash/conf.d/ directory.
24. Finally, we verify that the pipeline runs without errors and we start the Logstash service.
25. That's it. We can then exploit the new data in Analytics and Sentinel to create dashboards and queries.

![logstash_event_tosentinel](https://github.com/user-attachments/assets/9d950d02-7f8e-4cdd-b47c-d76b7512a15a)</br>
*Ref 9: Logstash logs showing Crowrie (Telnet/SSH Honeypot) logs forwarding to Azure Sentinel*

![Sentinel_workbook2](https://github.com/user-attachments/assets/4294f1c9-b048-4bfc-a15f-69b59dff21fe)</br>
*Ref 10: Custom Dashboard created with Crowrie logs from our TPOT Server*

