---
title: CyberDefender-PacketDetective
categories: [Writeup Cyberdefender]
tags: [cyberdefender, blue, threat_hunting]
---

**Scenario:**
As a SOC analyst, explore a collection of Wireshark pcap files that delve into various attack tactics, including evasion and lateral movement. Analyze network traffic captured within these pcaps to uncover valuable insights and detect potential command and control (C&C) activities.

## Traffic-1
### Q1: What is the amount of bandwidth being used by the SMB protocol in bytes?

![]({{site.baseurl}}/assets/img/2023-05-23-CyberDefender-PacketDetective-9.png){:width="70%"}

By utilizing the Wireshark Protocol Hierarchy Statistic, we can analyze the bandwidth consumption of the SMB protocol, which amounts to 4406 bytes.

**Answer: 4406**

### Q2: Which username was utilized for authentication via SMB?

![]({{site.baseurl}}/assets/img/2023-05-23-CyberDefender-PacketDetective.png){:width="70%"}

The authentication process using the SMB session setup andX Request involved the utilization of the SMB username "Administrator".

**Answer: Administrator**

### Q3: What is the name of the file that was opened?

![]({{site.baseurl}}/assets/img/2023-05-23-CyberDefender-PacketDetective-10.png){:width="70%"}

Within the packet, we can observe the utilization of the SMB Create AndX Request to open a file named "eventlog".

**Answer: eventlog**

### Q4: What is the timestamp of the attempt to clear the event log? (24H-UTC)

![]({{site.baseurl}}/assets/img/2023-05-23-CyberDefender-PacketDetective-11.png){:width="70%"}

To display it in UTC format, we can configure the Wireshark filter with an edit and time display option. 
The attempt to clear the event log was timestamped as 2020-09-23 16:50:16.

**Answer: 2020-09-23 16:50:16**

## Traffic-2 
### Q5: An attacker used a named pipe for communication to blend in and evade detection. What is the name of the service that utilized this pipe for communication?

![]({{site.baseurl}}/assets/img/2023-05-23-CyberDefender-PacketDetective-12.png){:width="70%"}

Atsvc, also known as the AT-Scheduler Service, is a Windows service that plays a significant role in managing scheduled tasks on a system. Upon analyzing packet 25, We can see that the malicious actor utilized the atsvc service within the Windows named pipe framework to establish communication channels. 

**Answer: atsvc**

### Q6: What was the duration of communication between 172.16.66.1 and 172.16.66.36?

![]({{site.baseurl}}/assets/img/2023-05-23-CyberDefender-PacketDetective-13.png){:width="70%"}

Upon inspecting the final packet (139), we can determine that the duration of the communication between IP addresses 172.16.66.1 and 172.16.66.36 which is 11.724708.

**Answer: 11.7247**

## Traffic-3 
### Q7: Which username is used to set up requests that may be considered suspicious?

![]({{site.baseurl}}/assets/img/2023-05-23-CyberDefender-PacketDetective-14.png){:width="70%"}

Packet 5 corresponds to the SMB2 protocol Session and Setup Request. Notably, the presence of the username "backdoor" raises suspicions due to its suspicious nature.

**Answer: backdoor**

### Q8: What is the name of the executable file utilized to execute processes remotely?

![]({{site.baseurl}}/assets/img/2023-05-23-CyberDefender-PacketDetective-15.png){:width="70%"}

We can observe the presence of the filename "PSEXESVC.exe" in packet 11. This particular file is a well-known tool that has been exploited by threat actors to execute programs on remote computers.

**Answer: PSEXESVC.EXE**

--- 
## References
- https://cyberdefenders.org/blueteam-ctf-challenges/104#nav-overview
- https://attack.mitre.org/techniques/T1071/
- https://attack.mitre.org/software/S0029/ 
