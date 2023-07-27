---
title: Hunting With ELK 1
categories: [Writeup threat_hunting]
tags: [eLearn, threat_hunting, elk, kibana, siem]
---
# Scenario 
The IT Security manager has asked your internal Penetration team to generate malicious PowerShell traffic in the environment and has now tasked you, the only Threat hunter, to create detection rules for potentially malicious usage of PowerShell. He has directly tasked you to ensure that your rules detect their commands, where with additional research, he expects you for all to take the detection rules a step further by ensuring that they expand the range of detection for other variations that would match the commands executed by the Penetration team (where possible).


## Task 1. Perform a hunt for well-known PowerShell Offensive Frameworks and commands

To begin our investigation, we will utilize a PowerShell script block to gather information on event 4104. This approach allows us to focus on and analyze the events directly linked to this specific event ID.

```
event.code : 4104 AND winlog.event_data.ScriptBlockText.keyword : *
```

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-2.jpg){: width="972" height="589" }

Upon executing the PowerShell script block, we obtained 573 hits. To narrow down our search and identify potential malicious activities, we will leverage the "**ScriptBlockText**" field and apply filtering to identify common command-line functions often associated with PowerShell offensive frameworks.

```
winlog.event_data.ScriptBlockText:(PowerUp OR Mimikatz OR NinjaCopy OR Get-ModifiablePath OR AllChecks OR AmsiBypass OR PsUACme OR Invoke-DLLInjection OR Invoke-ReflectivePEInjection OR Invoke-Shellcode OR Get-GPPPassword OR Get-Keystrokes OR Get-TimedScreenshot OR PowerView)
```

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-1.jpg){: width="972" height="589" }


it appears that the threat actor has utilized the function ["Get-TimedScreenshot"](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-TimedScreenshot.ps1) as part of their activities. This function is part of Powersploit framework which used to capture screenshots from the compromised system at specified intervals. Threat actors might use this capability to monitor the victim's activities, gain insight into sensitive information, or observe potential vulnerabilities that can be exploited further.

## Task 2. Perform a hunt for suspicious parent process spawning PowerShell

To hunt for suspicious parent processes and initiate our investigation, we can begin by querying the Sysmon event log for Event ID 1, which corresponds to the creation of a process. By examining the "**ParentImage**" and "**Image**" fields within these events, we can identify any potential malicious activities or abnormal process executions.

```
winlog.event_id: 1 AND winlog.event_data.ParentImage :* 
```

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1.jpg){: width="972" height="589" }

The observation that the process "[Regsvr32](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)" with Process ID (PID) 5344 spawned a PowerShell process is a potentially concerning finding. This behavior could indicate an attempt by threat actors to execute malicious code or achieve persistence on the system using a legitimate system tool like "Regsvr32" to load a PowerShell script.

## Task 3. Perform a hunt for renamed PowerShell.exe

To detect renamed instances of "powershell.exe," we can execute another query on the Sysmon event log, specifically Event ID 1, which records process creations. By inspecting the process descriptions, we can identify any potential instances of "powershell.exe" that might have been renamed to evade detection.

```
event.code : 1 AND winlog.event_data.Description: "Windows Powershell"
```

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-4.jpg){: width="972" height="589" }

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-6.jpg){: width="972" height="589" }

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-5.jpg){: width="972" height="589" }

The discovery of three hits, one of which involves a renamed "powershell.exe" now masquerading as "Windows.exe" with an identical description of a PowerShell program and matching hash confirms a potential attempt at obfuscation and evasion by threat actors.

## Task 4. Perform a hunt for base64-encoded PowerShell commands

To identify potential base64-encoded command lines and filter for instances related to the "ec" (Encoding and Decoding) process, we will initiate a query on the Sysmon event log, focusing on Event ID 1, which records process creations. By examining the command line arguments of each event, we can detect any suspicious base64-encoded strings, particularly those containing "ec" which might indicate decryption operations.


```
event.code : 1 AND winlog.event_data.CommandLine : *ec*
```

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-7.jpg){: width="972" height="589" }

The query has resulted in a single hit, where we discovered a base64-encoded command line. Using the CyberChef tool to decode the base64 string, we have revealed that the decoded command is "**whoami**."


## Task 5. Perform a hunt for PowerShell attacks utilizing GZIP compression

| File type | File Signature | Base64Encoding | 
|:----------|:---------------|---------------:|
| DOS Executable | 	MZ |	TV | 
| RAR Compressed |	Rar! |	UmFyI | 
| PDF |	%PDF	| JVBER
| Office/Zip| 	PK|	UE
| Rich Text Format|	{\\rtf	| e1xydG
| Compound Binary File (.doc etc.) |	D0 CF 11 E0 A1 B1 1A E1	| 0M8R4KGxGu
| Gzip | 1F 8B 08 |	H4sI |

To hunt for instances of GZIP compression within base64-encoded commands, we will continue using the "**ScriptBlockText**" field of Sysmon Event ID 4104. By filtering for the unique signature "**H4sl**," which corresponds to GZIP compression in base64, we can identify any PowerShell commands or scripts that utilize this specific compression technique.

```
event.code : 1 AND winlog.event_data.CommandLine : *H4sI*
```
![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-8.jpg){: width="972" height="589" }
It appears that the single hit from the query, which involved filtering for GZIP compression in base64, was a command, "**whoami**," after decoding using CyberChef.

## Task 6. Perform a hunt for obfuscated PowerShell code using XOR
In PowerShell, the XOR operation can be implemented using certain keywords such as **join** and **bxor**. These keywords are used to manipulate binary data and perform bitwise operations like XOR.  [code snippet of ps xor encoder](https://gist.github.com/loadenmb/8254cee0f0287b896a05dcdc8a30042f)

```
event.code : 4104 AND winlog.event_data.ScriptBlockText:(*bxor* AND *join*)
```

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-9.jpg){: width="972" height="589" }

The identification of a single hit in the query, involving a command that employs obfuscated PowerShell code using XOR, is a significant discovery. XOR-based obfuscation is a common technique used by threat actors to conceal malicious code and evade detection by security tools.


## Task 7. Perform a hunt for execution of an assembly from file by PowerShell
To hunt for suspicious .NET reflection via PowerShell, we can utilize the [Reflection.Assembly](https://www.elastic.co/guide/en/security/current/suspicious-.net-reflection-via-powershell.html#suspicious-.net-reflection-via-powershell) type accelerator, which enables the loading and execution of .NET assemblies from files. This technique is commonly used by attackers to dynamically load and execute malicious code during their operations.

```
event.code : 4104 AND winlog.event_data.ScriptBlockText: *[Reflection.Assembly]*
```

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-10.jpg){: width="972" height="589" }


The presence of the command ``[Reflection.Assembly]::LoadFile('C:\temp\cmd.dll');[CMD.Class1]::RunCMD()`` in a PowerShell script is a clear indication of a potential security concern. This script is dynamically loading an assembly named "cmd.dll" from the "C:\\temp" directory and executing a method called "RunCMD()" from a class named "CMD.Class1" within that assembly.

## Task 8. Perform a hunt for PowerShell commands downloading content

To detect commands downloading content in PowerShell. We can use script block text, filter for common commands used to download content, such as Get-Content, Invoke-WebRequest (curl), DownloadData, and Invoke-Expression (iex). 

```
winlog.event_data.ScriptBlockText:(*WebClient* OR *DownloadData* OR *DownloadFile* OR *DownloadString* OR *OpenRead* OR *WebRequest* OR *curl* OR *wget* OR *RestMethod* OR *WinHTTP* OR *InternetExplorer.Application* OR *Excel.Application* OR *Word.Application* OR *Msxml2.XMLHTTP* OR *MsXML2.ServerXML* OR *System.XML.XMLDocument* OR *BitsTransfer*)
```

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-11.jpg){: width="972" height="589" }
![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-13.jpg){: width="972" height="589" }


Based on the results of the query. Commands include curl, Invoke-RestMethod, and Start-BitsTransfer, all aimed at downloading a script.ps1 from  www[.]site[.]com domain. 

## Task 9. Perform a hunt for obfuscated PowerShell commands
Filtering for the usage of the Join command in PowerShell script block ext can be an effective way to detect potentially [Obfuscated Powershell Commands](https://helloitsliam.com/2018/03/21/obfuscating-powershell-commands/). The Join command is often utilized by threat actors to concatenate strings and obfuscate their intentions, making it harder for security tools to recognize malicious activities.

```
event.code : 4104 AND winlog.event_data.ScriptBlockText: *JoIn*
```

![]({{site.baseurl}}/assets/img/2023-07-26-eLearnSec-HuntingWithELK-1-12.jpg){: width="972" height="589" }


```powershell
$A06Jug= "))421]raHC[,)86]raHC[+021]raHC[+911]raHC[( EcALPEr- 63]raHC[,'AzY'ECaLPErc- 93]raHC[,'Om2' ECaLPErc- 43]raHC[,'yDB' ECaLPErc- )')Om2'+'xOm'+'2+]'+'03[E'+'MOHSpAzY+]'+'4[EMohsPA'+'zY (.Dxw y'+'DB '+') Om2 O'+'m2 '+' Om2sfo:ELbaiRaVOm2 me'+'T'+'i-TEs('+'AzY yD'+'B+ )}'+' ))) 61,)_Az'+'Y]GnI'+'rts[ ((61T'+'NI'+'Ot::]'+'T'+'RE'+'Vn'+'oc[ '+'( ]R'+'aH'+'C['+'( {t'+'cEJBO-H'+'cA'+'E'+'r'+'oF Dxw O'+'m2'+'zOm2t'+'IlPS-Om2qOm2'+'tI'+'LPs- Om2HOm2t'+'ILPS-'+' Om2;Om2TI'+'Lps- Om2}'+'Om2TiLps-Om2-Om2 t'+'ILPS-Om2yO'+'m2tiLPS- Om2U'+'Om2Ti'+'lpS-O'+'m296-'+'d6H'+'16yf6q'+'86q7'+'7Om2 
```

Based on the query we got one hit. The presence of concatenated characters and obscure strings is typical of obfuscation techniques used by threat actors to hide the true intent of the command.

--- 
## References
- <https://lolbas-project.github.io/>
- <https://helloitsliam.com/2018/03/21/obfuscating-powershell-commands/>
- <https://gist.github.com/loadenmb/8254cee0f0287b896a05dcdc8a30042f>
- <https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-TimedScreenshot.ps1> 