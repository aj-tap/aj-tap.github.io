---
title: CyberDefender-RedLine
categories: [Writeup Cyberdefender]
tags: [cyberdefender, blue, digital_forensics ]
---

**Scenario:** 
As a member of the Security Blue team, your assignment is to analyze a memory dump using Redline and Volatility tools. Your goal is to trace the steps taken by the attacker on the compromised machine and determine how they managed to bypass the Network Intrusion Detection System "NIDS". Your investigation will involve identifying the specific malware family employed in the attack, along with its characteristics. Additionally, your task is to identify and mitigate any traces or footprints left by the attacker.

## Q1 What is the name of the suspicious process?

First let's run volatility and perform profile scan for the image. 

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-9.png){:width="70%"}

```bash
vol.py imageinfo -f MemoryDump.mem
```
Once we have identified the profile image, we can proceed to conduct further analysis using tools such as `pstree` and `malfind` to identify any suspicious processes. 


![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine.png){:width="70%"}

During this analysis, we have discovered a process named `oneetx.exe` which appears to be suspicious. Notably, this process exhibits RWX (Read, Write, Execute) permissions in memory, which is an indicator of potentially malicious activity. Additionally, we have observed the presence of a Magic byte with an MZ header, which is typically associated with process injection techniques.

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-10.png){:width="70%"}

```bash
vol.py --profile=Win10x64_19041 -f MemoryDump.mem malfind
```

Answer:  oneetx.exe


## Q2 What is the child process name of the suspicious process?

We can find the name of the child process name of suspicious process using **pstree** comamnd in the volatility. The child process name is **rundll32.exe** 

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-11.png){:width="70%"}

```bash
vol.py --profile=Win10x64_19041 -f MemoryDump.mem pstree
```

Answer: rundll32.exe

## Q3 What is the memory protection applied to the suspicious process memory region?

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-10.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-4.png){:width="70%"}

Just like the previous scan using **malfind** plugin the memory protection is RWX

Answer: PAGE_EXECUTE_READWRITE

## Q4 What is the name of the process responsible for the VPN connection?

```bash
vol.py --profile=Win10x64_19041 netscan -f MemoryDump.mem 
```

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-2.png){:width="70%"}

We can see that the parent process of tun2socks.exe is Outline.exe. thus, it is the responsible process for vpn connection.

Answer: Outline.exe

## Q5 What is the attacker's IP address?

```bash
vol3 -f MemoryDump.mem windows.netscan
```

Based on the **netscan** plugin of volatility. the suspicious process onetx.exe established http connection to 77.91.124.20 

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-3.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-12.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-5.png){:width="70%"}

Answer: 77[.]91[.]124[.]20

## Q6 Based on the previous artifacts. What is the name of the malware family?

According to our previous artifacts found the IP is used as C2 domain for [Amadey](https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey ). It is a malware dropper capable of performing system reconnaissance, stealing information from the target endpoint, and dropping additional payloads. One of payload it drops is [Redline Stealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer)

If the strings redline can be found in memory, we can test our hypothesis. Let's start by extracting the strings and then filtering them with grep.

```bash
strings MemoryDump.mem > strings.txt
cat strings.txt | grep -i "redline"
```

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-6.png){:width="70%"}

Answer: RedLine Stealer


## Q7 What is the full URL of the PHP file that the attacker visited?

Using the same memory image extracted strings. We can easily use grep to extract and filter out the URL pattern. 

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-7.png){:width="70%"}

```bash
cat strings.txt | grep -iE "http(|s):\/\/77.91.124.20\/"
```

Answer: hxxp[://]77[.]91[.]124[.]20/store/games/index[.]php

## Q8 What is the full path of the malicious executable?

We can readily determine the malicious executable's file path by using grep with file path pattern matching, which results in the file name. 

```bash
cat strings.txt | grep -Eo '[A-Za-z]:\\[^[:cntrl:]"<>|?*]{6,}\oneetx.exe$'
```

![]({{site.baseurl}}/assets/img/2023-07-03-CyberDefender-RedLine-8.png){:width="70%"}

Answer: C:\\Users\\Tammam\\AppData\\Local\\Temp\\c3912af058\\oneetx.exe

--- 
## References
- https://cyberdefenders.org/blueteam-ctf-challenges/106#nav-overview
- https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet
- https://gridinsoft.com/blogs/oneetx-removal/