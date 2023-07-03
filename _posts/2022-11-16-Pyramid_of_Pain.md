---
title: THM-Writeups Pyramid of pain
categories: [Writeup tryhackme]
tags: [tryhackme, pentest]
---

![]({{site.baseurl}}/assets/img/writeups-pop-pyramid.jpg){:width="100%"}

# Table of Contents [Pyramid of pain](https://tryhackme.com/room/pyramidofpainax)
1. [Hash Values (Trivial) ](#id-hash_values)
2. [IP Address (Easy)](#id-ip_address)
3. [Domain Names (Simple)](#id-domain_names)
4. [Host Artifacts (Annoying)](#id-Host_artifacts)
5. [Network Artifacts (Annoying)](#id-Network_artifacts)
6. [Tools (Challenging)](#id-Tools)
7. [TTPs (Tough)](#id-ttps)

---

<div id='id-hash_values'/>

## Hash Values (Trivial) 
##### 1. Provide the ransomware name for the hash '63625702e63e333f235b5025078cea1545f29b1ad42b1e46031911321779b6be' using open-source lookup tools?

Several online tools can be used to determine which malware family this malicious sample belongs to. We can use Malshare, a public malware repository, to perform hash lookups to determine which malware family this binary belongs to.

![]({{site.baseurl}}/assets/img/writeups-pop-1.png){:width="100%"}

##### Answer: Conti 

---

<div id='id-ip_address'/>

## IP Address (Easy)
##### 2.0 What is the ASN for the third IP address observed?
![]({{site.baseurl}}/assets/img/writeups-pop-2.png){:width="100%"}

##### Answer: Host Europe GmbH

##### 2.1 What is the domain name associated with the first IP address observed?
![]({{site.baseurl}}/assets/img/writeups-pop-3_4.png){:width="100%"}

##### Answer: craftingalegacy.com
--- 

<div id='id-domain_names'/>

## Domain Names (Simple)
##### 3.0 Go to this report on app.any.run  and provide the first malicious URL request you are seeing, you will be using this report to answer the remaining questions of this task.
![]({{site.baseurl}}/assets/img/writeups-pop-3_4.png){:width="100%"}

##### Answer: craftingalegacy.com

##### 3.1 What term refers to an address used to access websites?
A name is easier to remember than a long string of numbers. An IP address is a lengthy string of numbers. As a result, a domain name is formed to give a simple way for us to communicate with internet-connected devices without having to remember complex numbers.
https://www.ietf.org/rfc/rfc1035.txt

##### Answer: domain name


##### 3.2 What type of attack uses Unicode characters in the domain name to imitate the a known domain?
DNS is limited to ASCII characters. This is where punycode comes in. It converts words that cannot be written in ASCII. For instance greek word characters. RFC 3492 described a way to apply this encoding to DNS labels using the a format.
The issue is that an attacker can easily launch a domain name that replaces some ASCII characters with Unicode characters. This is an IDN homograph attack, also referred to as a **Punycode attack.**
![]({{site.baseurl}}/assets/img/writeups-pop-5.png){:width="100%"}
https://www.rfc-editor.org/rfc/rfc3492

##### Answer: Punycode attack


##### 3.3 Provide the redirected website for the shortened URL using a preview: https://tinyurl.com/bw7t8p4u?

We can use Phishcheck is a tool to quickly gather information to a suspicious website. The link is redirected to tryhackme website. 
![]({{site.baseurl}}/assets/img/writeups-pop-6.png){:width="100%"}


##### Answer: https://tryhackme.com/
---

<div id='id-Host_artifacts'/>


## Host Artifacts (Annoying)

##### 4.0 What is the suspicious IP the victim machine tried to connect to in the screenshot above?
![]({{site.baseurl}}/assets/img/writeups-pop-ip.png){:width="100%"}
Based on logs, It is a Powershell script execution that connects to 35.214.215.3 by opening a socket on 1047.  192.168.75.22 is a RFC1918 address which more likely the host, and the c2 server's address is 35.214.215.33.
##### Answer: 35.214.215.33

##### 4.1 Use the tools introduced in task 2 and provide the name of the malware associated with the IP address?
Using Alien OTX, we can find associated files with the IP address
![]({{site.baseurl}}/assets/img/writeups-pop-7.png){:width="100%"}
The file associated with the IP is associated with the emotet malware familiy.
![]({{site.baseurl}}/assets/img/writeups-pop-8.png){:width="100%"}

##### Answer: emotet


#### 4.2 Using your OSINT skills, what is the name of the malicious document associated with the dropped binary?
![]({{site.baseurl}}/assets/img/writeups-pop-9.png){:width="100%"}
##### Answer: g_jugk.exe

##### 4.3 Use your OSINT skills and provide the name of the malicious document associated with the dropped binary?

Using Google we can find out there is Any.run report by search using the name of the binary.
![]({{site.baseurl}}/assets/img/writeups-pop-10.png){:width="100%"}
![]({{site.baseurl}}/assets/img/writeups-pop-11.png){:width="100%"}
![]({{site.baseurl}}/assets/img/writeups-pop-docname.png){:width="100%"}

##### 4.4 Answer: CMO-100120 CDW-102220.doc

---

<div id='id-Network_artifacts'/>


## Network Artifacts (Annoying)
##### 5.0 What browser uses the User-Agent string shown in the screenshot above?
Using https://developers.whatismybrowser.com/, we can easily determine the browser of the user agent which is Internet explorer.
![]({{site.baseurl}}/assets/img/writeups-pop-12.png){:width="100%"}

##### Answer: Internet Explorer

##### 5.1 How many POST requests are in the screenshot from the pcap file?
The pcap file contains six POST requests, according to wireshark.
![]({{site.baseurl}}/assets/img/writeups-pop-13.png){:width="100%"}

##### Answer: 6 

---

<div id='id-Tools'/>


##  Tools (Challenging)
##### 6.0 Provide the method used to determine similarity between the files? 
By making minor changes to their malware samples, adversaries can easily evade signature-based detection engines. Fuzzy hashing will use an algorithm such as SSDEEP to hash files into parts and then compare the similarity of those parts. It computes the similarity of two or more files. 

##### Answer: Fuzzy hashing

##### 6.1 Provide the alternative name for fuzzy hashes without the abbreviation?
##### Answer: context triggered piecewise hashes

---

<div id='id-ttps'/>

## TTPs (Tough)

##### 7.0 Navigate to ATT&CK Matrix webpage. How many techniques fall under the Exfiltration category?
![]({{site.baseurl}}/assets/img/writeups-pop-14.png){:width="100%"}

##### Answer: 9

##### 7.1 Chimera is a China-based hacking group that has been active since 2018. What is the name of the commercial, remote access tool they use for C2 beacons and data exfiltration?
Exfiltration Over c2 Channel Technique (T1041) Chimera used Cobalt Strike for their C2 beacons, which is a popular and preferred tool among threat actors.
![]({{site.baseurl}}/assets/img/writeups-pop-15.png){:width="100%"}

##### Answer: Cobalt Strike