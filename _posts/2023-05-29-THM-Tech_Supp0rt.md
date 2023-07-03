---
title: THM-Tech_Support
categories: [Writeup tryhackme]
tags: [tryhackme, pentest]
---

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-20.png){:width="70%"}

Hack into the scammer's under-development website to foil their plans.

## Nmap Scanning 

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt.png){:width="70%"}

Based on the findings from Nmap, it appears that ports 22, 80, 139, and 445 are open. Now, we can proceed with the enumeration of the SMB (Server Message Block) protocol.

## SMB Enumeration 

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-1.png){:width="70%"}


![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-4.png){:width="70%"}

By utilizing the anonymous/guest account, we can gain access to the **websvr** directory in the SMB protocol. We should proceed to download the file named "enter.txt."

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-5.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-6.png){:width="70%"}

The file "enter.txt" holds personal notes belonging to the scammer.  Additionally, port 80 appears to host multiple websites, including WordPress and Subrion. Within the obtained information, we discovered credentials for Subrion along with a hint about a "magical formula." By utilizing the "magic recipe" feature in CyberChef, we can determine that the password was encoded in both Base58 and Base32 formats. Fortunately, decoding it using the appropriate tools should be a straightforward process.

## Test site of the scammer

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-2.png){:width="70%"}

## Word press 

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-13.png){:width="70%"}

## Subrion 4.2 panel 

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-7.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-11.png){:width="70%"}

Upon investigating, it was found that the Subrion version in use is v4.2.1. Further research indicates that this version is susceptible to CVE-2018-19422. Exploiting this vulnerability with the provided script will allow us to effortlessly obtain a shell. [exploit script](https://packetstormsecurity.com/files/162591)
```php 
<?php system($_GET['cmd']); ?>
```

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-10.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-9.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-12.png){:width="70%"}

To proceed with the attack, we can establish an HTTP server on our own attack box and exfiltrate the "linpeas.sh" script to the target machine. using the script we can enumerate and find ways to escalate privileges. 

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-14.png){:width="70%"}

Linpeas find out the credentials of admin of word press. 

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-16.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-15.png){:width="70%"}

We have gained access to the WordPress platform. Considering the possibility of password reuse by the scammer, we can explore the potential reuse of passwords in SSH keys.

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-17.png){:width="70%"}

With the credentials we acquired from WordPress, we can try using them to gain additional access. By inspecting the "**/etc/passwd**" file, we can identify the user accounts registered on the machine. In this case, we find that the user account is "**scamsite**." Utilizing the password obtained from WordPress, we can successfully log in to the SSH (Secure Shell) interface.

## Privilege escalation

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-18.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-29-THM-Tech_Supp0rt-19.png){:width="70%"}

Through our investigation, we discovered that the "**/usr/bin/iconv**" binary can be executed with sudo privileges. After researching in GTFO bins, we learned that if this binary is permitted to run as the superuser, it can potentially access the file system.

---
## References 
- [https://tryhackme.com/room/techsupp0rt1]()
- [https://gtfobins.github.io/gtfobins/iconv/]()
- [https://packetstormsecurity.com/files/162591]()
- [https://cyberchef.org/#recipe=From_Base58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',true)From_Base32('A-Z2-7%3D',false)From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=N3NLdm50WGRQRUpheGF6Y2U5UFhpMjR6YUZyTGlLV0NrIA]()