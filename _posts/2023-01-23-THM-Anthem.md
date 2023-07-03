---
title: THM-Writeups_Anthem
categories: [Writeup tryhackme]
tags: [tryhackme, pentest]
---

![]({{site.baseurl}}/assets/img/anthem.png){:width="100%"}

Exploit a Windows machine in this beginner level challenge.

## Task 1 Website Analysis

##### 1.0. Let's run nmap and check what ports are open.

![]({{site.baseurl}}/assets/img/thm-anthem-1.png){:width="100%"}

We can see the open ports using Nmap, which are http on port 80 and rdp on port 3389.

##### 1.1. What port is for the web server?

##### Answer: 80

##### 1.2. What port is for remote desktop service?

##### Answer: 3389

##### 1.3. What is a possible password in one of the pages web crawlers check for?

![]({{site.baseurl}}/assets/img/thm-anthem-2.png){:width="100%"}

Robots.txt usually contains interesting information that tells web crawlers and other web robots which parts of the website they can and can't visit. We can see here the possible password.

##### Answer:  UmbracoIsTheBest!

##### 1.4. What CMS is the website using?

![]({{site.baseurl}}/assets/img/thm-anthem-3.png){:width="100%"}

Using Wapapalyzer, we can determine that the website's CMS is Umbraco. 

##### Answer: Umbraco

##### 1.5. What is the domain of the website?
![]({{site.baseurl}}/assets/img/thm-anthem-4.png){:width="100%"}

By simply visiting the home page, we can see that the website's domain is anthem.com.

##### Answer: Anthem.com 

##### 1.6. What's the name of the Administrator  
![]({{site.baseurl}}/assets/img/thm-anthem-5.png){:width="100%"}
![]({{site.baseurl}}/assets/img/thm-anthem-6.png){:width="100%"}
![]({{site.baseurl}}/assets/img/thm-anthem-7.png){:width="100%"}

We found that the web app's archive directory uses the nursery rhyme "Solomon Grundy" to describe the admin.

##### 1.7. Can we find the email address of the administrator?
![]({{site.baseurl}}/assets/img/thm-anthem-8.png){:width="100%"}
![]({{site.baseurl}}/assets/img/thm-anthem-9.png){:width="100%"}
##### Answer: SG@anthem.com

## Task 2 Spot the flags
Our beloved admin left some flags behind that we require to gather before we proceed to the next task..

##### 2.0. What is flag 1?
![]({{site.baseurl}}/assets/img/thm-anthem-10.png){:width="100%"}
##### Answer: THM{L0L_WH0_US3S_M3T4}

##### 2.1. What is flag 2?
![]({{site.baseurl}}/assets/img/thm-anthem-11.png){:width="100%"}
##### Answer: THM{G!T_G00D}

##### 2.3 What is flag 3?
![]({{site.baseurl}}/assets/img/thm-anthem-12.png){:width="100%"}
##### Answer: THM{L0L_WH0_D15}

##### 2.4 What is flag 4?
![]({{site.baseurl}}/assets/img/thm-anthem-13.png){:width="100%"}
##### Answer: THM{AN0TH3R_M3TA}
## Task 3 Final Stage
Let's get into the box using the intel we gathered.

##### 3.1 Let's figure out the username and password to log in to the box.(The box is not on a domain)

We discovered that the rdp protocol is open. We can use Remmina to login and use the credentials we obtained previously.

##### Username: SG
##### Password: UmbracoIsTheBest!

##### 3.2 Gain initial access to the machine, what is the contents of user.txt?
![]({{site.baseurl}}/assets/img/thm-anthem-14.png){:width="100%"}
##### Answer: THM{N00T_NO0T}
![]({{site.baseurl}}/assets/img/thm-anthem-15.png){:width="100%"}
##### 3.3 Can we spot the admin password?
![]({{site.baseurl}}/assets/img/thm-anthem-16.png){:width="100%"}
![]({{site.baseurl}}/assets/img/thm-anthem-17.png){:width="100%"}
![]({{site.baseurl}}/assets/img/thm-anthem-18.png){:width="100%"}

The administrator's password is stored in C:\\backup\\restore.txt, which is hidden. To see it, simply click the hidden view button. To view the file contents, change the file permissions.
##### Answer: ChangeMeBaby1MoreTime
##### 3.4 Escalate your privileges to root, what is the contents of root.txt?
![]({{site.baseurl}}/assets/img/thm-anthem-19.png){:width="100%"}

The root flag can be found in the Desktop Directory.

##### Answer: THM{Y0U_4R3_1337}