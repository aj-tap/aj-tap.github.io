---
title: THM-Writeups Splunk-Basics
categories: [Writeup tryhackme]
tags: [tryhackme, pentest]
---

Learn the basics of Splunk.
## Task 3 Splunk Components 
3.0. Which component is used to collect and send data over the Splunk instance?

Answer: Forwarder

## Task 4 Navigating Splunk
4.0. In the Add Data tab, which option is used to collect data from files and ports?

Answer: Monitor

## Task 5 Adding Data 
5.0 Upload the data attached to this task and create an index "VPN_Logs". How many events are present in the log file?

![]({{site.baseurl}}/assets/img/THM-Splunk-basic.png)

Answer:  2,862

5.1. How many log events by the user **Maleena** are captured?  

![]({{site.baseurl}}/assets/img/THM-Splunk-basic-1.png)

Answer: 60

5.2. What is the name associated with IP 107.14.182.38?  
![]({{site.baseurl}}/assets/img/THM-Splunk-basic-2.png)

Answer: Smith

5.3. What is the number of events that originated from all countries except France?  
![]({{site.baseurl}}/assets/img/THM-Splunk-basic-3.png)

Answer:   2,814

5.4. How many VPN Events were observed by the IP 107.3.206.58?
![]({{site.baseurl}}/assets/img/THM-Splunk-basic-4.png)

Answer: 14

--- 
## References 
- https://tryhackme.com/room/splunk101