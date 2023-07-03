---
title: THM-Writeup_Confidential
categories: [Writeup tryhackme]
tags: [tryhackme, pentest]
---
We got our hands on a confidential case file from some self-declared "black hat hackers"... it looks like they have a secret invite code available within a QR code, but it's covered by some image in this PDF! If we want to thwart whatever it is they are planning, we need your help to uncover what that QR code says.

##### Let's start our Ubuntu Vm Box and navigate to the home/ubuntu/confidential directory, where we can find the Repdf.pdf file.
![writeups_confidential-1]({{site.baseurl}}/assets/img/writeups_confidential-1.png){:height="450px" width="450px"}


##### It looks like our ubuntu Vm box has Libre Office Suite, Let's open the file using Libre draw office. 
![writeups_confidential-2]({{site.baseurl}}/assets/img/writeups_confidential-2.png){:height="450px" width="450px"}



##### It looks like the attacker didn't flatten the pdf. We can simply drag or delete the vector image.
![writeups_confidential-4]({{site.baseurl}}/assets/img/writeups_confidential-4.png){:height="450px" width="450px"}




##### Take a screenshot of the QR code, then decode it to retrieve the flag. 
![writeups_confidential-3]({{site.baseurl}}/assets/img/writeups_confidential-3.png){:height="450px" width="450px"}
