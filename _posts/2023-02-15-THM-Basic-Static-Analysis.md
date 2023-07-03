---
title: THM-Writeups Basic Static Analysis
categories: [Writeup tryhackme]
tags: [tryhackme, pentest]
---

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis-7.png){:width="100%"}

Learn basic malware analysis techniques without running the malware.

## Task 1 Introduction
1.0 Complete the pre-requisite rooms

Answer: No answer needed

## Task 2 Lab Setup 
2.0 Start the attached VM before proceeding

Username: `Administrator`  

Password: `letmein123!`

Answer: No answer needed

## Task 3 String Search
  
3.0 On the Desktop in the attached VM, there is a directory named 'mal' with malware samples 1 to 6. Use floss to identify obfuscated strings found in the samples named 2, 5, and 6. Which of these samples contains the string 'DbgView.exe'?

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis.png){:width="100%"}

Using Floss to extract strings of the binary 6 and findstr to print strings end in exe.

Answer: 6

## Task 4 Fingerprinting Malware

4.0 In the samples located at Desktop mal directory in the attached VM, which of the samples has the same imphash as file 3?

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis-1.png){:width="100%"}

Using ssdeep tool to generate fuzzy hashes for binary 3 and compare it to all binary under mal directory. We can see we have a match to binary 1. 

Answer: 1

4.1 Using the ssdeep utility, what is the percentage match of the above-mentioned files?

Answer: 93

## Task 5 Signature-based detection

Now let's use capa to analyse the file Desktop mal 4 and answer the following questions.

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis-2.png){:width="100%"}

5.0 How many matches for anti-VM execution techniques were identified in the sample?

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis-3.png){:width="100%"}

Answer: 86

5.1 Does the sample have to capability to suspend or resume a thread? Answer with Y for yes and N for no.

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis-4.png){:width="100%"}

Answer: Y

5.2 What MBC behavior is observed against the MBC Objective 'Anti-Static Analysis'?

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis-5.png){:width="100%"}

Answer: Disassembler Evasion::Argument Obfuscation [B0009.012]

5.3 At what address is the function that has the capability 'Check HTTP Status Code'?

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis-8.png){:width="100%"}

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis-9.png){:width="100%"}

Using capa -vv flag to show verbose we can see the address of the function that has capability of checking HTTP status code

Answer: 0x486921

## Task 6 Leveraging the PE header
  
6.0 Open the sample Desktop mal 4 in PEstudio. Which library is blacklisted?

![]({{site.baseurl}}/assets/img/2023-02-15-THM-Basic-Static-Analysis-6.png){:width="100%"}

Answer: rpcrt4.dll 

6.1 What does this dll do?

Answer: Remote Procedure Call Runtime  

## Task 7 Conclusion

7.0 Join the discussion on our social channels.

Answer:  No answer needed 

## References 
- https://tryhackme.com/room/staticanalysis1
