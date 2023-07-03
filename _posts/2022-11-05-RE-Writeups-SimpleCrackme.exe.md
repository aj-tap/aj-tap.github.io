---
title: SimpleCrackme.exe - Finding the Main function
categories: [Writeup crackmes]
tags: [crackmes, reverse_engineering]
---
![]({{site.baseurl}}/assets/img/SimpleCrackme/cat.gif)

```
File name: SimpleCrackMe.exe
Size: 19456(19.00 kB)
MD5: 5ca23d1110ac04a9ea1e54a1c7696065
SHA1: 23ae3c2a8ce88a21442ceaa83198f806c46b2eb8

entry point: 0000000140002210
Address of main function 1400012c0
Password string: 1ecc7dd7b9763028e119e5046268d922
```

---
#### Let's open Ghidra and examine the symbol table. Proceed to the binary's entry point. Then, launch Function Graph.(Window tab -> Function Graph)

![]({{site.baseurl}}/assets/img/SimpleCrackme/SimpleCrackme-1.png){:width="100%"}

![]({{site.baseurl}}/assets/img/SimpleCrackme/SimpleCrackme-2.png){:width="100%"}

#### Working backwards from the binary's entry point is one way to find the main function. Finding the return value 0 (the syscalls for exit).
https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-quit
```
# Code snippets of WinMain function which returns int value zero when it terminates
int __clrcall WinMain(
  [in] HINSTANCE hInstance,
  [in] HINSTANCE hPrevInstance,
  [in] LPSTR     lpCmdLine,
  [in] int       nShowCmd
);
```


![]({{site.baseurl}}/assets/img/SimpleCrackme/SimpleCrackme-3.png){:width="100%"}

#### This appears to be the main function because it pushes three arguments, which are the argc() count of the number of arguments and the argv() number of strings passing. We can also see the operands Test AL, AL and Mov EBX, EAX. which appears to be a return 0.
#### Let's rename this function as main 
---

![]({{site.baseurl}}/assets/img/SimpleCrackme/SimpleCrackme-5.png){:width="100%"}

![]({{site.baseurl}}/assets/img/SimpleCrackme/SimpleCrackme-6.png){:width="100%"}
#### The program compares two string values, one of which is a user-provided string from a buffer and the other of which is a password that can be seen by following the pointer. To follow the pointer simply right click and open reference in ghidra or open Defined strings. 
![]({{site.baseurl}}/assets/img/SimpleCrackme/SimpleCrackme-7.png){:width="100%"}
#### We can see here that the password string is located at 140003438, which is referenced and compared to the user input buffer.
#### Let's run the program and input the string password 
![]({{site.baseurl}}/assets/img/SimpleCrackme/SimpleCrackme-8.png){:width="100%"}

#### Summary 
#### Finding the main function can be difficult for beginners. This is especially true when the code is obfuscated and the symbol table is unavailable. Writing and compiling your own scripts will train your eye for this. I've included links below to websites where you can practice reverse engineering without having to set up a machine.

---
## References
-  https://godbolt.org/
- https://dogbolt.org/
