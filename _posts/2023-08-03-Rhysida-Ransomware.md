---
title: Malware Analysis Rhysida Ransomware
categories: [Malware_Analysis Reverse_Engineering]
tags: [Rhysida, ransomware, malware]
---

![]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware.jpg){: width="972" height="589" }
## Summary 
The Rhysida ransomware group uses phishing attacks to infiltrate their targets' networks. They deploy payloads on compromised systems using tools like Cobalt Strike or similar command-and-control frameworks. The gang's malware employs the ChaCha20 algorithm, but it is still in development and lacks certain features in other ransomware strains. The group threatens to publicly disclose the exfiltrated data, aligning with the methods commonly seen among modern multi-extortion groups.The group first came to public attention in May 2023, when their victim support chat portal was discovered using TOR (.onion). They disguise themselves as a "cybersecurity team," claiming to assist victims by hacking into their systems and exposing security flaws.

## Malware composition

| Filename | sha256|
|:---------|------:|
| fury.exe | 258ddd78655ac0587f64d7146e52549115b67465302c0cbd15a0cba746f05595 | 


![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-1.jpg){: width="972" height="589" }
_Figure 1 –  CFF Explorer and Detect it Easy shows MinGW (mingw32) was used to compile the sample, which was written in C++. It was unpacked and 418.00 KiB in size._

![]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-1.png{: width="972" height="589" }

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-2.jpg){: width="972" height="589" }
_Figure 2 –  The analysis indicates that the binary file consists of 9 sections. Notably, the ".data" section displays high entropy, that is likely packed or encrypted._

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-3.jpg){: width="972" height="589" }
_Figure 3 –  Yara detected functions like ThreadControl__Context, anti_dbg, and RijnDael_AES, indicating possible thread management, anti-debugging measures, and the use of Rijndael AES encryption within the binary. The YARA rules suggest specific patterns or characteristics targeted by the binary's behavior._

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-4.jpg){: width="972" height="589" }
_Figure 4 –  Capa result of Rhysida Ransomware: Obfuscation, shared modules for evasion, cryptography with pseudo-random sequences, Base64 and XOR encoding, file and directory discovery, and host system interaction for file handling, thread management, and process termination._

## Reverse Engineering
### Main Routine

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-5.jpg){: width="972" height="589" }
_Figure  5 – Main function graph of Rhysida Ransomware_

The Rhysida ransomware main routine is  a multi-threaded file processing application. It starts by initializing various data structures and resources required for file processing. It then imports an RSA key, registers AES encryption and CHC hashing algorithms. After the setup, it repeatedly runs a file processing loop using multiple threads. The application processes files in directories specified in the command-line arguments or all available drive letters if no arguments are provided. It calculates various statistics and keeps track of empty directories. The loop continues for a fixed number of iterations. Once the processing is complete, it frees up allocated resources and runs a PowerShell script to remove the application from the system if the command-line parameter dictates so. Finally, the routine returns 0 to indicate successful completion.

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-6.jpg){: width="972" height="589" }
_Figure  6 –  First routine of the ransomware  performs  several memory allocation and initialization operations._

The initial part of the ransomware code performs several tasks to set up data structures and initialize resources for subsequent program execution. It starts by obtaining the current time to seed the random number generator and retrieving the current working directory. The system information, including the number of processors, is gathered using GetSystemInfo(). Memory is then allocated for various data structures like which appear to be related to file queries and locking information. Mutexes are initialized using mutex_init() for synchronization purposes. Finally, a specific block of data is copied from a known location to a newly allocated memory address.

### Encryption Routine 


![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-7.jpg){: width="972" height="589" }
_Figure 7  – Overview of encryption routine of Rhysida Ransomware in IDA_

The Encryption routine of the ransomware sets up cryptographic functionalities. It begins by initializing the ChaCha20 pseudo-random number generator (PRNG) and defining its characteristics. Next, an RSA-4096 public key is imported, then registers the Advanced Encryption Standard (AES) cipher, known for its strong encryption capabilities. A constant named CIPHER is defined, signifying that AES will be the chosen cipher throughout the program. The process continues by enabling the Cipher Hash Construction (CHC) hash type, which allows using AES as a hash function. AES is then registered as the block cipher for the CHC hash. Finally, a constant HASH_IDX is defined, representing the CHC hash, providing a complete setup of cryptographic features. The encryption modules in the Rhysida ransomware payload were created by the authors of the ransomware using the open-source library **LibTomCrypt**.

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-8.jpg){: width="972" height="589" }
_Figure  8 – Overview of chacha20 pseudo-random number generator (PRNG) function in IDA_

The initialize_PRNG function is responsible for initializing a pseudo-random number generator (PRNG) based on the ChaCha20 cipher algorithm. It first sets the PRNG index by calling get_PRNG_index with a pointer to the PRNG implementation, and if the index is -1, it indicates that the PRNG implementation is not available, leading to the function returning an error code. Next, it starts the initialization process of the ChaCha20 PRNG with the provided seed, and if this initialization fails, the function returns an error. The function then checks if the PRNG is ready for use, and if not, it returns another error code. To add additional unpredictability, the function generates a 40-byte entropy buffer filled with random bytes and adds it to the PRNG state. If adding entropy fails, it returns an error. After that, it generates a random value and allocates memory of that size. Using this memory block, it updates the PRNG state with additional randomness. Finally, the allocated memory is freed, and the function returns a success code, indicating that the ChaCha20 PRNG has been successfully initialized and is ready for generating pseudo-random numbers based on the provided seed.

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-9.jpg){: width="972" height="589" }
_Figure 9 – RSA Import routine decoded code using IDA_

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-10.jpg){: width="972" height="589" }
_Figure  10 – RSA public key and CriticalBreachDetected.pdf in memory dump using x64 debugger and HxD tool_

The rsa_import function is responsible for importing an RSA key pair. It takes key_data, a2, and rsa_key as input parameters, where key_data represents the raw RSA key data, a2 is the size of the data, and rsa_key is a pointer to the location where the imported key will be stored. The function first validates the input parameters and initializes the RSA key. It then allocates a temporary buffer to hold some intermediate data. Next, it attempts to import the RSA key data using the sub_424880 function and performs various RSA operations to validate and set up the key. If all operations are successful, the rsa_key is marked as valid. The function returns an error code to indicate the success or failure of the key import process. It's worth noting that some parts of the code may be dependent on external RSA-related libraries or functions, which are not shown in this code snippet.

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-11.jpg){: width="972" height="589" }
_Figure 11  – When keys are encrypted with RSA, the Cryptographic Hash Construction (CHC) hash is used to generate cipher Initialization Vectors (IVs)_

### Encryption Process of the drive 

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-12.jpg){: width="972" height="589" }
_Figure  12 – Decompiled code of encryption process routine of the ransomware._

The ransomware sets the AES key size to 32 bytes and initializes various global statistics and flags required for encryption. It then starts multiple threads, each representing a processor on the system, to enable parallel file processing. These threads will execute the function processFiles_Encrypt to encrypt the files concurrently. Once the file is encrypted it will add following extension

file_name.rhysida

The ProcessFiles_Encrypt function processes files and checks if they are encrypted. If a file is found to be unencrypted, it increments a global statistics counter for unencrypted files (global_statistics[1]) and invokes the possible_enc_func to perform some encryption-related task on the file. The function is likely part of a larger program that aims to process and secure files by identifying and possibly encrypting unencrypted ones.

The OpenDriveDirectory function processes files and directories located on the system's drives. It begins by retrieving information about the system's processors using the GetSystemInfo function and creates multiple threads to process files concurrently. The function seems to traverse through the files and directories on the drives, and it may be designed to perform specific file operations on them. The program processes all directories on the system starting from A to Z then iterates through the files in these directories and performs encryption operations using the chosen cryptographic functions.

### Wiper Routine 

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-13.jpg){: width="972" height="589" }
_Figure 13  – Powershell script Wipe routine_

Once the processing is complete, it frees up allocated resources and runs a command cmd which launches a hidden PowerShell session, waits for 500 milliseconds, and then attempts to forcefully remove an item specified by its path. The use of a hidden PowerShell window makes it less noticeable to the user, and the forced removal ensures that no confirmation prompt is shown before deleting the specified item. Finally, the routine returns 0 to indicate successful completion.


![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-14.jpg){: width="972" height="589" }
_Figure 14  – Set Wallpaper_

The last routine sets a custom wallpaper for the user's desktop. It first creates an image block with the specified dimensions and fills it with a character value (likely to generate a simple background pattern). Then, it reads the Arial font file to prepare for drawing text on the wallpaper. The function calculates the size and position of the text lines based on the provided text content. It then draws the text onto the image block with the specified font size. Afterward, it saves the image block as a JPEG file named "**bg.jpg)**" in the "**C:/Users/Public/**" directory. Next, the routine executes a series of system commands using **cmd.exe** to modify the Windows Registry entries related to desktop wallpaper settings. It deletes any existing wallpaper settings and adds new entries to specify the custom wallpaper file and set wallpaper style options. Finally, the function updates the desktop wallpaper using the **rundll32.exe** command, effectively setting the custom wallpaper for the user's desktop.


## Dynamic Analysis (Behavioral Analysis)
### Process tree 

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-15.jpg){: width="972" height="589" }
_Figure 15 - depicts the process tree illustrating the execution of the Rhysida Ransomware.
The process launches multiple instances of "cmd.exe" (Command Prompt) to execute various commands and modify registry settings. The "reg.exe" utility is used within the "cmd.exe" instances to perform registry operations. The tree shows that registry keys related to desktop wallpaper settings are being manipulated. The "Wallpaper" and "WallpaperStyle" values under "HKCU\\Control Panel\\Desktop" and "HKLM\\Software\Microsoft\\Windows\CurrentVersion\\Policies\\System" are modified. Additionally, the "NoChangingWallPaper" value under "HKCU\\Software\\Microsoft\Windows\\CurrentVersion\\Policies\\ActiveDesktop" and "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" is set to "1" which may prevent wallpaper changes. A "rundll32.exe" process is invoked to update per-user system parameters, potentially to apply the wallpaper changes. Finally, a hidden PowerShell script is launched to remove the "fury.exe" file located in a temporary directory._

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-16.jpg){: width="972" height="589" }

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-17.jpg){: width="972" height="589" }
_Figure 16 - shows the Rhysida Ransomware launching with a cmd.exe window. The ransomware proceeds to navigate through all files on all local drives. However, Rhysida excludes encryption from the following directories: : $Recycle.Bin, Boot, Documents and Settings, PerfLogs, Program Files, Program Files (x86), ProgramData, Recovery, System Volume Information, Windows, and $RECYCLE.BIN._

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-18.jpg){: width="972" height="589" }
_Figure 17 - The Rhysida ransomware-infected computer's wallpaper_

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-19.jpg){: width="972" height="589" }
_Figure 18 -  victims receive instructions to contact the attackers through a TOR-based portal, using the Unique ID provided in the ransom notes._

![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-20.jpg){: width="972" height="589" }
_Figure 19 - the Rhysida TOR-based Portal prompts the victim to enter their unique ID, which they obtained from the ransom note._


![Desktop View]({{site.baseurl}}/assets/img/2023-08-03-Rhysida-Ransomware-21.jpg){: width="972" height="589" }
_Figure 20 –  Rhysida TOR-based Payment Victim Portal allowing them to give the attackers more information for authentication and contact details._

## **Executed Commands**

|**Image path**|**Process args**|
|---|---|
|C:\Windows\system32\cmd.exe|/c cmd.exe /c reg delete "HKCU\Contol Panel\Desktop" /v Wallpaper /f|
| |/c cmd.exe /c reg delete "HKCU\Contol Panel\Desktop" /v Wallpaper /f|
| |/c cmd.exe /c reg delete "HKCU\Conttol Panel\Desktop" /v WallpaperStyle /f|
| |/c cmd.exe /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v NoChangingWallPaper /t REG_SZ /d 1 /f|
| |/c cmd.exe /c reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v NoChangingWallPaper /t REG_SZ /d 1 /f|
| |/c cmd.exe /c reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "C:\Users\Public\bg.jpg)" /f|
| |/c cmd.exe /c reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v Wallpaper /t REG_SZ /d "C:\Users\Public\bg.jpg)" /f|
| |/c cmd.exe /c reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v WallpaperStyle /t REG_SZ /d 2 /f|
| |/c cmd.exe /c reg add "HKCU\Control Panel\Desktop" /v WallpaperStyle /t REG_SZ /d 2 /f|
| |/c rundll32.exe user32.dll,UpdatePerUserSystemParameters|
| |/c start powershell.exe -WindowStyle Hidden -Command Sleep -Milliseconds 500; Remove-Item -Force -Path "C:\Users\admin\AppData\Local\Temp\C:\Users\admin\AppData\Local\Temp\fury.exe" -ErrorAction SilentlyContinue;|


## Indicators of compromise 
### Host-based Indicators 

**File indicators:**

|**Name**|**Type**|**Hash (sha256)**|**Location on Disk**|**Description**|
|---|---|---|---|---|
|fury.exe|EXE|258ddd78655ac0587f64d7146e52549115b67465302c0cbd15a0cba746f05595|C:\Users\user \Desktop\|Ransomware binary|
|**CriticalBreachDetected.pdf**|PDF|7a00a9f4ffd1b2149deacecf85f2e8da93468f8448383352ef6713ba062e6cc5|A-Z Drive all of the directory accessed by the ransomware|Ransom|

**Registry path:**
```
HKEY_LOCAL_MACHINE\Software\Microsoft\LanguageOverlay\OverlayPackages\en-US
HKU\S-1-5-21-4270068108-2931534202-3907561125-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.exe\OpenWithProgids\exefile
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\fury (2).exe
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Segment Heap
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\GRE_Initialize
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MUI\Settings
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Display
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Error Message Instrument\
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\FileSystem\
```

### Network Indicators 

|**Domain/IP**|**Port**|
|---|---|
|**rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad[.]onion**|443|
|**131[.]107[.]255[.]255**||
|**209[.]197[.]3[.]8**||

### Appendices 
#### Yara Rules
```
rule Rhysida_fury {

   meta:

      description = "Rhysida - file fury.exe"

      author = "@aj-tap"

      date = "2023-08-04"

      hash1 = "258ddd78655ac0587f64d7146e52549115b67465302c0cbd15a0cba746f05595"

   strings:

      $x1 = "cmd.exe /c reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v Wallpaper /t REG_SZ /d \"C:\\User" ascii

      $x2 = "cmd.exe /c reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v Wallpaper /t REG_SZ /d \"C:\\User" ascii

      $x3 = "cmd.exe /c reg add \"HKCU\\Control Panel\\Desktop\" /v Wallpaper /t REG_SZ /d \"C:\\Users\\Public\\bg.jpg)\" /f" fullword ascii

      $x4 = "cmd.exe /c start powershell.exe -WindowStyle Hidden -Command Sleep -Milliseconds 500; Remove-Item -Force -Path \"" fullword ascii

      $x5 = "cmd.exe /c reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v WallpaperStyle /t REG_SZ /d 2 /f" fullword ascii

      $x6 = "cmd.exe /c reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\" /v NoChangingWallPaper /t REG" ascii

      $x7 = "cmd.exe /c reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\" /v NoChangingWallPaper /t REG" ascii

      $x8 = "cmd.exe /c reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\" /v NoChangingWallPaper /t REG" ascii

      $x9 = "cmd.exe /c reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\" /v NoChangingWallPaper /t REG" ascii

      $x10 = "rundll32.exe user32.dll,UpdatePerUserSystemParameters" fullword ascii

      $x11 = "cmd.exe /c reg add \"HKCU\\Control Panel\\Desktop\" /v WallpaperStyle /t REG_SZ /d 2 /f" fullword ascii

      $x12 = "cmd.exe /c reg delete \"HKCU\\Conttol Panel\\Desktop\" /v WallpaperStyle /f" fullword ascii

      $x13 = "cmd.exe /c reg delete \"HKCU\\Contol Panel\\Desktop\" /v Wallpaper /f" fullword ascii

      $s14 = "It's vital to note that any attempts to decrypt the encrypted files independently could lead to permanent data loss. We strongly" ascii

      $s15 = "It's vital to note that any attempts to decrypt the encrypted files independently could lead to permanent data loss. We strongly" ascii

      $s16 = "Rest assured, our team is committed to guiding you through this process. The journey to resolution begins with the use of the un" ascii

      $s17 = "Rest assured, our team is committed to guiding you through this process. The journey to resolution begins with the use of the un" ascii

      $s18 = "C:/Users/Public/bg.jpg)" fullword ascii

      $s19 = "Error cleaning up spin_keys for thread " fullword ascii

      $s20 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii

      uint16(0) == 0x5a4d and filesize < 1000KB and

      1 of ($x*) and all of them

}
```

#### Decompiled Code Snippets 
Main Function: 
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{

double v3;
unsigned int v4;
int aes_keysize; 
struct _SYSTEM_INFO SystemInfo; 
char DstBuf[268];
int v11; 
char *drive; 
int error; 
void *v14; 
void *thread_is; 
void *QUERY_FILE_THREAD_IDS; 
char *Destination; 
int v18; 
unsigned int drive_letter; 
int i; 
int threads; 

main(argc, argv, envp);
v4 = time64(0i64);
srand(v4);
getcwd(DstBuf, 260);
GetSystemInfo(&SystemInfo);
num_processors = SystemInfo.dwNumberOfProcessors;
prngs = malloc(17648i64  *  (int)SystemInfo.dwNumberOfProcessors);
PRNG_IDXS = malloc(4i64  *  num_processors);
QUERY_FILE_THREAD_IDS = malloc(8i64  *  num_processors);
thread_is = malloc(4i64  *  num_processors);
QUERY_FILE_POSS = malloc(4i64  *  num_processors);
QUERY_FILES = malloc(8i64  *  num_processors);
QUERY_FILE_LOCKEDS = malloc(4i64  *  num_processors);
MUTEXES = malloc(8i64  *  num_processors);
mutex_init(&MUTEX_PRNG, 0i64);
for ( threads = 0;
threads < num_processors;
++threads ) {
    mutex_init((char  * )MUTEXES  +  8  *  threads, 0i64);
     * ((_DWORD  * )QUERY_FILE_POSS  +  threads) =  - 1;
    v5 = (void **)((char  * )QUERY_FILES  +  8  *  threads);
     * v5 = malloc(0x2000ui64);
    for ( i = 0;
    i <= 1023;
    ++i ) {
        v6 = (void **)( * ((_QWORD  * )QUERY_FILES  +  threads)  +  8i64  *  i);
         * v6 = malloc(0x1000ui64);
    }

     * (_DWORD  * )(4i64  *  threads  +  QUERY_FILE_LOCKEDS) = 0;
     * ((_DWORD  * )thread_is  +  threads) = threads;
}

v14 = malloc(0x18ui64);
sub_416556((unsigned int)argc, argv, v14);
qmemcpy(mp_ltc_name, &off_45F7E0, sizeof(mp_ltc_name));
if ( !(unsigned int)initialize_PRNG((__int64)&unk_46EE60, &dword_46EE04) )  {
    for ( threads = 0;
    threads < num_processors;
    ++threads ) {
        if ( (unsigned int)initialize_PRNG((__int64)prngs  +  17648  *  threads, (_DWORD  * )PRNG_IDXS  +  threads) )         goto LABEL_45;
    }

    if ( !(unsigned int)rsa_import((__int64)&key_data, key_size, (__int64)&rsa_key) )  {
        error = register_cipher((__int64  * )&ptr_aes_enc_desc);
        if ( !error )  {
            Cipher = Find_Cipher("aes");
            if ( Cipher !=  - 1 )  {
                error = register_hash(&ptr_aChcHash_0);
                if ( !error )  {
                    error = chc_register(Cipher);
                    if ( !error )  {
                        HASH_IDX = find_hash("chc_hash");
                        if ( HASH_IDX !=  - 1 )  {
                            aes_keysize = 32;
                            error = rijndael_keysize(&aes_keysize);
                            if ( !error )  {
                                for ( dword_4733D0[0] = 1;
                                dword_4733D0[0] <= 1;
                                ++dword_4733D0[0] ) {
                                    global_statistics[0] = 0;
                                    global_statistics[1] = 0;
                                    global_statistics[2] = 0;
                                    global_statistics[3] = 0;
                                    global_statistics[4] = 0;
                                    global_statistics[5] = 0;
                                    QUERY_EMPTY_CIRCLES[0] = 0;
                                    QUERY_RUNNING = 1;
                                    for ( threads = 0;
                                    threads < num_processors;
                                    ++threads )                      pthread_create(                        (char  * )QUERY_FILE_THREAD_IDS  +  8  *  threads, 0i64, processFiles_Encrypt, (char  * )thread_is  +  4  *  threads);
                                    for ( threads = 0;
                                    threads < num_processors;
                                    ++threads )                      pthread_detach((char  * )QUERY_FILE_THREAD_IDS  +  8  *  threads);
                                    if ( **((_BYTE **)v14  +  1) )  {
                                        openDriveDirectory( * ((_QWORD  * )v14  +  1));
                                    } else {
                                        drive = (char  * )malloc(0x1000ui64);
                                        for ( drive_letter = 'A';
                                        (int)drive_letter <= 'Z';
                                        ++drive_letter ) {
                                            sprintf(drive, "%c:/", drive_letter);
                                            openDriveDirectory((__int64)drive);
                                        }

                                        free(drive);
                                    }

                                    v11 = 1280  *  num_processors;
                                    while ( v11 > QUERY_EMPTY_CIRCLES[0] )                      Sleep(0xAu);
                                    v18 = 0;
                                    while ( !v18 )  {
                                        v18 = 1;
                                        for ( threads = 0;
                                        threads < num_processors;
                                        ++threads ) {
                                            sub_442050((char  * )MUTEXES  +  8  *  threads);
                                            if (  * ((_DWORD  * )QUERY_FILE_POSS  +  threads) !=  - 1 )                           v18 = 0;
                                            sub_442320((char  * )MUTEXES  +  8  *  threads);
                                        }

                                        Sleep(0xAu);
                                    }

                                    QUERY_RUNNING = 0;
                                }

                            }

                        }

                    }

                }

            }

        }

    }

}

LABEL_45:  free(prngs);
free(PRNG_IDXS);
for ( threads = 0;
threads < num_processors;
++threads )    sub_4424C0((char  * )MUTEXES  +  8  *  threads);
free(QUERY_FILE_THREAD_IDS);
free(thread_is);
free(QUERY_FILE_POSS);
for ( threads = 0;
threads < num_processors;
++threads ) {
    for ( i = 0;
    i <= 1023;
    ++i )      free( * (void **)(8i64  *  i  +   * ((_QWORD  * )QUERY_FILES  +  threads)));
    free( * ((void **)QUERY_FILES  +  threads));
}

free(QUERY_FILES);
free(QUERY_FILE_LOCKEDS);
free(MUTEXES);
sub_4424C0(&MUTEX_PRNG);
if (  * ((_DWORD  * )v14  +  4) == 1 )  {
    Destination = (char  * )malloc(0x7FFui64);
    strcpy(      Destination, "cmd.exe /c start powershell.exe -WindowStyle Hidden -Command Sleep -Milliseconds 500; Remove-Item -Force -Path \"");
    strcat(Destination, DstBuf);
     * (_WORD  * )&Destination[strlen(Destination)] = 92;
    strcat(Destination, * (const char **)v14);
    strcat(Destination, "\" -ErrorAction SilentlyContinue;");
}

free( * (void **)v14);
free( * ((void **)v14  +  1));
free(v14);
Set_Wallpaper(v3);
if (  * ((_DWORD  * )v14  +  4) == 1 )  {
    system(Destination);
    free(Destination);
}

return 0;
}
```

--- 
## References
- <https://github.com/libtom/libtomcrypt>
- <https://malpedia.caad.fkie.fraunhofer.de/details/win.rhysida>
