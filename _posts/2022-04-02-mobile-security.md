---
layout: post
title: "Mobile Security"
author: "joelczk"
tags: Vulns
excerpt_separator: <!--more-->
---

Well, it's been quite some time since my last post and recently I've been very much involved in doing mobile security and here comes my take on some of the (extremely) common vulnerabilities in the field of mobile security.
<!--more-->

## Introduction to mobile security
Mobile security as everyone knows would be the security of the applications that we download in our mobile phones. The proliferation of mobile phones also meant that mobile security has actually now a part and parcel of our daily lives. 

Before I make a dive into some of the commonly seen vulnerabilities in our mobile applications, I would like to quickly point out that whilst the impact of vulnerabilities found in mobile applications might not be as impactful as other vulnerabilties, the mobile vulnerabilities are actually more easily exploited due to the easy availability of tools to reverse-engineer the mobile applications.

Now that we have gotten all the basic information out of the way, let's dive into the mobile vulnerabilities!!

## Vulnerability #1 : Leaked API keys 
For one, this is actually a commonly-seen problems in many of the mobile applications because developers fail to realize that their mobile applications can actually be easily reverse-engineered to obtain these hardcoded API keys. 

Thankfully, most of the times these exposed API keys are mostly Google API keys which are not as exploitable due to the proper permissions that is being set on the Google API keys. However, in some specific cases these exposed Google API keys are overly-permissive which gives a malicious actor permissions to view the information on the relevant Firebase project or the permissions to modify information on the Firebase project. If the firebase project contains sensitive information or information related to any company's operations, this may cause a huge leakage of PIIs or a huge impact on the company's operations. 

In other cases, some of these exposed API keys may grant an attacker access to other 3rd party APIs that can then be used to generate links/urls with the company's domain which can then be furthur exploited for phishing attacks.

## Vulnerability #2 : Task Hijacking 
Task Hijacking is specific only to Android 10 and below and is also one of the more commonly found vulnerabilities in Android mobile applications that stems from a misconfiguration in the ```AndroidManifest.xml``` with the TaskControl features. 

Task Hijacking is made possible when the launch mode of the activity is set to ```singleTask```. This is due to the fact that if the Android system evaluates and thinks that there is a need to create a new activity instance, the Activity Manager Service will select a task to host the newly created instance by finding a "matching" task among the exisiting tasks. An activity will only "match" a task if they have the same task affinity. By specifying a malicious mobile application to have the same task affinity as our vulnerable mobile application, we can then cause the malicious mobile application to be launched instead of the vulnerable mobile applicaiton

We can quickly identify Task Hijacking vulnerabilities by searching for the following line in the ```AndroidManifest.xml``` file

```xml
android:launchMode="singleTask"
```

Thankfully, this vulnerability does not cause disastrous impact most of the time and can be easily mitigated by replacing the single task launch modes to other methods of launch modes.

## Vulnerability #3 : Insecure deep link handling
To start off with this, let me explain what are deep links in mobile applications. Deep links are essentially a link that can either take us to specific destination within the application or redirect us to a url. To identify deeplinks, we can analyze the ```AndroidManifest.xml``` file. If we are looking at an ```intent-filter``` with ```action```, ```category``` and ```data```, chances are we are looking at a deep link.

All of these explanation seems very complicated, let me break it down with a simple example below. 

```
<activity android:label="test" android:name="com.test.activity.MainActivity" >
    <intent-filter>
        <!-- URI format that resolves to the activity -->
        <data android:scheme="test" android:pathPattern=".*"/>
        <!-- so that intent filter can be reached from search engines -->
        <action android:name="android.intent.action.VIEW"/>
        <!-- required for intent filter to be accessible from a web browser -->
        <category android:name="android.intent.category.BROWSABLE"/>
        <!-- allows app to respond w/o need for component name -->
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

In the case above, the deep link scheme would be ```test://``` and the activity that supports this deep link would be ```com.test.activity.MainActivity```.

Now that we have explained what are deep links, let us dwelve into insecure deep links. Many a times, deep links are used together with web views to allow redirects to urls or to allow the contents of urls to be loaded into the mobile application. At the same time, there is also a tendency to no verify the domains of the urls that are being used and this will allow malicious actors to redirect victims to malicious sites and this could then be potentially be exploited for phishing.

Apart from that, this could also be exploited to load other activity in the mobile applications which may cause unintended user actions on the mobile application.

## Vulnerability #4 : Insecure web view due to a lack of verification on intent parameters
To start this off, let us understand what are web views and intents. Web views are basically web contents that are loaded into the mobile application. However, they also function similarly to a web browser where we can browse contents, click on contents or download content. Intent, on the other hand can be thought of a message that can be passed between components to perform an action on the screen.

One thing to take note about web views is that exported web views can also be reachable by other applications installed in the mobile device. To check if the web view is exported, the components have to be explicitly declared with the ```exported=True``` attribute in the ```AndroidManifest.xml``` configuration file.

Now that we know what are web views, let us dwelve deeper into insecure web views. Insecure web views are most commonly brought about by a lack of validation on the intent parameters. Consider the following snippet below, the intent parameter does not validate the ```uri``` parameter that is being passed to the webview. This presents a potential vulnerability as a malicious attacker can make use of this activity to modify the ```uri``` parameter that is passed to the webview which may eventually redirect the victim to another site.

In some of the scenarios, there may be additional permissions that are given to the webview such as the ability to execute javascript code or the ability to read user's files. This may then cause other consequences such as code execution ability or obtaining the information of other users.

However, at the same time, this vulnerability may not be reporducible on a non-rooted environment and may either require a rooted environment or be chained with other vulnerabilities such as Intent Injection

```java
// At onCreate()
Intent intent = getIntent();
if (intent != null) {
    this.uri = intent.getStringExtra("uri");
    this.title = intent.getStringExtra("title");
    this.EnableJavascript = intent.getBooleanExtra(Const.ENABLE_JAVASCRIPT, false);
}

// At loadUrlOnWebView()
WebView webView2 = this.webView;
webView2.loadUrl(this.uri + "?role=admin")
```

## Vulnerability #5 : Intent Injection
For intent injection, malicious actors are able to force the launch of non-exported components which may then cause the user to carry out unintended actions and in some cases, bypass the authentication process. However, this vulnerability has to be chained with the ability to launch arbitary urls via an insecure deep link or an exported activity.

To exploit this, all we have to do is to host the following url on an attacker-controlled page and visitng the page on an Android device will then lauch the unexported component

```html
<script>
location.href = "intent://evil#Intent;scheme=http;component=<apk name>/<unexported component name>;end";
</script>
```
