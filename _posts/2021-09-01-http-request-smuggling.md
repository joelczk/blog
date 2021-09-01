---
layout: post
title: "My take on HTTP Request Smuggling"
author: "joelczk"
tags: Vulns
excerpt_separator: <!--more-->
---

During one of my research sessions over the last couple of days, I've come across a new vulnerability - HTTP Request Smuggling. However, I realized that this class of vulnerability is often overlooked and thus, I've decided to write an article about it. 
<!--more-->

## Introduction to HTTP Request Smuggling

As we all know, every website relies on load balancers, CDNs or reverse proxies to manage incoming HTTP requests over 1 single connection. In a usual scenario, users will first send a request to our load balancers or reverse proxies (which will be referred to as "front-end servers" for simplicity) which will then be forwarded to the backend servers that will then execute the application logic.

However, this gives rise to the inconsistencies in the way the front-end server and the backend server processes the requests from the senders, which could then be leveraged to interfere with how the web site processes the sequences of HTTP requests. This is exploit is what we termed as HTTP Request Smuggling.

## Background Information

Before we dive into the technical details of how HTTP Request Smuggling works, we will first have to understand the 2 types of HTTP headers that are exploited by malicious actors, namely `Content-Length` header and `Transfer-Encoding` header. 

The main purpose of the `Content-Length` header is to define the size of the request body in bytes, while the main purpose of the `Transfer-Encoding` header is to send the request body in chunks, which are seperated by newline. 

Apart from that, it is essential to understand that there are several pre-requisites that has to be fulfilled for the exploit to work:
1. The front-end server and the back-end server processes where a request ends differently
2. Front-end server forwards several HTTP requests to the backend server over the same network connection. However, this would be usually be fulfilled as this is much more efficient.

## How do Request Smuggling work?

HTTP Request Smuggling would then arise when an attacker sends a single malicious request as shown in the diagram below, but that malicious request is interpreted as 2 different requests by the back-end server. 

Such an exploit is considered to be criticial to the web application as it allows malicious actors to bypass security controls which allows them to gain access to sensitive information that could potentially result in account takeover and directly compromise other users.

![Request Smuggline illustration](../assets/request_smuggling/smuggline_example.PNG)

## Types of Request Smuggling attacks

1. CL-TE attack

In this attack, the front-end server processes the `Content-Length` header and the back-end server processes the `Transfer-Encoding` header. 

As a result, the front-end server will take the request to be 13 bytes long and process to the end of SMUGGLED. However, the back-end server will only process the first chunk (but this chunk is taken to be zero-length), so it will then treat SMUGGLEd as the start of the next request. 

```
GET / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

2. TE-CL attack

In this attack, the front-end server processes the `Transfer-Encoding` header and the front-end server processes the `Content-Length` header.

As a result, the front-end server will process the first chunk (this chunk is taken to be size of 8 bytes) up till SMUGGLED. It will then continue to process the second chunk (this chunk is taken to be of zero-length) and is treated as a terminating request. However, the back-end server will think that size of the request body is only 3 bytes long and will only process until 8 while the remaining bytes are taken as the start of the next request

```
GET / HTTP/1.1
Host: vulnerable-site.com
Content-Length: 3
Tramsfer-Encoding: chunked

8
SMUGGLED
0
```

3. TE-TE attack

In this attack, both the front-end and the back-end server supports `Transfer-Encoding` header, but the headers in one of the servers can be obfuscated in a way such that they do not process the header. Afterwards, the remaining of the attack will take the form of either TE-CL or CL-TE, depending on whether the front-end or the back-end server can be induced to ignore the header.

Some of the common ways of obufuscating the header are as follows:

```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

## Prevention
1. Prioritize `Transfer-Encoding` header over the `Content-Length` header.
2. Disallowing requests with both `Transfer-Encoding` headers and `Content-Length` headers. Any requests with both headers should be returned with a status code of `400`.
3. Proper filtering of header values. TE-TE attacks can occur by creating malformed headers that are not properly processed by either the front-end or back-end servers. Both the front-end servers and the back-end servers should do a proper input filtering to reject malicious header variations. 