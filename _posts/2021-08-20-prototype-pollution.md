---
layout: post
title: "My take on Prototype pollution"
author: "joelczk"
tags: Vulns
excerpt_separator: <!--more-->
---

With the recent release of a new prototype pollution scanner on [Github](https://github.com/kleiton0x00/ppmap), I've seeing more and more issues related XSS caused by prototype pollution and guessed its time I write an article about it.
<!--more-->

## Basic knowledge about JavaScript
Before I dive into the technical causes of prototype pollution, let me introduce to 3 main terms that will be used quite frequently in this article - `Objects`, `Prototype` and finally, `__proto__`.

`Object` can be understood as a key-value pair in JavaScript, where the key is a string and the value can be anything (literally anything). For those familiar to Python, `Object` is in a sense similiar to our map or dictionary. Everything that we type in JavaScript is an `Object`. 

`Prototype` can be understood as an attribute that is related to an `Object` and is a mechanism used by JavaScript to inherit attributes or features from one `Object` to another. However, since we know that everything we use in JavaScript is also an `Object`, `Prototype` is also an `Object`.

`__proto__` is a prototype chain which refers to all the `prototypes` of an object and every single `Object` in JavaScript has `__prototype__` as their attribute. When `__prototype__` was implmented, it was meant to be created as a feature to support class inheritance etc. However, such a feature introduced a vulnerability in it, which is prototype pollution that we are going to talk about today.

## What is prototype pollution
Prototype pollution occurs when a malicious actor manipulates the `__proto__` either by adding new prototypes into `__proto__` or by modifying existing prototypes in `__proto__`. Since every `Object` has `__proto__` as their attribute, the addition of new prototypes/modification of existing prototypes are inherited by all the objects. The consequence of this would be that this opens up a new attack surface where malicious actors can actually inject malicious code to carry out Remote Code Execution Attacks or to cause Reflected XSS attacks by triggerring exceptions.

## Mitigations to prototype pollution
The first mitigation would be to use `Object.freeze`. Freezing any `Object` will prevent new `Prototypes` from being added to the `Object`. However, such a mitigation contains a risk of breaking any system, especially larger commerical sites where it may affect the inheritance of features or functionality between `Objects`

Another alternative would be to sanitize the inputs on our payloads such as our URLs, JSON input etc. to remove suspicious characters such as `__prototype__`.

One other alternative is to replace `Object` primitives with `Map`. However, this change might not be feasible to be implemented especially in commercial sites with large code base since this would mean a large change would have to be made to the code base which might pose the possibility of breaking the system.

## Conclusion
In the upcoming years, there is not plans to remove `__proto__` yet and so, prototype pollution is likely to continue to be widely exploited. In my own opinion, the best prevention against prototype pollution would still be a proper sanitization of client-side inputs to remove suspicious characters or payloads.