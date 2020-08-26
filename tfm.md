# Study of reverse engineering protections on Android applications

<div class="page"/>

## Objectives and environment

Reverse engineering protections are code checks that the developer inserts into the application in order to try to make it more difficult for an attacker (the reverse engineer) to understand how the application works, or to modify its logic. For example a banking application has to protect its business logic, their clients information and its own integrity to avoid an attacker modifying the application and distributing a malicious version. Note that malicious software usually also uses reverse engineering protections for the same reasons, since if the functioning of the application is unknown it is harder to detect and protect the users from them.

The main objective in this project will be to investigate about reverse engineering protections design and evasion on an Android environment. Since this is a very broad field, I will be investigating a limited number of possible protections, chosen with a popularity and usefulness criteria. It is also important to understand that the reverse engineering field is a constant battle between the developer and the reverse engineer, so it is not possible to describe all the new technologies and evasions developed constantly. Because of this, I will try to describe the basics in order to get a general knowledge of each protection.

<div class="page"/>

## Work methodology

For each of the chosen protections, i have:

* Found or developed an open source implementation of the control in order to fully understand how it works by developing it or understanding the source code
* Investigated a way to bypass said protection.
* Investigate on future improvements or alternative protections that could mitigate or prevent the bypass.

This scenario is not fully realistic, since an attacker in a real world scenario would not know the implementation of the control, making it more difficult. Nonetheless, since this is an educational project i consider this to be a good start.

### Tools

The tools used are pretty standard in the Android reversing community.

#### Frida Dynamic instrumentation toolkit

[Frida](https://frida.re/) is a very popular and powerful tool that allows us to hook into processes, modifying its flow and logic on the fly without the need to modify low-level code, or restart the application. This is very powerful when evading reverse engineering controls, Since they are often obfuscated and difficult to analyze statically.

#### Runtime Mobile Security (RMS)

[RMS](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security) is a Frida web interface that makes workflow much easier and quick.

#### Android emulator from Android SDK

The emulator allows us to test all the controls in a realistic scenario. The emulator was chosen over a real phone because some experiments require having a rooted phone, which is generally not safe to have on a personal phone that is used daily.

#### Burp Proxy

Burp is a proxy focused on attacking web communications, edit and repeating requests, decoding data, and more.

<div class="page"/>

## Work accomplished

I've chosen the following controls to study:

* root check
* emulator check
* certificate pinning
* binary obfuscation

These are four of the most usual controls that we can find implemented on applications that deal with sensitive information.

<div class="page"/>

:[root](root_detection/root.md)

<div class="page"/>

:[emulator](emulator_detection/emulator.md)

<div class="page"/>

:[certpin](certificate_pinning/certificate_pinning.md)

<div class="page"/>

:[obfuscation](obfuscation/obfuscation.md)

<div class="page"/>

## Results

afbaegg

<div class="page"/>

## Conclusions

afeagagea
