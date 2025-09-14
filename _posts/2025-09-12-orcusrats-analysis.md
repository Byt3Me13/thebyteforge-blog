---
layout: post
title: "Dissecting OrcusRAT: Watching a RAT Come Alive"
date: 2025-09-12 05:00:00 -0400
categories:
  - Malware Analysis
  - RATs
  - OrcusRAT
tags:
  - OrcusRAT
  - Reverse Engineering
  - Keylogger
  - Fake C2
  - XWorm
author: ByteForge
---

What I thought was a simple AsyncRAT sample turned out to be something far more dangerous: OrcusRAT. This week-long dive pulled me from static strings all the way to decrypted beacons, showing how quickly assumptions in malware analysis can unravel.

---
<div style="margin-bottom: 2em;"></div>

## Background

Why a RAT? Because they're everywhere. Modular, feature-rich, and often indistinguishable from "legit" admin tools at first glance. RATs are a perfect case study for training and intelligence sharing. 

I started by tracking open-source intelligence trends. A few months back, **AsyncRAT** was spiking in popularity, so I decided to grab a sample to study. Except, once I started analyzing it, things weren't what they seemed. 
<div style="margin-bottom: 2em;"></div>

---

## Static Analysis

My first stop was PeStudio, my go-to analysis tool. That's where the twist hit: I wasn't looking at AsyncRAT at all. I was staring down an **OrcusRAT** sample. 

This was a pivot moment. In malware analysis, sometimes your assumptions get overturned in minutes. I shifted gears, recalibrated my analysis flow, and prepared for a RAT with a difference feature set. 


<figure>
	<img src="{{ '/assets/images/orcusrat/pestudio-orcusrat.png' | relative_url }}">
</figure>

Next, I dropped the binary into **Detect-It-Easy** to check for signs of packing. Instead of just confirming Orcus, it flagged the sample as **XWorm**, specifically between versions 3.0 and 5.0. That changed the threat profile completely: from just remote control to potential self-propagation. 
In a real production environment, this could mean rapid lateral spread. 


<figure>
	<img src="{{ '/assets/images/orcusrat/die-orcusrat.png' | relative_url }}">
</figure>

Finally, pulling **strings** and **API imports** gave a preview of the RAT's toolbox:

#### API and Strings of Interest:

- **APIs:** `DownloadFile`, `HttpWebRequest`, `FromBase64String`, **`SetWindowsHookEx`**
- **Strings:** **`XLogger`**, **DDoS**, **Base64**, "SELECT * FROM Win32_VideoController", **`shutdown.exe /f /r /t 0`**

Even before detonation, the picture was clear. This wasn't just a "program." It was a surveillance and control toolkit. Designed to log keystrokes, capture data, and potentially disrupt its environment. With that gathered, we'll move onto Behavioral Analysis.

<div style="margin-bottom: 3em;"></div>

---
<div style="margin-bottom: 1em;"></div>
## Behavioral Analysis

After executing the sample for about 30 minutes in my isolated lab environment, I generated realistic user activity: typing into a text editor, creating MS Office documents, opening a browser, and even scripting a batch file to mimic admin behavior. 
<div style="margin-bottom: 2em;"></div>

---

### Artifacts

When I suspended execution, I shifted into forensics mode, hunting for what this sample left behind. That's when I found: 

`C:\Users\%USER%\AppData\Local\Temp\Log.tmp`

<figure>
	<img src="{{ '/assets/images/orcusrat/log-tmp-location.png' | relative_url }}" alt="OrcusRAT Log.tmp File Location">
</figure>

Opening `Log.tmp` revealed detailed **keylogging output**, complete with application context (e.g. `Report.docx - Word`).


<figure>
	<img src="{{ '/assets/images/orcusrat/orcus-keylog.png' | relative_url }}" alt="OrcusRAT keylogging user activity">
</figure>

This confirmed the RAT's active surveillance capability. It was capturing real-time keystrokes across apps, browsers, and editors. To simulate risk, I even mimicked entering fake credentials into a website. Orcus captured every keystroke. In a real-world compromise, that account would now be considered stolen. 

This highlights the danger of keyloggers. They bypass most authentication controls by stealing credentials *before* they're encrypted or protected. With valid usernames and passwords in hand, an attacker doesn't need exploits, they can just log in like a normal user.


---
#### Persistence:

Most malware wants to survive reboots. Surprisingly, Orcus didn't establish persistence.

I checked the usual persistence mechanisms: 

- Registry autorun keys
- Startup folders
- Scheduled tasks
- New services
  
All were clean. I even rebooted mid-execution. On restart, Orcus did not reload. Its presence was tied only to its running process. Once killed, it left no self-start mechanism behind. 

<div style="margin-bottom: 2em;"></div>
---
<div style="margin-bottom: 1em;"></div>
#### System Interaction

Orcus wasn't silent, though. While running, it:
- Created and wrote to `Log.tmp` continuously.
- Queried the Windows Registry, particularly for webcam keys.
- Read through the system hives, but never created new keys or values.


<figure>
	<img src="{{ '/assets/images/orcusrat/logtmp-created.png' | relative_url }}" alt="File System Creation of Log.tmp">
</figure>

<figure>
	<img src="{{ '/assets/images/orcusrat/reg-webcam.png' | relative_url }}">
</figure>
<figure>
	<img src="{{ '/assets/images/orcusrat/reg-write-open.png' | relative_url }}" alt="OrcusRAT constantly logging every keystroke to log.tmp">
</figure>

It queried system hives and webcam-related keys, suggesting surveillance checks, but never modified anything. These reads align with what we saw in the Static Strings. This is reconnaissance steps to understand the host's hardware and environment before activating heavier capabilities. 

Even without persistence, Orcus left behind forensics traces, most notably the active keylogger file. Every query, registry peek, and file write adds context to the story: the RAT was actively surveying the host, testing its environment, and preparing for deeper surveillance.  

<div style="margin-bottom: 2em;"></div>
---
<div style="margin-bottom: 2em;"></div>
### Network Behavior

Here's where things got interesting.

Instead of reaching out to an external IP or domain, the RAT attempted to connect to **192.168.178[.]20:4782**

<figure>
	<img src="{{ '/assets/images/orcusrat/traffic.png' | relative_url }}">
</figure>

That's a private IP address, meaning the RAT wasn't preconfigured to phone home to some external server. Instead, it maybe was looking for something local to its operator's environment. 

Since this sample came from a public repository, the context is unknown, but I have two theories: 

1. It was built for internal testing or development, explaining the private IP.
2. It was tailored to a specific victim's internal network. 

Either way, the takeaway is clear. The RAT attempted to connect in a very specific way, and without that environment present, it went quiet. 

---
<div style="margin-bottom: 2em;"></div>
### What We Know So Far

Here's the high-level wrap-up of the behavioral analysis: 
- The RAT successfully captured keystrokes. We have proof of active monitoring and data theft functionality via the `Log.tmp` file.
- It did not establish persistence, which was surprising. If the process was killed, it wouldn't survive a reboot. 
- It read registry keys, especially ones tied to the webcam, hinting at surveillance capability but it made no modifications. 
- It attempted network communications to a private IP address (`192.168.178[.]20:4782`). Since that IP didn't exist in my lab, the connection failed. 

So far, OrcusRAT is clearly capable of surveillance (keylogging, reconnaissance), but its configuration limited how far it could operate in my lab. To uncover what it was really designed to do, I needed to go deeper into the code. 

<div style="margin-bottom: 3em;"></div>
---
<div style="margin-bottom: 2em;"></div>
## Code Analysis

This is where we first meet OrcusRAT in action, the **entry point**. Where everything comes alive right after we run the executable. When I dropped OrcusRAT into dnSpy and traced execution, I landed in the `Main` function. From here, Orcus does a few important things right away: 

1. **Loads its Configuration**: This is where the RAT obtains it's configurations such as Encryption Key, Host/IP, Ports, etc. and functionality toggles. This is the brain telling the body what it's supposed to do. 
2. **Runs through Obfuscation Layers**: This is the part where a malware author tries to slow down malware analysts. Strings and code paths are scrambled and required time to understand how they worked and decrypting them. The snippet below (in `Settings`) looks like Base64, but it's actually wrapped in more layers of obfuscation that we'll decode/decrypt soon. 
3. **Initializes RAT Thread**: Lastly, we see the threads for where the RAT will begin it's keylogging activity (`XLogger`), background processes it needs, and network socket creation (`ClientSocket`).

We're now officially looking under the hood of OrcusRAT. From a static file to a running agent, this is where OrcusRAT truly comes alive.


<figure>
	<img src="{{ '/assets/images/orcusrat/main-entrypoint-orcusrat.png' | relative_url }}">
</figure>
<figure>
	<img src="{{ '/assets/images/orcusrat/setting.png' | relative_url }}">
</figure>

At first glance, the configuration strings inside the `Settings` module look like ordinary Base64. But don't be fooled, if you took those strings into a Base64 decoder, you'll just get gibberish. That's because these values aren't *just* encoded, they're also encrypted. OrcusRAT wraps its configuration in multiple layers. To understand this "gibberish", we need to replicate the RAT's own decryption routine.

---
<div style="margin-bottom: 2em;"></div>
### Configuration & Obfuscation: Cracking the Cipher

Here's where the cryptography part comes into play. Orcus doesn't store its configuration in plaintext. Instead it hides the values Hosts, Port, KEY, Groub (probably meant Group*) by wrapping them first in **Base64**, then encrypting them all with **AES-256** in **ECB Mode**.


<figure>
	<img src="{{ '/assets/images/orcusrat/algorithm-aes.png' | relative_url }}" alt="AES Alogrithm Process">
</figure>

As AES is a symmetric cipher, you need the right key in order to decrypt the data. Orcus doesn't hardcode this key directly. Instead, it **derives it from the mutex string** we saw earlier (`LYBiIvqxHQpkC5on`). The process looks like this: 
1. Take the mutex and run it through **MD5 hashing**, which produces a 16-byte hash.
2. Duplicate that 16-byte value to make a 32-byte key (AES-256 requires 32-bytes).
3. Use that derived key with **AES-256 in ECB mode**, and the data decrypts into plaintext. 

Because **ECB mode** doesn't use an initialization vector (IV), the derived key alone is enough to unlock the strings. Once we replicate this routine, we can unfold Orcus's true configuration.

---
#### Configuration Decryption Routine

Base64 String
<div style="margin-bottom: 0.2em;"></div>
↓ (Convert.FromBase64String)
<div style="margin-bottom: 0.2em;"></div>
AES-256 Decryption (ECB Mode)
<div style="margin-bottom: 0.2em;"></div>
↓ (Key required)
<div style="margin-bottom: 0.2em;"></div>
Key = MD5(mutex - LYBiIvqxHQpkC5on) → 16 bytes → duplicated to 32 bytes
<div style="margin-bottom: 0.2em;"></div>
↓  
Decrypted Configuration (Host, Port, Key, SPL, Groub, USBNM)

---
<div style="margin-bottom: 1em;"></div>
Now at first, I did debug this directly. But then something about the KEY made me question myself... and that kicked off the deep dive into manual decryption. 


#### Configuration Pipeline

To show my understanding of how OrcusRAT generated its AES key, I rebuilt the same routine in Python. 


<figure>
	<img src="{{ '/assets/images/orcusrat/python-key.png' | relative_url }}" alt="Python Key Derivation Script">
</figure>


<div style="margin-bottom: 2em;"></div>
With that derived key, we now have everything we need to decrypt the RAT's configuration values. And to make the decryption easier to visualize, I've put them into CyberChef for the actual decoding process: 


<figure>
	<img src="{{ '/assets/images/orcusrat/decrypt-cyberchef-orcusrat.png' | relative_url }}">
</figure>

Here's the payoff: running the encryption strings through CyberChef with the derived AES key revealed the RAT's true configuration. Notice the hardcoded addresses: 127.0.0.1 and **192.168.178.20** over port **4728**. Clearly not random, these are operator defined endpoints! 

And then, the **KEY**. Yes, really. This was the point where I nearly lost it. Debugging showed me the outcomes automatically, but when I saw *that*, I refused to just accept it. I *had* to go back and manually deobfuscate and decrypt everything to confirm it wasn't some debugger trick. And sure enough, the RAT is secured by the **KEY: <123456789>**. After all that cryptography, it turned out the real obfuscation was me questioning my sanity. 

On top of that, We see the family markers like `<Xwormmm>` and `XWorm V5.3`, perfectly lining up with what Detect-It-Easy hinted at earlier. And lastly, USB.exe is another capability we haven't discovered. This means that if the RAT sees a USB on the device, it can enumerate it. 


<figure>
	<img src="{{ '/assets/images/orcusrat/before-after-orcus-2.png' | relative_url }}">
</figure>


----
<div style="margin-bottom: 2em;"></div>
### Core Capabilities

After cracking the obfuscation layers, the code reveals more of what OrcusRAT is capable of:


- `XLogger`: Hooks into Windows APIs (`SetWindowsHookEx`) to capture keystrokes.
	- This matches the `Log.tmp` keylog file we saw earlier in Behavioral Analysis.
	
<figure>
	<img src="{{ '/assets/images/orcusrat/xlogger-orcusrat.png' | relative_url }}">
</figure>
- `Messages`: The RAT's remote control command handler: shutdowns, reboots, PowerShell execution, webcam spying, and even DDoS.
	- This explains the system call traces we observed and the potential webcam registry that were read.
<figure>
	<img src="{{ '/assets/images/orcusrat/messages-orcusrat.png' | relative_url }}">
</figure>
<figure>
	<img src="{{ '/assets/images/orcusrat/messages-orcus-2.png' | relative_url }}">
</figure>
- `Helper`: Handles thread management and AES routines, plus glue logic for communication.
	- This underpins the obfuscation we decrypted and the RAT's ability to maintain long-running activity. 
<figure>
	<img src="{{ '/assets/images/orcusrat/helper-orcusrat.png' | relative_url }}">
</figure>
- `Uninstaller`:  Deletes its own executable and artifacts when instructed. 
	- Designed to remove any traces of its existence when instructed. *Sneaky little RAT*. 
<figure>
	<img src="{{ '/assets/images/orcusrat/uninstaller-orcusrat.png' | relative_url }}">
</figure>

What matters here is alignment. The modules in the code directly explain the artifacts we observed. Keylogging, registry reconnaissance, and even destructive potentials. Static analysis revealed the design, while behavioral analysis confirmed it in action. But now we come to the last module we haven't gone over.


---
<div style="margin-bottom: 2em;"></div>

### ClientSocket

All the modules we saw in Orcus from keylogging, remote commands, plugins, all rely on one critical piece: the **ClientSocket** module. This is the RAT's communication hub. It takes the configuration we decrypted earlier (host, port, and key), spins up a TCP socket, and begins sending traffic. It even includes logic for ping/pong messages and retries if it gets disconnected. Before sending its first beacon, it collects a bundle of system information; CPU, RAM, GPU, Antivirus, and even whether the users is running with admin privileges, along with if it can spread across a network. This is where this sample pivots from just being a program on disk to being a full fledge remote-controlled agent. 

<figure>
	<img src="{{ '/assets/images/orcusrat/clientsocket-orcusrat.png' | relative_url }}">
</figure>

This `ClientSocket` logic explains what we saw in Behavioral Analysis: the repeated attempts to connect to **192.168.178[.]20:4782**. With the configuration decrypted, the network behavior makes complete sense. 


---
<div style="margin-bottom: 1em;"></div>

## But Now What?

The hardcoded IP didn’t exist in my lab, but in a controlled environment, I had the freedom to rewire things and see what would happen if it did.  

<div style="margin-bottom: 4em;"></div>

---
<div style="margin-bottom: 2em;"></div>
### Thinking with Networks

I reassigned REMnux to resolve 192.168.178[.]20 and forced outbound requests to loop back into my controlled environment with `/etc/hosts`.  

- **INetSim** handled the basics (DNS, HTTP), fooling Windows into believing it had a real internet connection.  
- A **Python HTTP server** stood in as the Fake Command and Control (C2), delivering just enough fake responses to keep Orcus engaged.   

The results?  

---

### The RAT Speaks


<figure>
	<img src="{{ '/assets/images/orcusrat/encrypted-comm.png' | relative_url }}">
</figure>

Once Orcus connected to my Fake C2, the silence broke. It began firing AES-encrypted payloads every ~15 seconds. A steady heartbeat-like beacon declaring that *"I'm alive! I'm ready, and I've got a host waiting to be compromised."* 

But, what is it truly saying?

#### Decrypting the Traffic

Remember the AES routine from the `Helper` module? By applying the same decryption logic from the configuration (`AlgorithmAES`) to the live traffic, the opaque blobs can be cracked open. What once looked like meaningless ciphertext resolved into clear, structured logs. Evidence of Orcus beaconing and reporting in real time.

 
<figure>
	<img src="{{ '/assets/images/orcusrat/decrypt-comms.png' | relative_url }}" alt="Decrypted beacon showing Xwrommm tag">
</figure>

That's where we see the `<Xwormmm>` tag and `XWorm V5.3` marker we uncovered from the configuration in the live traffic. The very first beacon dumped host reconnaissance about my system; OS version, RAM, CPU, GPU, AV status, worm version, and even UAC checks (all reporting `False`, unsurprisingly in my lab).

This is OrcusRAT in its natural state. Beaconing, reporting, and probably awaiting instructions. It passively watched as I went about *"normal"* activity; opening a browser, editing a Word document, working in Notepad++, and even watching me launch PowerShell in an Administrator session. Everything I did, it logged and relayed. 

Now imagine that same capability in a production environment. An operator wouldn't just be watching. They could chain this surveillance into real attacks. Stealing credentials, escalating privileges, or moving laterally across a network. 

This brings us to the bigger picture. When we stitch together static analysis, behavioral findings, and code analysis with decrypting the network traffic. OrcusRAT reveals its true capabilities. 

---
<div style="margin-bottom: 2em;"></div>

## Summary

OrcusRAT isn't just a keylogger. It's a modular surveillance and control platform with worm-like capabilities, encrypted communications, and operator-level features. 

- Captures **every keystroke** into `Log.tmp`.  
    _(T1056.001 Input Capture: Keylogging, T1074.001 Data Staged: Local Data Staging)_
 - Performs **host reconnaissance**: OS version, CPU, RAM, GPU, AV, UAC status.  
    _(T1082 System Information Discovery, T1518 Software Discovery)_
 - Uses **AES-encrypted beacons** to report back every ~15s.  
    _(T1071.001 Application Layer Protocol: Web Protocols)_
 - Executes **remote commands**: PowerShell, shutdown/restart, file download/exec.  
    _(T1059.001 Command and Scripting Interpreter: PowerShell, T1105 Ingress Tool Transfer)_
 - Supports **surveillance**: webcam, microphone, active window tracking.  
    _(T1123 Audio Capture, T1125 Video Capture, T1010 Application Window Discovery)_
 - Modular by design: operators can load **plugins** (including destructive ones like DDoS).  
    _(T1102 Web Service, T1498.001 Direct Network Flood)_
 - Includes **worm-like spreading** to removable drives (`USB.exe`).  
    _(T1091 Replication Through Removable Media)_
 - Features a **self-destruct uninstaller** to cover its tracks.  
    _(T1070 Indicator Removal on Host)_

Put that together, OrcusRAT looks less like “just another RAT” and more like an operator’s toolkit: stealth, surveillance, and control.  

### Hunting Ideas:
If you wanted to hunt for Orcus-like activity, here are a few leads:
-  **File Artifacts**:
     - Look for `Log.tmp` in `C:\Users\%USER%\AppData\Local\Temp\`
     - Unusual temp file growth tied to user typing activity.
 - **Registry/Process Activity**:
    - Repeated registry reads against `Win32_VideoController` or `SecurityCenter2` AV queries.
    - Processes calling `SetWindowsHookEx` (API keylogger behavior).
 - **Network Signals**:
    - Beacons every fixed interval (e.g., ~15s), especially AES-encrypted blobs with no obvious plaintext headers.
 - **Behavioral Oddities**:
     - PowerShell execution with `-ExecutionPolicy Bypass`.
     - Processes creating then rapidly writing to the same file (`Log.tmp`).

### Recommendations
- **Train Employees on Phishing/Suspicious URL Detection**  
    RATs like Orcus often arrive through phishing emails or malicious attachments. Security Awareness Training reduces the chances of the first foothold. (T1566.001 Phishing: Spearphishing Attachment, T1566.002 Phishing: Spearphishing Link)
 - **Enforce Least Privilege Access**  
    Orcus checks whether it’s running with admin rights. Limiting privileges prevents malware from fully exploiting host capabilities. (T1078 Valid Accounts, T1068 Exploitation for Privilege Escalation)
 - **Control Scripting Languages**  
    Orcus can execute PowerShell (`-ExecutionPolicy Bypass`) for payload delivery. Restricting or monitoring scripting languages (PowerShell, WSH, etc.) limits post-compromise options. (T1059.001 Command and Scripting Interpreter: PowerShell, T1059.005 Command and Scripting Interpreter: Visual Basic)
 - **Harden Remote Access Settings**  
    RATs masquerade as “legit remote admin software.” Disabling or restricting unnecessary RDP/VNC, and monitoring for anomalous connections, closes a common abuse vector. (T1021.001 Remote Services: Remote Desktop Protocol, T1133 External Remote Services)
 - **Deploy Multi-Factor Authentication (MFA)**  
    Even if credentials are stolen (via keylogging), MFA can block attackers from walking straight in. (Mitigation M1032 Multi-factor Authentication)
 - **Monitor System Activity for Anomalies**  
    Keystroke capture leaves behind artifacts like `Log.tmp`. Centralized logging and Sysmon rules can flag suspicious file creation and registry access patterns. (T1056.001 Input Capture: Keylogging, T1119 Automated Collection)
 - **Monitor Network Traffic for C2 Behavior**  
    Orcus beacons every ~15 seconds with AES-encrypted blobs. Defenders should look for **periodic, encrypted outbound traffic to unusual hosts/IPs**, not just known signatures. (T1071.001 Application Layer Protocol: Web Protocols, T1008 Fallback Channels)


And while Orcus itself may be older, its DNA lives on. AsyncRAT, NetSupport, and others follow the same playbook. Understanding Orcus means understanding the lineage because the tactics don’t disappear, they evolve.  

That’s why deep dives like this matter: they turn opaque blobs into intelligence defenders can actually use.  

---
<div style="margin-bottom: 2em;"></div>
### Final Thoughts
<div style="margin-bottom: 2em;"></div>
This project reminded me why I do this work. It was long hours, sometimes hilariously frustrating (looking at you, `<123456789>`), but every roadblock turned into a lesson. Documenting every step not only gave me clarity, it turned chaos into repeatable workflow. This analysis was a test of my persistence and process. Debugging, decrypting, and faking C2s. Every stage reinforced the idea that with patience and method, the puzzle always comes together. 

<div style="margin-bottom: 2em;"></div>

> *Thank you for reading ByteForges first ever post. You can expect more of these in the future to come.*




