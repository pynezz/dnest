# dnest - a local honeypot and network monitor [WIP]

<img src="pic/logo_fill.png" alt="logo" height="256" />

## Description

dnest is a *work-in-progress* local network security monitor and honeypot system built with Go. It's designed to protect data assets by monitoring network traffic and file access on the machine.

## Features (todo)

### File Watcher

DNest are able to monitor specific files for any write, rename, permission change, or move operation. If any such operation is detected, it triggers an alert.

### Network Monitor

- Packet Inspection: DNest inspects all network packets in and out of your machine. It can detect suspicious activities such as data exfiltration attempts.
- Whois Lookup: For every unique IP address that DNest encounters, it performs a Whois lookup and logs the organization name associated with the IP.
- VirusTotal Integration: DNest uses the VirusTotal API to check the reputation of each unique IP address it encounters. If VirusTotal reports that an IP is associated with malicious or suspicious activities, DNest logs this information.

### Log Analysis

DNest are able to read nginx logs and detect suspicious activities such as SQL injection attempts, XSS attacks, and shell upload attempts.

It will furthermore try to do forensics on any payloads that it detects in the logs. For example, if DNest detects a shell upload attempt, it will try to download the shell and analyze it for malicious content.

### Threat Intelligence

DNest uses the following threat intelligence sources to detect and attribute suspicious activities:

- [AlienVault Open Threat Exchange](https://otx.alienvault.com/)
- [Virustotal](https://www.virustotal.com/)
- [ThreatFox](https://threatfox.abuse.ch/)

### Logging

DNest logs all suspicious activities to a local log file readable by logging aggregators such as Promtail.

## Build

```bash
make build
```

### Requirements

#### Linux

- libpcap-dev
- gcc-multilib
- gcc-mingw-w64 (for cross-compiling)

#### Windows

- MinGW-w64 (for cross-compiling)
- WinPcap
- make
