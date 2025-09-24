# Cybersecurity-Elevate-Labs
***TASK-1***

**Objective**: Learn to discover open ports on devices in your local network to understand network exposure. 

**Tools**: Nmap

**Key Concepts**: Port scanning, TCP SYN scan, IP ranges, network reconnaissance, open ports, network security basics

So, my local Area Network consists of a 192.168.1.1/24 IP subnet.
Firstly, I installed Nmap on my Windows 11 machine. You can either use Windows or Linux OS for scanning the port using Nmap, but using Linux is more reliable in the cybersecurity field.
Using- nmap -sS 192.168.1.1/24, I performed a TCP SYN scan, which means “half-open” or stealth scan.

**What it does**: Sends TCP SYN packets to target ports and inspects replies.

SYN + SYN/ACK → port open (scanner usually sends a RST to avoid completing the handshake).

SYN + RST → port closed.

No reply or ICMP unreachable → port filtered (firewall or drop).

Why “stealth”? It avoids completing the 3-way handshake, so it may leave less of a connection trace than a full connect scan.

**Privileges**: Requires raw packet privileges (usually run as root/Administrator).

**Speed & stealth tradeoff**: Faster and often quieter than a full TCP connect (-sT), but still detectable by modern IDS/host logs.

**Common additions**: -p to specify ports (e.g., -p1-65535), -sV for service/version detection, and -O for OS detection.

**Ethics/legal**: Only scan hosts/networks you own or have permission to test.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
