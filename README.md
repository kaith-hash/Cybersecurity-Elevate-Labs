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

***TASK-2***

**Objective**: Identify phishing characteristics in a suspicious email sample. 

**Tools**: Email client or saved email file (text), free online header analyzer. 

**Deliverables**: A report listing phishing indicators found

**Key Concepts**: Phishing, email spoofing, header analysis, social engineering, threat detection

1. Collect Phishing Emails

-Obtain sample phishing emails from safe online sources or your email inbox (mark them as suspicious).

-Save them as .eml or copy raw text.

2. Extract Email Header

-Open the email in your client (Gmail, Outlook, Yahoo, etc.).

-Locate “Show Original” / “View Source / Internet Headers”.

-Copy the full raw header for analysis.

3. Analyse Header Using MXToolbox

-Go to MxToolbox Email Header Analyzer.

-Paste the raw header into the analyzer.

-Review authentication results (SPF, DKIM, DMARC) and sender IP routing.

4. Check Suspicious Links and Attachments

-Hover over links to reveal the real URLs (do not click).

-Note any mismatched domains or IP addresses.

-Check attachment names for .exe, .zip, or unusual file types.

5. Review Email Content

-Look for urgent or threatening language.

-Check grammar, spelling errors, and generic greetings.

-Identify signs of social engineering.

6.Document Findings

-Record all suspicious indicators: spoofed sender, failed authentication, mismatched links, malicious attachments, urgency, spelling errors.

-Summarise phishing traits in a report for awareness or learning purposes.

7. Optional (Safe Lab Analysis)

-Use VirusTotal or sandbox environments to inspect attachments.

-Use dig or whois for domain reputation checks.

✅ Outcome:

Learn to identify phishing tactics and analyze email threats systematically.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

