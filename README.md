# Cybersecurity-Elevate-Labs
🔍 Task 1: Discovering Open Ports in the Local Network
This task focuses on performing basic network reconnaissance to discover open ports on devices within the local network. This is a fundamental step in understanding the network's exposure and potential security risks.

Objective
Use 

Nmap to perform a port scan on devices in the local network.

Understand key concepts like TCP SYN scanning, IP ranges, and open port significance.

Tools Used

Nmap (Network Mapper) 


Operating System: Windows 11 (or Linux for better reliability in cybersecurity) 


Target Network: 192.168.1.1/24 IP subnet 

Key Concepts
Concept	Description
Port Scanning	
The process of sending requests to a range of ports on a target device to determine which ports are open and active.

IP Ranges	
A set of IP addresses, often denoted using 

CIDR notation (e.g., 192.168.1.1/24), which specifies all devices within a particular subnet.

Open Ports	
Ports on a host that are accepting connections, often indicating a running service (e.g., web server, SSH, FTP).

Network Exposure	
The measure of what services or entry points an attacker can see and potentially interact with on a network.

Ethics/Legal	
Only scan hosts/networks you own or have explicit permission to test.


Export to Sheets
Step-by-Step Implementation
1. Nmap Installation

Install Nmap on the chosen machine (Windows or Linux).


(Note: While Windows 11 was used, Linux is considered more reliable for cybersecurity tasks).

2. Performing the TCP SYN Scan
The core of this task involves executing a TCP SYN Scan (-sS) against the entire local subnet.

Step	Command/Action	Description
2.1	
Open the terminal or command prompt (with Administrator/root privileges).

The scan requires 

raw packet privileges to function correctly.

2.2	
Execute the scan command: 

nmap -sS 192.168.1.1/24.

This initiates a 

stealth scan across all 254 possible host IPs in the 192.168.1.1/24 subnet.


Export to Sheets
3. Understanding the TCP SYN Scan (-sS)
The TCP SYN scan is a 

"half-open" or stealth scan because it avoids completing the standard TCP 3-way handshake.

How it Works (Packet Inspection)
The scan sends a 

TCP SYN packet (Synchronization) to the target ports and interprets the reply:

Port Open: The target sends a SYN/ACK (Synchronization-Acknowledgement). The scanner then typically sends an 

RST (Reset) to immediately close the connection, thus avoiding a full handshake.


Port Closed: The target sends an RST (Reset) packet.


Port Filtered: There is No reply or an ICMP unreachable message is received, often indicating a firewall or a packet-dropping rule is in place.

Stealth and Trade-offs

Why Stealth? By avoiding the final ACK packet, it leaves fewer connection traces than a full TCP connect scan (-sT), making it harder to log by host-based tools.


Trade-off: While generally faster and quieter than a connect scan, it is still detectable by modern Intrusion Detection Systems (IDS) and network monitoring tools.

4. Common Scan Additions
While the basic scan is useful, Nmap offers parameters to enrich the findings:


-p: Specify ports to scan (e.g., -p1-65535 for all ports).


-sV: Attempt to detect the service and version running on open ports.


-O: Attempt to perform OS detection to identify the target's operating system.

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

## Task 3: Performing a Basic Vulnerability Scan on a PC

This task involves using a free vulnerability scanner, **OpenVAS (Greenbone Vulnerability Manager - GVM)**, to identify common security risks on a personal computer.

### **Objective**

* [cite_start]Use free tools to identify common vulnerabilities on a local machine[cite: 2].
* [cite_start]Gain introductory experience in vulnerability assessment and understand common PC risks[cite: 5].

### **Tools Used**

* [cite_start]**OpenVAS Community Edition** (Greenbone Vulnerability Manager) [cite: 3]
* [cite_start]**Operating System:** Kali Linux (as suggested by the `sudo apt install openvas` command shown) [cite: 6]

### **Deliverables**

* [cite_start]Vulnerability scan report with identified issues[cite: 4].

---

## **Step-by-Step Implementation**

### **1. OpenVAS (GVM) Installation and Setup**

The first step is to install and set up the Greenbone Vulnerability Management (GVM) framework, which includes OpenVAS.

| Step | Command/Action | Description |
| :--- | :--- | :--- |
| **1.1** | `sudo apt install openvas` | [cite_start]Install the OpenVAS package and its dependencies on Kali Linux[cite: 6]. |
| **1.2** | `sudo gvm-setup` | [cite_start]Run the setup script to configure the Greenbone Vulnerability Manager (GVM)[cite: 7]. This may take a significant amount of time as it downloads and processes all necessary vulnerability data (NVTs). |
| **1.3** | `sudo gvm-check-setup` | [cite_start]Verify that the GVM/OpenVAS installation and setup were successful[cite: 8]. |

---

### **2. Accessing the Greenbone Security Assistant (GSA)**

Once the setup is complete, the OpenVAS web interface, known as the Greenbone Security Assistant (GSA), will be ready.

1.  [cite_start]**Navigate** to the following address in your web browser: `https://127.0.0.1` (or the local IP of your Kali machine)[cite: 10].
2.  [cite_start]**Log in** using the default credentials[cite: 11]:
    * [cite_start]**Username:** `admin` [cite: 12]
    * [cite_start]**Password:** `admin` [cite: 13]

### **3. Starting the Vulnerability Scan**

[cite_start]The initial scan is recommended against the localhost (`127.0.0.1`) to ensure the installation is working correctly[cite: 16].

1.  [cite_start]**Navigate** to the scanning interface: **Scans** > **Tasks**[cite: 15].
2.  [cite_start]**Start the configuration wizard** by clicking on the purple magic wand icon (Quick start)[cite: 15].
3.  [cite_start]**Set the scan target** to `127.0.0.1` (localhost) to test your installation[cite: 16, 18].
    * [cite_start]*Note: Later scans can target other IPs, such as the one mentioned in the task, `192.168.1.98`[cite: 23].*
4.  [cite_start]**Click "Start Scan"** to begin the process[cite: 16, 17].
5.  **Wait** for the scan to finish. [cite_start]The scan progress can be monitored, and upon completion, the task status will show as "Done"[cite: 19].

---

### **4. Reviewing the Vulnerability Report**

After the scan is complete, the results can be analyzed in the reports section.

1.  [cite_start]**Navigate** to: **Scans** > **Reports**[cite: 20].
2.  [cite_start]**Select** the newly created report for the scan (e.g., "Immediate scan of IP 127.0.0.1")[cite: 20].

#### **Initial Localhost Scan Findings**

[cite_start]A successful initial scan against the localhost (`127.0.0.1`) should typically show vulnerabilities related to OpenVAS/GVM itself, which is normal for a default installation[cite: 21, 22].

* **Example Findings:**
    * [cite_start]**OpenVAS / Greenbone Vulnerability Manager Default Credentials** (Severity: High, 10.0) [cite: 20]
    * [cite_start]**SSL/TLS: Certificate Expired** (Severity: Medium, 5.0) [cite: 20]

#### **Host Scan Summary (Example: 192.168.1.98)**

[cite_start]The full report for a specific host (e.g., `192.168.1.98`) provides a summary of findings[cite: 23, 25]:

| **Category** | **Count** |
| :--- | :--- |
| **High** | 9 |
| **Medium** | 28 |
| **Low** | 2 |
| **Log** | 0 |
| **False Positive** | 0 |

[cite_start]The report also includes an **open port summary** and **host authentication** details[cite: 26].

---

### **5. Analyzing and Documenting a Critical Vulnerability**

[cite_start]The final step is to analyze a specific vulnerability reported by OpenVAS and document a mitigation strategy[cite: 27, 29].

#### **Vulnerability Example: OS End of Life Detection**

| Detail | Information from Report |
| :--- | :--- |
| **Vulnerability Name** | [cite_start]**OS End of Life Detection** [cite: 30] |
| **Severity** | [cite_start]**High** (CVSS: 10.0) [cite: 30] |
| **Affected System** | [cite_start]Ubuntu Linux, Version 8.04 [cite: 32, 33] |
| **End of Life (EOL) Date** | [cite_start]2013-05-09 [cite: 35, 43] |
| **Summary** | [cite_start]The OS has reached EOL, meaning it no longer receives security updates, patches, or vendor support[cite: 38, 39]. [cite_start]Using EOL software exposes the system to known and unknown vulnerabilities[cite: 40]. |
| **Detection Method** | [cite_start]OS End of Life Detection (OID: 1.3.6.1.4.1.25623.1.0.103674) [cite: 52, 53] |

#### [cite_start]**Solution / Mitigation** [cite: 45, 50]

The primary solution for an End-of-Life operating system is to upgrade to a supported version.

* [cite_start]**Recommended Action:** Upgrade the operating system to a supported version (e.g., Ubuntu 24.04 LTS or the latest supported LTS)[cite: 46].
* **Best Practices:**
    * [cite_start]Backup critical data before starting the upgrade process[cite: 47].
    * [cite_start]Test critical applications on the new OS version for compatibility[cite: 48].
    * [cite_start]Apply the latest patches and security updates immediately after the OS upgrade[cite: 49].
