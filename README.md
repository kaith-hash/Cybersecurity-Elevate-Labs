# Cybersecurity-Elevate-Labs
##TASK 1:Learn to discover open ports on devices in your local network to understand network exposure. 

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
