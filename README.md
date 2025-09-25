# Cybersecurity-Elevate-Labs

## Task 1: Discovering Open Ports in the Local Network

This task focuses on performing basic **network reconnaissance** to discover **open ports** on devices within the local network.This is a fundamental step in understanding the network's exposure and potential security risks.

### **Objective**

* [cite_start]Use **Nmap** to perform a port scan on devices in the local network[cite: 1].
* [cite_start]Understand key concepts like TCP SYN scanning, IP ranges, and open port significance[cite: 1].

### **Tools Used**

* [cite_start]**Nmap** (Network Mapper) [cite: 1]
* [cite_start]**Operating System:** Windows 11 (or Linux for better reliability in cybersecurity) [cite: 1]
* [cite_start]**Target Network:** 192.168.1.1/24 IP subnet [cite: 1]

### **Key Concepts**

| Concept | Description |
| :--- | :--- |
| **Port Scanning** | [cite_start]The process of sending requests to a range of ports on a target device to determine which ports are open and active[cite: 1]. |
| **IP Ranges** | [cite_start]A set of IP addresses, often denoted using **CIDR notation** (e.g., `192.168.1.1/24`), which specifies all devices within a particular subnet[cite: 1]. |
| **Open Ports** | [cite_start]Ports on a host that are accepting connections, often indicating a running service (e.g., web server, SSH, FTP)[cite: 1]. |
| **Network Exposure** | [cite_start]The measure of what services or entry points an attacker can see and potentially interact with on a network[cite: 1]. |
| **Ethics/Legal** | [cite_start]Only scan hosts/networks you own or have explicit permission to test[cite: 1]. |

***

## **Step-by-Step Implementation**

### **1. Nmap Installation**

1.  [cite_start]**Install Nmap** on the chosen machine (Windows or Linux)[cite: 1].
    * [cite_start]*(Note: While Windows 11 was used, Linux is considered more reliable for cybersecurity tasks)[cite: 1].*

### **2. Performing the TCP SYN Scan**

The core of this task involves executing a **TCP SYN Scan (`-sS`)** against the entire local subnet.

| Step | Command/Action | Description |
| :--- | :--- | :--- |
| **2.1** | [cite_start]Open the terminal or command prompt (with Administrator/root privileges)[cite: 1]. | [cite_start]The scan requires **raw packet privileges** to function correctly[cite: 1]. |
| **2.2** | [cite_start]Execute the scan command: `nmap -sS 192.168.1.1/24`[cite: 1]. | [cite_start]This initiates a **stealth scan** across all 254 possible host IPs in the `192.168.1.1/24` subnet[cite: 1]. |

### **3. Understanding the TCP SYN Scan (`-sS`)**

[cite_start]The TCP SYN scan is a **"half-open"** or **stealth scan** because it avoids completing the standard TCP 3-way handshake[cite: 1].

#### **How it Works (Packet Inspection)**

[cite_start]The scan sends a **TCP SYN packet** (Synchronization) to the target ports and interprets the reply[cite: 1]:

* **Port Open:** The target sends a **SYN/ACK** (Synchronization-Acknowledgement). [cite_start]The scanner then typically sends an **RST** (Reset) to immediately close the connection, thus avoiding a full handshake[cite: 1].
* [cite_start]**Port Closed:** The target sends an **RST** (Reset) packet[cite: 1].
* [cite_start]**Port Filtered:** There is **No reply** or an **ICMP unreachable** message is received, often indicating a firewall or a packet-dropping rule is in place[cite: 1].

#### **Stealth and Trade-offs**

* [cite_start]**Why Stealth?** By avoiding the final `ACK` packet, it leaves fewer connection traces than a full TCP connect scan (`-sT`), making it harder to log by host-based tools[cite: 1].
* [cite_start]**Trade-off:** While generally faster and quieter than a connect scan, it is still detectable by modern Intrusion Detection Systems (IDS) and network monitoring tools[cite: 1].

### **4. Common Scan Additions**

While the basic scan is useful, Nmap offers parameters to enrich the findings:

* [cite_start]`-p`: Specify ports to scan (e.g., `-p1-65535` for all ports)[cite: 1].
* [cite_start]`-sV`: Attempt to detect the **service and version** running on open ports[cite: 1].
* [cite_start]`-O`: Attempt to perform **OS detection** to identify the target's operating system[cite: 1].

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Task 2: Analyzing a Phishing Email Sample

This task details the systematic analysis of a suspicious email to expose its **phishing characteristics** using header analysis and content review.

### **Objective**

  * [cite\_start]Identify phishing characteristics in a suspicious email sample[cite: 57].
  * [cite\_start]Utilize an email client and a free online header analyzer[cite: 58].
  * Learn to systematically identify phishing tactics and analyze email threats.

### **Tools Used**

  * [cite\_start]**Email Client** or saved email file (text) [cite: 58]
  * [cite\_start]**Free Online Header Analyzer** (e.g., MXToolbox) [cite: 58]

### **Key Concepts**

| Concept | Description |
| :--- | :--- |
| **Phishing** | [cite\_start]Fraudulently acquiring sensitive data by disguising communication as trustworthy[cite: 60]. |
| **Email Spoofing** | [cite\_start]Forging the sender's address, often using **lookalike domains** (e.g., `bannk` instead of `bank`)[cite: 60, 64]. |
| **Header Analysis** | [cite\_start]Examining the raw headers to check authentication (SPF, DKIM, DMARC) and the true sending IP[cite: 60, 68]. |
| **Social Engineering** | [cite\_start]Psychological manipulation using **urgency** or **threats** to induce immediate action[cite: 60, 104]. |
| **Threat Detection** | [cite\_start]Identifying indicators like failed authentication, mismatched URLs, and malicious attachments[cite: 60, 114, 116, 118]. |

-----

## **Step-by-Step Implementation**

### **1. Collect Sample and Extract Header**

1.  [cite\_start]**Obtain a sample** phishing email (e.g., from safe online sources or an inbox marked suspicious)[cite: 56].
2.  [cite\_start]**Save** the email as `.eml` or copy the raw text[cite: 58].
3.  [cite\_start]**Extract the Header:** Open the email and locate the **“Show Original”** or **“View Source / Internet Headers”** option[cite: 65].
4.  **Copy** the full raw header for analysis.

### **2. Analyze Header for Authentication and Origin**

[cite\_start]The raw header is pasted into a tool like the MXToolbox Email Header Analyzer[cite: 86].

| Analysis Point | Finding | Indicator |
| :--- | :--- | :--- |
| **Sender Domain** | [cite\_start]Claimed: `support@mysecurebank.com` [cite: 62] [cite\_start]<br> Actual: `support@mysecurebannk.co` [cite: 63] | [cite\_start]**Spoofed/Lookalike Domain**[cite: 64]. |
| **Sender IP** | [cite\_start]`185.203.118.45` (associated with `mail.fakehost.ru`) [cite: 70, 87] | [cite\_start]**Origin IP not belonging to the legitimate bank** (foreign host/generic mail provider)[cite: 67, 87]. |
| **SPF** | [cite\_start]`spf=fail` [cite: 73, 88] | [cite\_start]**Failed authentication**—sending IP is **not authorized** by the domain’s SPF record (spoofing likely)[cite: 68, 88]. |
| **DKIM** | [cite\_start]`dkim=fail` (no signature) [cite: 76, 89] | [cite\_start]**Failed authenticity**—message lacks a valid DKIM signature from the claimed domain[cite: 68, 89]. |
| **DMARC** | [cite\_start]`dmarc=fail` (p=none) [cite: 77, 90] | [cite\_start]**DMARC not passing**—strong indicator of a forged email[cite: 68, 91]. |

### **3. Check Suspicious Links and Attachments**

1.  **Check Suspicious Links:**
      * [cite\_start]**Visible Link Text:** `https://mysecurebank.com/login`[cite: 93].
      * [cite\_start]**Actual Target Link (simulated):** `http://185.203.118.45/login.php` or `http://malicious-site.co/secure/login`[cite: 94].
      * [cite\_start]**Finding:** **Mismatched URL**—the displayed link differs from the real target, a classic redirect for credential harvesting[cite: 95, 116]. **Do not click** the link.
2.  **Check Attachments:**
      * [cite\_start]**Attachment Name:** `Invoice_Sept2025.zip`[cite: 97].
      * [cite\_start]**Inside (simulated):** `Invoice_Sept2025.exe`[cite: 98].
      * [cite\_start]**Finding:** Attachments with **double extensions or executables inside compressed files (.zip)** are common malware delivery vectors[cite: 99, 118]. [cite\_start]**Do not open** attachments[cite: 100].

### **4. Review Email Content for Social Engineering**

1.  **Subject Line and Tone:**
      * [cite\_start]**Subject:** `URGENT: Verify Your Account Now or It Will Be Blocked`[cite: 83, 102].
      * [cite\_start]**Tone:** **Threatening and time-limited** ("You have 24 hours to verify or your account will be suspended")[cite: 103].
      * [cite\_start]**Reason:** Phishers use **fear/urgency** to bypass rational checks and induce immediate clicks[cite: 104, 117].
2.  **Language and Greeting:**
      * [cite\_start]**Simulated Errors:** Spelling/grammar errors like "You musted verify your account immediatly" or "Please click here to secure youre account"[cite: 106].
      * [cite\_start]**Greeting:** **Generic greeting** ("Dear Customer") instead of the recipient's name[cite: 110].
      * [cite\_start]**Reason:** Legitimate institutional emails rarely contain such errors; poor language is a phishing hallmark[cite: 107, 119].

### **5. Summary of Phishing Traits Found (Deliverables)**

[cite\_start]The following indicators confirm the email is a phishing attempt[cite: 59, 112]:

  * [cite\_start]**Spoofed/Lookalike Sender Domain** (`mysecurebannk.co`)[cite: 113].
  * [cite\_start]**Failed Email Authentication** (SPF=fail, DKIM=fail, DMARC=fail)[cite: 114].
  * [cite\_start]**Non-Legitimate Sender IP** (`185.203.118.45`)[cite: 115].
  * [cite\_start]**Mismatched Display URL vs Actual Href** (link leads to an IP/malicious domain)[cite: 116].
  * [cite\_start]**Threatening, Urgent Language** to force immediate action[cite: 117].
  * [cite\_start]**Suspicious Attachment** with an executable inside a ZIP[cite: 99, 118].
  * [cite\_start]**Poor Language/Generic Greeting**[cite: 119].
  * [cite\_start]**Inconsistent Branding** or unusual reply-to address mismatch[cite: 120, 111, 109].

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
