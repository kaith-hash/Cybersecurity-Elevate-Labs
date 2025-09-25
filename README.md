# Cybersecurity-Elevate-Labs

## Task 1: Discovering Open Ports in the Local Network

This task focuses on performing basic **network reconnaissance** to discover **open ports** on devices within the local network.This is a fundamental step in understanding the network's exposure and potential security risks.

### **Objective**

* Use **Nmap** to perform a port scan on devices in the local network.
* Understand key concepts like TCP SYN scanning, IP ranges, and open port significance.

### **Tools Used**

* **Nmap** (Network Mapper) 
* **Operating System:** Windows 11 (or Linux for better reliability in cybersecurity) 
* **Target Network:** 192.168.1.124 IP subnet 

### **Key Concepts**

| Concept | Description |
| :--- | :--- |
| **Port Scanning** | The process of sending requests to a range of ports on a target device to determine which ports are open and active. |
| **IP Ranges** | A set of IP addresses, often denoted using **CIDR notation** (e.g., `192.168.1.124`), which specifies all devices within a particular subnet. |
| **Open Ports** | Ports on a host that are accepting connections, often indicating a running service (e.g., web server, SSH, FTP). |
| **Network Exposure** | The measure of what services or entry points an attacker can see and potentially interact with on a network. |
| **EthicsLegal** | Only scan hostsnetworks you own or have explicit permission to test. |

***

## **Step-by-Step Implementation**

### **1. Nmap Installation**

1.  **Install Nmap** on the chosen machine (Windows or Linux).
    * *(Note: While Windows 11 was used, Linux is considered more reliable for cybersecurity tasks).*

### **2. Performing the TCP SYN Scan**

The core of this task involves executing a **TCP SYN Scan (`-sS`)** against the entire local subnet.

| Step | CommandAction | Description |
| :--- | :--- | :--- |
| **2.1** | Open the terminal or command prompt (with Administratorroot privileges). | The scan requires **raw packet privileges** to function correctly. |
| **2.2** | Execute the scan command: `nmap -sS 192.168.1.124`. | This initiates a **stealth scan** across all 254 possible host IPs in the `192.168.1.124` subnet. |

### **3. Understanding the TCP SYN Scan (`-sS`)**

The TCP SYN scan is a **"half-open"** or **stealth scan** because it avoids completing the standard TCP 3-way handshake.

#### **How it Works (Packet Inspection)**

The scan sends a **TCP SYN packet** (Synchronization) to the target ports and interprets the reply:

* **Port Open:** The target sends a **SYNACK** (Synchronization-Acknowledgement). The scanner then typically sends an **RST** (Reset) to immediately close the connection, thus avoiding a full handshake.
* **Port Closed:** The target sends an **RST** (Reset) packet.
* **Port Filtered:** There is **No reply** or an **ICMP unreachable** message is received, often indicating a firewall or a packet-dropping rule is in place.

#### **Stealth and Trade-offs**

* **Why Stealth?** By avoiding the final `ACK` packet, it leaves fewer connection traces than a full TCP connect scan (`-sT`), making it harder to log by host-based tools.
* **Trade-off:** While generally faster and quieter than a connect scan, it is still detectable by modern Intrusion Detection Systems (IDS) and network monitoring tools.

### **4. Common Scan Additions**

While the basic scan is useful, Nmap offers parameters to enrich the findings:

* `-p`: Specify ports to scan (e.g., `-p1-65535` for all ports).
* `-sV`: Attempt to detect the **service and version** running on open ports.
* `-O`: Attempt to perform **OS detection** to identify the target's operating system.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Task 2: Analyzing a Phishing Email Sample

This task details the systematic analysis of a suspicious email to expose its **phishing characteristics** using header analysis and content review.

### **Objective**

  * Identify phishing characteristics in a suspicious email sample.
  * Utilize an email client and a free online header analyzer.
  * Learn to systematically identify phishing tactics and analyze email threats.

### **Tools Used**

  * **Email Client** or saved email file (text) 
  * **Free Online Header Analyzer** (e.g., MXToolbox) 

### **Key Concepts**

| Concept | Description |
| :--- | :--- |
| **Phishing** | Fraudulently acquiring sensitive data by disguising communication as trustworthy. |
| **Email Spoofing** | Forging the sender's address, often using **lookalike domains** (e.g., `bannk` instead of `bank`). |
| **Header Analysis** | Examining the raw headers to check authentication (SPF, DKIM, DMARC) and the true sending IP. |
| **Social Engineering** | Psychological manipulation using **urgency** or **threats** to induce immediate action. |
| **Threat Detection** | Identifying indicators like failed authentication, mismatched URLs, and malicious attachments. |

-----

## **Step-by-Step Implementation**

### **1. Collect Sample and Extract Header**

1.  **Obtain a sample** phishing email (e.g., from safe online sources or an inbox marked suspicious).
2.  **Save** the email as `.eml` or copy the raw text.
3.  **Extract the Header:** Open the email and locate the **“Show Original”** or **“View Source  Internet Headers”** option.
4.  **Copy** the full raw header for analysis.

### **2. Analyze Header for Authentication and Origin**

The raw header is pasted into a tool like the MXToolbox Email Header Analyzer.

| Analysis Point | Finding | Indicator |
| :--- | :--- | :--- |
| **Sender Domain** | Claimed: `support@mysecurebank.com`  <br> Actual: `support@mysecurebannk.co`  | **SpoofedLookalike Domain**. |
| **Sender IP** | `185.203.118.45` (associated with `mail.fakehost.ru`)  | **Origin IP not belonging to the legitimate bank** (foreign hostgeneric mail provider). |
| **SPF** | `spf=fail`  | **Failed authentication**—sending IP is **not authorized** by the domain’s SPF record (spoofing likely). |
| **DKIM** | `dkim=fail` (no signature)  | **Failed authenticity**—message lacks a valid DKIM signature from the claimed domain. |
| **DMARC** | `dmarc=fail` (p=none)  | **DMARC not passing**—strong indicator of a forged email. |

### **3. Check Suspicious Links and Attachments**

1.  **Check Suspicious Links:**
      * **Visible Link Text:** `https:mysecurebank.comlogin`.
      * **Actual Target Link (simulated):** `http:185.203.118.45login.php` or `http:malicious-site.cosecurelogin`.
      * **Finding:** **Mismatched URL**—the displayed link differs from the real target, a classic redirect for credential harvesting. **Do not click** the link.
2.  **Check Attachments:**
      * **Attachment Name:** `Invoice_Sept2025.zip`.
      * **Inside (simulated):** `Invoice_Sept2025.exe`.
      * **Finding:** Attachments with **double extensions or executables inside compressed files (.zip)** are common malware delivery vectors. **Do not open** attachments.

### **4. Review Email Content for Social Engineering**

1.  **Subject Line and Tone:**
      * **Subject:** `URGENT: Verify Your Account Now or It Will Be Blocked`.
      * **Tone:** **Threatening and time-limited** ("You have 24 hours to verify or your account will be suspended").
      * **Reason:** Phishers use **fearurgency** to bypass rational checks and induce immediate clicks.
2.  **Language and Greeting:**
      * **Simulated Errors:** Spellinggrammar errors like "You musted verify your account immediatly" or "Please click here to secure youre account".
      * **Greeting:** **Generic greeting** ("Dear Customer") instead of the recipient's name.
      * **Reason:** Legitimate institutional emails rarely contain such errors; poor language is a phishing hallmark.

### **5. Summary of Phishing Traits Found (Deliverables)**

The following indicators confirm the email is a phishing attempt:

  * **SpoofedLookalike Sender Domain** (`mysecurebannk.co`).
  * **Failed Email Authentication** (SPF=fail, DKIM=fail, DMARC=fail).
  * **Non-Legitimate Sender IP** (`185.203.118.45`).
  * **Mismatched Display URL vs Actual Href** (link leads to an IP-malicious domain).
  * **Threatening, Urgent Language** to force immediate action.
  * **Suspicious Attachment** with an executable inside a ZIP.
  * **Poor LanguageGeneric Greeting**.
  * **Inconsistent Branding** or unusual reply-to address mismatch.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Task 3: Performing a Basic Vulnerability Scan on a PC

This task involves using a free vulnerability scanner, **OpenVAS (Greenbone Vulnerability Manager - GVM)**, to identify common security risks on a personal computer.

### **Objective**

* Use free tools to identify common vulnerabilities on a local machine.
* Gain introductory experience in vulnerability assessment and understand common PC risks.

### **Tools Used**

* **OpenVAS Community Edition** (Greenbone Vulnerability Manager) 
* **Operating System:** Kali Linux (as suggested by the `sudo apt install openvas` command shown) 

### **Deliverables**

* Vulnerability scan report with identified issues.

---

## **Step-by-Step Implementation**

### **1. OpenVAS (GVM) Installation and Setup**

The first step is to install and set up the Greenbone Vulnerability Management (GVM) framework, which includes OpenVAS.

| Step | CommandAction | Description |
| :--- | :--- | :--- |
| **1.1** | `sudo apt install openvas` | Install the OpenVAS package and its dependencies on Kali Linux. |
| **1.2** | `sudo gvm-setup` | Run the setup script to configure the Greenbone Vulnerability Manager (GVM). This may take a significant amount of time as it downloads and processes all necessary vulnerability data (NVTs). |
| **1.3** | `sudo gvm-check-setup` | Verify that the GVMOpenVAS installation and setup were successful. |

---

### **2. Accessing the Greenbone Security Assistant (GSA)**

Once the setup is complete, the OpenVAS web interface, known as the Greenbone Security Assistant (GSA), will be ready.

1.  **Navigate** to the following address in your web browser: `https:127.0.0.1` (or the local IP of your Kali machine).
2.  **Log in** using the default credentials:
    * **Username:** `admin` 
    * **Password:** `admin` 

### **3. Starting the Vulnerability Scan**

The initial scan is recommended against the localhost (`127.0.0.1`) to ensure the installation is working correctly.

1.  **Navigate** to the scanning interface: **Scans** > **Tasks**.
2.  **Start the configuration wizard** by clicking on the purple magic wand icon (Quick start).
3.  **Set the scan target** to `127.0.0.1` (localhost) to test your installation.
    * *Note: Later scans can target other IPs, such as the one mentioned in the task, `192.168.1.98`.*
4.  **Click "Start Scan"** to begin the process.
5.  **Wait** for the scan to finish. The scan progress can be monitored, and upon completion, the task status will show as "Done".

---

### **4. Reviewing the Vulnerability Report**

After the scan is complete, the results can be analyzed in the reports section.

1.  **Navigate** to: **Scans** > **Reports**.
2.  **Select** the newly created report for the scan (e.g., "Immediate scan of IP 127.0.0.1").

#### **Initial Localhost Scan Findings**

A successful initial scan against the localhost (`127.0.0.1`) should typically show vulnerabilities related to OpenVASGVM itself, which is normal for a default installation.

* **Example Findings:**
    * **OpenVAS  Greenbone Vulnerability Manager Default Credentials** (Severity: High, 10.0) 
    * **SSLTLS: Certificate Expired** (Severity: Medium, 5.0) 

#### **Host Scan Summary (Example: 192.168.1.98)**

The full report for a specific host (e.g., `192.168.1.98`) provides a summary of findings:

| **Category** | **Count** |
| :--- | :--- |
| **High** | 9 |
| **Medium** | 28 |
| **Low** | 2 |
| **Log** | 0 |
| **False Positive** | 0 |

The report also includes an **open port summary** and **host authentication** details.

---

### **5. Analyzing and Documenting a Critical Vulnerability**

The final step is to analyze a specific vulnerability reported by OpenVAS and document a mitigation strategy.

#### **Vulnerability Example: OS End of Life Detection**

| Detail | Information from Report |
| :--- | :--- |
| **Vulnerability Name** | **OS End of Life Detection** |
| **Severity** | **High** (CVSS: 10.0)  |
| **Affected System** | Ubuntu Linux, Version 8.04  |
| **End of Life (EOL) Date** | 2013-05-09  |
| **Summary** | The OS has reached EOL, meaning it no longer receives security updates, patches, or vendor support. Using EOL software exposes the system to known and unknown vulnerabilities. |
| **Detection Method** | OS End of Life Detection (OID: 1.3.6.1.4.1.25623.1.0.103674)  |

#### **Solution  Mitigation** 

The primary solution for an End-of-Life operating system is to upgrade to a supported version.

* **Recommended Action:** Upgrade the operating system to a supported version (e.g., Ubuntu 24.04 LTS or the latest supported LTS).
* **Best Practices:**
    * Backup critical data before starting the upgrade process.
    * Test critical applications on the new OS version for compatibility[cite: 48].
    * Apply the latest patches and security updates immediately after the OS upgrade[cite: 49].
