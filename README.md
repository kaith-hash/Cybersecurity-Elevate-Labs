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

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


## Task 4: Setup and Use a Firewall on Windows/Linux

This task demonstrates the setup and testing of basic firewall rules to control network traffic, a critical aspect of host security.

### **Objective**

  * Configure and test basic firewall rules to allow or block network traffic.
  * Understand the function of inbound and outbound rules.

### **Tools Used**

  * **Windows Defender Firewall with Advanced Security** (on Windows) [cite: 123, 125]
  * **Telnet Client** (for testing) [cite: 131]
  * **Operating System:** Windows [cite: 121]
  * *Alternate Tool:* UFW (Uncomplicated Firewall) on Linux [cite: 123]

### **Key Concepts**

| Concept | Description |
| :--- | :--- |
| **Inbound Rules** | Control traffic entering the system (e.g., blocking Telnet on port 23). [cite: 136] |
| **Outbound Rules** | Control traffic leaving the system (e.g., preventing an application from accessing the internet). [cite: 137] |
| **Firewall Filtering** | The process of allowing or blocking traffic based on defined rules using parameters like port numbers, protocols (TCP/UDP), IP addresses, or applications. [cite: 135, 138] |

-----

## **Step-by-Step Implementation**

### **1. Accessing Windows Defender Firewall**

1.  **Open** the Windows Defender Firewall interface. The overview shows the firewall state (e.g., On) and connection settings for Private and Public networks. [cite: 124]
2.  **Navigate** to **Windows Defender Firewall with Advanced Security** to view the **Inbound** and **Outbound Rules**. [cite: 125] This is where rules for traffic entering (Inbound) and leaving (Outbound) the system are managed. [cite: 126, 127]

### **2. Adding a Rule to Block Inbound Traffic**

The objective is to create a new **Inbound Rule** to block all incoming traffic on a specific port (Port 23, typically used by the Telnet protocol).

| Step | Action/Configuration | Detail |
| :--- | :--- | :--- |
| **2.1 Rule Type** | Select **Port**. [cite: 128] | The rule will control connections for a TCP or UDP port. |
| **2.2 Protocol and Ports** | Select **TCP** and choose **Specific local ports**. Enter `23`. [cite: 128] | Port 23 is the standard port for the Telnet service. |
| **2.3 Action** | Select **Block the connection**. [cite: 128] | This specifies the firewall's action when traffic matches the rule. |
| **2.4 Profile** | Select **Domain**, **Private**, and **Public** profiles. [cite: 128] | This ensures the rule applies regardless of the network environment (e.g., home, corporate, public Wi-Fi). |
| **2.5 Name** | Assign a descriptive name, such as **`Block_Telnet_23`**. [cite: 128] | The new rule is now active in the Inbound Rules list. [cite: 128] |

### **3. Testing the Firewall Rule**

The rule is tested by attempting to connect to the blocked port (Port 23) using the Telnet client.

1.  **Enable Telnet Client** (if not already installed): Navigate to **Control Panel** → **Programs** → **Turn Windows features on or off**, and enable **Telnet Client**. [cite: 131]
2.  **Run the Test Command** from the Command Prompt:
    ```bash
    telnet [host ip] 23
    ```
    *Example:* `telnet 192.168.1.39 23` [cite: 132]
3.  **Observation:** The connection attempt fails with a **"Connect failed"** message. [cite: 132] This confirms the new firewall rule successfully intercepted and blocked the inbound connection attempt to Port 23. [cite: 132]

### **4. Summary of Firewall Functionality**

A firewall acts as a security guard for the computer, determining whether to **allow or block traffic** based on defined rules. [cite: 134, 135]

  * **Rule Mechanism:** Rules are based on parameters like port numbers, protocols (TCP/UDP), IP addresses, or applications. [cite: 138]
  * **Action:** If traffic matches a **Block** rule, the traffic is dropped. If the traffic is **allowed**, it passes. [cite: 140, 141]
  * **Test Outcome:** Blocking port **23** stopped Telnet connections, proving the firewall filters unwanted access while allowing other safe traffic. [cite: 142]
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Task 5: Capture and Analyze Network Traffic Using Wireshark

This task focuses on using **Wireshark** to capture and analyze live network packets, a core skill in network forensics and troubleshooting.

### **Objective**

  * Capture live network packets using Wireshark.
  * Identify basic network protocols (e.g., DNS, TCP, HTTP) and traffic types.

### **Tools Used**

  * **Wireshark** (Free Network Protocol Analyzer)
  * **Command Prompt** (for testing with `ping`)

### **Key Concepts**

| Concept | Description |
| :--- | :--- |
| **Packet Capture** | The process of intercepting and logging traffic passing over a digital network or part of a network. |
| **Protocol Filtering** | Using specific expressions (e.g., `http`, `dns`) in Wireshark to display only packets belonging to a certain protocol. |
| **TCP 3-way Handshake** | The connection setup process for TCP: **SYN** $\rightarrow$ **SYN-ACK** $\rightarrow$ **ACK**. |
| **ICMP** | Internet Control Message Protocol, used primarily for network diagnostic tools like **`ping`**. |
| **Well-Known Ports** | Standardized ports for services, such as Port 53 (DNS), Port 80 (HTTP), and Port 445 (SMB). |

-----

## **Step-by-Step Implementation**

### **1. Capture Live Network Packets**

1.  **Launch Wireshark** and select the active network interface (e.g., Ethernet or Wi-Fi).
2.  **Start the Capture** by clicking the fin icon or selecting **Capture \> Start**.
3.  **Generate Test Traffic:** While Wireshark is running, perform actions like:
      * Browsing a website (to generate DNS, TCP, HTTP/TLS traffic).
      * Executing a `ping` command to a local or remote server to generate ICMP traffic[cite: 147].
4.  **Stop the Capture** after a few moments (e.g., **Capture \> Stop**).

### **2. Generate and Capture ICMP Traffic**

The `ping` command is used to generate specific ICMP traffic to a known host (e.g., a local campus server at `10.0.0.39`)[cite: 147].

1.  **Open** the Command Prompt.
2.  **Execute** the command:
    ```bash
    ping 10.0.0.39
    ```
3.  **Verify** the output shows successful replies (0% loss) and approximate round trip times[cite: 147].

### **3. Filter and Analyze Protocols**

Use the Wireshark filter bar at the top to isolate different protocols in the captured file (`task5 packet capture.pcapng`)[cite: 148].

| Protocol | Filter Used | Key Observation |
| :--- | :--- | :--- |
| **DNS** [cite: 150] | `dns` | Shows standard **DNS queries and responses** between the system (`192.168.1.39`) and DNS servers (e.g., `10.0.0.41`)[cite: 150]. |
| **HTTP** [cite: 149] | `http` | Displays **HTTP GET and response packets**, often mixed with PKIX-CRL traffic[cite: 149]. |
| **TCP** [cite: 151] | `tcp` | Reveals the underlying **TCP segments**, including the 3-way handshake process (SYN, SYN-ACK, ACK), and protocols riding over TCP like TLSv1.2[cite: 163, 151]. |
| **ICMP** [cite: 153] | `icmp` | Isolates the **Echo Request** and **Echo Reply** packets generated by the `ping` command[cite: 176, 177, 153]. |
| **SMB** [cite: 154] | `smb` | Shows **Server Message Block** traffic, often indicating local Windows file-sharing or network services on port 445[cite: 173, 174]. |

-----

## **Summary of Findings**

Analysis of the captured traffic file revealed several common network protocols:

  * **DNS (Domain Name System):** Identified as several **DNS queries and responses** that translate domain names to IP addresses[cite: 158, 159, 160]. This traffic primarily uses the **UDP** protocol on **Port 53**[cite: 161].
  * **TCP (Transmission Control Protocol):** Observed the standard **TCP 3-way handshake** before data transfer[cite: 163]. TCP segments were seen carrying higher-level data protocols like HTTP[cite: 164].
      * *Example Detail:* Handshake packets with flags **SYN, SYN-ACK, ACK** were present[cite: 180].
  * **HTTP (Hypertext Transfer Protocol):** Captured **HTTP GET and response packets** (e.g., a request to fetch a webpage)[cite: 167, 168].
  * **ICMP (Internet Control Message Protocol):** Confirmed the `ping` activity by observing **echo request and echo reply** packets between the system and other hosts[cite: 176, 177, 182].
  * **SMB (Server Message Block):** Detected traffic on **TCP Port 445**, indicating file-sharing or background Windows network services[cite: 172, 173].

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Task 6: Creating a Strong Password and Evaluating Its Strength

This task focuses on the principles of **strong password creation** and uses an online tool to demonstrate how length and complexity directly impact security against common cracking methods.

### **Objective**

* Understand the factors that make a password strong.
* Test password strength using online tools.

### **Tools Used**

* **Online free password strength checker** (e.g., `passwordmeter.com` [cite: 3])

### **Key Concepts**

| Concept | Description |
| :--- | :--- |
| **Password Complexity** | The inclusion of different character sets: uppercase, lowercase, numbers, and symbols[cite: 32]. |
| **Brute Force Attack** | An attack that tries every possible combination until the correct password is found[cite: 37]. |
| **Dictionary Attack** | An attack that uses a list of common words or leaked passwords[cite: 38]. |
| **Credential Stuffing** | Using leaked credentials from one service to try logging into another account[cite: 39]. |

---

## **Step-by-Step Implementation**

### **1. Creating and Testing Passwords**

Multiple passwords were created with increasing complexity and tested using a password strength checker to observe the score and complexity rating.

| Password | Score (%) | Strength | Primary Characteristics |
| :--- | :--- | :--- | :--- |
| `Password` [cite: 17] | 26% [cite: 18] | **Weak** [cite: 18] | Too short, only lowercase + uppercase[cite: 28]. |
| `hello12345` [cite: 19] | 51% [cite: 20] | **Good** [cite: 20] | Longer length, includes lowercase and numbers[cite: 20]. |
| `hello@1234` [cite: 21] | 66% [cite: 22] | **Strong** [cite: 22] | Good length, uses lowercase, numbers, and a symbol[cite: 22]. |
| `Hello@123` [cite: 23] | 89% [cite: 24] | **Very Strong** [cite: 24] | Incorporates uppercase, lowercase, number, and symbol[cite: 24, 28]. |
| `Hell0@Guys#Cyb3r!$` [cite: 25] | 100% [cite: 26] | **Very Strong** [cite: 26] | Long, random, and diverse, making it very difficult to crack[cite: 10, 28]. |

### **2. Identifying Best Practices**

Based on the testing, several best practices were identified for creating passwords that maximize security:

* **Length:** Passwords should be at least **12–16 characters long**[cite: 31].
* **Diversity:** Use a combination of **uppercase and lowercase letters, numbers, and symbols**[cite: 32].
* **Unpredictability:** **Avoid dictionary words**, names, or birthdates[cite: 33].
* **Uniqueness:** Use a **unique password for every single account**[cite: 34].
* **Management:** Employ a **password manager** to securely generate and store complex passwords[cite: 35].

### **3. Research on Common Password Attacks**

Strong password habits help mitigate risk from common password attacks:

| Attack Type | Description |
| :--- | :--- |
| **Brute Force Attack** [cite: 37] | Tries every possible character combination until the correct password is found[cite: 37]. |
| **Dictionary Attack** [cite: 38] | Uses lists of common words, phrases, and previously leaked passwords[cite: 38]. |
| **Credential Stuffing** [cite: 39] | Uses username/password combinations stolen in a breach on one site to attempt login on others[cite: 39]. |
| **Social Engineering** [cite: 40] | Involves tricking the user (e.g., through phishing) into willingly revealing their password[cite: 40]. |

### **4. Conclusion**

Password complexity directly impacts security[cite: 42]. While simple passwords (like `hello123`) can be **cracked in seconds** [cite: 43], long, complex passwords (like `Hell0@Guys#Cyb3r!$`) may take **centuries** to crack with brute force methods[cite: 44]. Adopting strong password practices significantly reduces the risk of hacking and improves overall cybersecurity hygiene[cite: 45].
