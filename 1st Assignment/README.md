
 
Mini Port Scanner Report: Understanding Network Security
1. Introduction: What is a Port Scanner?
In the vast landscape of computer networks, "ports" are like the doors or communication endpoints on a computer. Each port is associated with a specific service or application. For instance, web servers typically listen on port 80 (HTTP) or 443 (HTTPS), while email servers might use port 25 (SMTP) or 110 (POP3).
A port scanner is a tool designed to probe a target system's ports to determine their state: whether they are "open," "closed," or "filtered." By identifying open ports, a security professional can understand what services are running on a system. This knowledge is crucial for:
•	Network Auditing: Gaining an inventory of active services on your network.
•	Security Assessments: Identifying potential vulnerabilities by discovering services that shouldn't be exposed or are misconfigured.
•	Compliance: Ensuring that only necessary services are running and accessible, adhering to security policies.
•	Threat Intelligence: Understanding how attackers might enumerate your systems to plan their attacks, allowing you to proactively defend.
This report details a simple bash script that leverages nmap, a powerful network scanning tool, to perform a basic port scan.
2. Prerequisites: Your Kali Linux Environment
This script is designed to run on a Linux environment, specifically Kali Linux, which comes pre-installed with nmap. nmap (Network Mapper) is an open-source tool for network discovery and security auditing. If you are not using Kali Linux, you will need to install nmap first. On Debian/Ubuntu-based systems (like Kali), you can install it using:
sudo apt update
sudo apt install nmap

3. The Mini Port Scanner Script
The following bash script automates the process of asking for a target IP address, performing a fast port scan using nmap, and saving the results to a log file.
#!/bin/bash

# Mini Port Scanner Script
# This script uses nmap to scan the top 1000 common ports on a target IP address.
# The results are saved to a log file named 'scan_<date>.log'.
#
# IMPORTANT: Only use this script on networks or systems for which you have explicit permission.
# Unauthorized port scanning can be illegal and unethical.

# --- Configuration ---
LOG_DIR="./scan_logs" # Directory to store scan logs

# --- Script Start ---

echo "======================================="
echo "  Mini Port Scanner - Defensive Tool"
echo "======================================="

# Check if nmap is installed
if ! command -v nmap &> /dev/null
then
    echo "Error: nmap is not installed."
    echo "Please install nmap first (e.g., sudo apt install nmap on Kali Linux)."
    exit 1
fi

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Get the current date and time for the log file
SCAN_DATE=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="${LOG_DIR}/scan_${SCAN_DATE}.log"

echo ""
echo "Enter the Target IP Address (e.g., 127.0.0.1 for localhost):"
read -p "IP Address: " TARGET_IP

# Basic validation for IP address format (optional, nmap handles some errors)
if [[ ! "$TARGET_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Warning: The entered IP address format might be invalid. Proceeding anyway."
fi

echo ""
echo "Starting port scan on ${TARGET_IP}..."
echo "Results will be saved to ${LOG_FILE}"
echo "---------------------------------------"

# Perform the scan using nmap
# -F: Fast mode - Scans fewer ports than the default scan (top 1000 common ports)
# -oN: Output to normal file. This saves the output in a human-readable format.
# -Pn: Treat all hosts as online -- skip host discovery. Useful if target blocks ping.
nmap -F -oN "$LOG_FILE" -Pn "$TARGET_IP"

# Check the exit status of nmap
if [ $? -eq 0 ]; then
    echo "---------------------------------------"
    echo "Scan completed successfully!"
    echo "Results saved to: ${LOG_FILE}"
    echo ""
    echo "To view the results, use: cat ${LOG_FILE}"
else
    echo "---------------------------------------"
    echo "Scan encountered an error or was interrupted."
    echo "Please check the IP address and your network connectivity."
fi

echo "======================================="
echo "  Script Finished"
echo "======================================="

4. Step-by-Step Explanation of the Script
Let's break down what each part of the script does:
1.	#!/bin/bash: This is called a "shebang" and tells the operating system to execute the script using bash.
2.	Comments (#): Lines starting with # are comments, providing explanations and documentation for the script.
3.	LOG_DIR="./scan_logs": This line defines a variable LOG_DIR and sets its value to ./scan_logs. This means scan results will be saved in a directory named scan_logs in the same location where the script is run.
4.	echo "...": These commands print messages to the terminal, providing user-friendly output and guiding the user.
5.	if ! command -v nmap &> /dev/null: This is a crucial check.
o	command -v nmap: Tries to find the nmap executable in the system's PATH.
o	&> /dev/null: Redirects both standard output and standard error to /dev/null, effectively silencing any output from command -v.
o	!: Negates the result, so the if block executes if nmap is not found.
o	If nmap is not found, an error message is printed, and the script exits with exit 1 (indicating an error).
6.	mkdir -p "$LOG_DIR": This command creates the scan_logs directory. The -p option ensures that if the directory already exists, mkdir won't throw an error, and it will create parent directories if they don't exist.
7.	SCAN_DATE=$(date +"%Y-%m-%d_%H-%M-%S"): This command captures the current date and time.
o	date +"%Y-%m-%d_%H-%M-%S": Formats the date as YYYY-MM-DD_HH-MM-SS (e.g., 2023-10-27_14-30-05).
o	$(...): This is command substitution, meaning the output of the date command is assigned to the SCAN_DATE variable.
8.	LOG_FILE="${LOG_DIR}/scan_${SCAN_DATE}.log": This constructs the full path and filename for the log file, combining the LOG_DIR, the SCAN_DATE, and the .log extension.
9.	read -p "IP Address: " TARGET_IP: This prompts the user to enter the target IP address and stores the input in the TARGET_IP variable. The -p option allows specifying a prompt string.
10.	if [[ ! "$TARGET_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]: This is a basic regular expression check to see if the entered TARGET_IP looks like an IP address. It's a warning, not a strict validation, as nmap itself will handle invalid IPs.
11.	nmap -F -oN "$LOG_FILE" -Pn "$TARGET_IP": This is the core nmap command:
o	nmap: The command to run the Nmap scanner.
o	-F: This is the "Fast mode" option. Instead of scanning all 65535 possible ports, nmap -F scans the 1000 most common ports, significantly speeding up the scan.
o	-oN "$LOG_FILE": This option tells nmap to output the results in its "Normal" format to the specified LOG_FILE. This format is human-readable and easy to parse.
o	-Pn: This option tells nmap to skip the host discovery phase (i.e., don't try to ping the target first). This is useful if the target is configured to block ICMP (ping) requests, as nmap would otherwise assume the host is down and not scan it.
o	"$TARGET_IP": The IP address provided by the user.
12.	if [ $? -eq 0 ]: This checks the exit status of the previous command (nmap).
o	$?: This special bash variable holds the exit status of the last executed command. A value of 0 typically means the command executed successfully.
o	If nmap ran without errors, a success message is displayed; otherwise, an error message is shown.
13.	cat ${LOG_FILE}: This command is suggested to the user to view the contents of the generated log file.
5. Demonstration and How to Run
To run the script on your Kali Linux machine:
1.	Save the script: Open a text editor (like nano or gedit) and paste the script code into a new file. Save it as port_scanner.sh (or any .sh extension).
2.	nano port_scanner.sh

Paste the script, then Ctrl+O to save, Enter, and Ctrl+X to exit.
3.	Make it executable: Give the script execution permissions.
4.	chmod +x port_scanner.sh

5.	Run the script: Execute the script from your terminal.
6.	./port_scanner.sh

7.	Enter Target IP: When prompted, enter the IP address of the target you wish to scan.
o	For a safe test: You can use 127.0.0.1 (localhost) to scan your own machine.
o	For a public test target (with permission): scanme.nmap.org is a host provided by the Nmap project specifically for testing. Do not scan other public IPs without explicit permission.
Example output during execution:
=======================================
  Mini Port Scanner - Defensive Tool
=======================================

Enter the Target IP Address (e.g., 127.0.0.1 for localhost):
IP Address: 127.0.0.1

Starting port scan on 127.0.0.1...
Results will be saved to ./scan_logs/scan_2023-10-27_14-30-05.log
---------------------------------------
# Nmap output will appear here as it runs...
# ... then the summary messages from the script.
---------------------------------------
Scan completed successfully!
Results saved to: ./scan_logs/scan_2023-10-27_14-30-05.log

To view the results, use: cat ./scan_logs/scan_2023-10-27_14-30-05.log
=======================================
  Script Finished
=======================================

8.	View Results: Use the cat command (as suggested by the script) to view the full nmap output.
9.	cat ./scan_logs/scan_2023-10-27_14-30-05.log

(Replace the date/time with your actual log file name.)
6. Understanding the Results
The nmap output in your log file will show a table of scanned ports and their states. Here's what the different states mean:
•	open: This indicates that an application is actively listening for connections on that port. This is the most significant finding, as it means there's a service running that could potentially be interacted with (e.g., a web server, an SSH server).
o	Example: 80/tcp open http (A web server is running on port 80 using TCP).
•	closed: This means the port is accessible, but no application is listening on it. The target received the probe and responded that no service is available. While not directly exploitable, it confirms the host is online.
•	filtered: This state means that nmap cannot determine if the port is open or closed because a firewall, router, or other network device is blocking the probes. This often indicates that the port is protected by a security mechanism.
o	Example: 22/tcp filtered ssh (Port 22, typically for SSH, is being blocked by a firewall).
Common Ports and Services We Might See:
Port	Protocol	Service	Description
21	TCP	FTP	File Transfer Protocol
22	TCP	SSH	Secure Shell (for remote command-line access)
23	TCP	Telnet	Unencrypted remote command-line access (less secure)
25	TCP	SMTP	Simple Mail Transfer Protocol (sending email)
53	TCP/UDP	DNS	Domain Name System (resolving domain names to IPs)
80	TCP	HTTP	Hypertext Transfer Protocol (web traffic)
110	TCP	POP3	Post Office Protocol v3 (receiving email)
139	TCP	NetBIOS Session	Windows file and printer sharing
443	TCP	HTTPS	Secure HTTP (encrypted web traffic)
445	TCP	SMB	Server Message Block (Windows file sharing)
3389	TCP	RDP	Remote Desktop Protocol (Windows remote access)
8080	TCP	HTTP Proxy/Alt	Common alternative HTTP port
7. Why Port Scanning Matters (Defensive Perspective)
From a security standpoint, understanding port scanning is invaluable for defense:
•	Attack Surface Reduction: By regularly scanning your own systems, you can identify open ports that are not needed. Closing unnecessary ports reduces your "attack surface" – the number of potential entry points an attacker could exploit.
•	Vulnerability Management: An open port running an old or unpatched service is a significant risk. Port scanning helps you discover these services, allowing you to patch them or remove them.
•	Firewall Verification: You can use a port scanner to verify that your firewalls are correctly configured and blocking access to ports that should not be publicly accessible.
•	Compliance and Auditing: Many security standards require regular network scanning to ensure only authorized services are exposed.
8. Ethical Considerations
While port scanning is a fundamental tool for network defense and analysis, it's crucial to understand its ethical and legal implications:
•	Permission is Paramount: Never scan systems or networks that you do not own or for which you do not have explicit, written permission from the owner. Unauthorized scanning can be considered a form of trespass or even a precursor to an attack, leading to legal consequences.
•	Responsible Use: Use this tool responsibly and for educational or authorized professional purposes only.
9. Conclusion
This mini port scanner script, powered by nmap, provides a practical introduction to identifying active services on a network. By understanding how to use such tools and interpret their output, you gain valuable insights into your network's security posture. Remember, the goal is to use this knowledge to strengthen your defenses, not to compromise others. Regular, authorized port scanning is a key practice in maintaining a secure and resilient network environment.

BASH CODE :-

#!/bin/bash

# Mini Port Scanner Script
# This script uses nmap to scan the top 1000 common ports on a target IP address.
# The results are saved to a log file named 'scan_<date>.log'.
#
# IMPORTANT: Only use this script on networks or systems for which you have explicit permission.
# Unauthorized port scanning can be illegal and unethical.

# --- Configuration ---
LOG_DIR="./scan_logs" # Directory to store scan logs

# --- Script Start ---

echo "======================================="
echo "  Mini Port Scanner - Defensive Tool"
echo "======================================="

# Check if nmap is installed
if ! command -v nmap &> /dev/null
then
    echo "Error: nmap is not installed."
    echo "Please install nmap first (e.g., sudo apt install nmap on Kali Linux)."
    exit 1
fi

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Get the current date and time for the log file
SCAN_DATE=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="${LOG_DIR}/scan_${SCAN_DATE}.log"

echo ""
echo "Enter the Target IP Address (e.g., 127.0.0.1 for localhost):"
read -p "IP Address: " TARGET_IP

# Basic validation for IP address format (optional, nmap handles some errors)
if [[ ! "$TARGET_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Warning: The entered IP address format might be invalid. Proceeding anyway."
fi

echo ""
echo "Starting port scan on ${TARGET_IP}..."
echo "Results will be saved to ${LOG_FILE}"
echo "---------------------------------------"

# Perform the scan using nmap
# -F: Fast mode - Scans fewer ports than the default scan (top 1000 common ports)
# -oN: Output to normal file. This saves the output in a human-readable format.
# -Pn: Treat all hosts as online -- skip host discovery. Useful if target blocks ping.
nmap -F -oN "$LOG_FILE" -Pn "$TARGET_IP"

# Check the exit status of nmap
if [ $? -eq 0 ]; then
    echo "---------------------------------------"
    echo "Scan completed successfully!"
    echo "Results saved to: ${LOG_FILE}"
    echo ""
    echo "To view the results, use: cat ${LOG_FILE}"
else
    echo "---------------------------------------"
    echo "Scan encountered an error or was interrupted."
    echo "Please check the IP address and your network connectivity."
fi
echo "======================================="
echo "  Script Finished"
echo "======================================="
