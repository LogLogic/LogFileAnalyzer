# Log File Analyzer

A Python script to analyze Apache access logs for suspicious activity, including failed login detection, URL scanning, and sensitive path monitoring with detailed alert reporting.

---
## Features

- **Apache Log Parsing**: Extracts key fields (IP address, timestamp, HTTP method, URL, status code, bytes) from Apache Common Log Format logs.  
- **Failed Login Detection**: Identifies multiple HTTP 401 Unauthorized responses from the same IP, flagging potential brute-force attacks.  
- **URL Scanning Detection**: Detects IPs accessing multiple unique URLs, indicating possible reconnaissance or scanning behavior.  
- **Sensitive Path Monitoring**: Flags accesses to critical or sensitive paths such as `/admin`, `/wp-login.php`, and `/config.php`.  
- **Aggregated Alert Reporting**: Summarizes suspicious activities by IP address for easy review.  
- **Human-Readable Report Export**: Generates and saves a clear text report (`suspicious_report.txt`) summarizing findings.  
- **Command-Line Friendly**: Runs easily via terminal or VS Code with minimal setup.  
- **Modular Codebase**: Clean, well-organized Python script using regex and data structures for efficient log analysis.

---
## Requirements

- Python 3.x installed  
- Access to Apache access log file (or sample provided)

---
## Setup

1. Clone or download this repository  
2. Place your Apache access log file as:  
   sample_logs/access.log

---
### Running the Script

In your terminal or command prompt, navigate to the project folder and run:

python3 main.py

The script will:

Parse the log file

Print suspicious activity to the terminal

Save a summary report as suspicious_report.txt
