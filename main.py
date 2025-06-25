import os
import re
from collections import defaultdict

# List of sensitive URL paths to monitor for potential unauthorized access attempts
SENSITIVE_PATHS = [
    "/admin",
    "/wp-login.php",
    "/config.php",
    "/.env",
    "/backup",
    "/phpmyadmin",
    "/login",
    "/etc/passwd",
    "/shell",
    "/robots.txt"
]

# Regex pattern to parse Apache Common Log Format entries
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<date>.*?)\] '      # IP address and timestamp
    r'"(?P<method>\S+)\s(?P<url>\S+)\s(?P<protocol>[^"]+)" '  # HTTP method, URL, protocol
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'          # Status code and bytes transferred
)

def parse_log_line(line):
    """
    Parse a single log line using the regex pattern.
    Returns a dictionary of extracted fields if matched, else None.
    """
    match = log_pattern.match(line)
    if match:
        return match.groupdict()
    return None

def main():
    # Determine absolute paths for input log file and output report file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    log_file_path = os.path.join(current_dir, "sample_logs", "access.log")
    output_file_path = os.path.join(current_dir, "suspicious_report.txt")
    
    print(f"Looking for log file at: {log_file_path}")

    # Trackers for suspicious activities:
    failed_logins = defaultdict(int)          # Count of failed login attempts per IP (status 401)
    urls_per_ip = defaultdict(set)             # Unique URLs accessed per IP to detect scanning
    sensitive_accesses = defaultdict(set)      # Sensitive paths accessed per IP
    report_lines = []                          # Lines to be written to the final report

    try:
        with open(log_file_path, "r") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    ip = parsed['ip']
                    status = parsed['status']
                    url = parsed['url']

                    # Count failed login attempts (HTTP 401 Unauthorized)
                    if status == '401':
                        failed_logins[ip] += 1

                    # Track unique URLs visited by each IP
                    urls_per_ip[ip].add(url)

                    # Detect access to sensitive URL paths
                    if url in SENSITIVE_PATHS:
                        sensitive_accesses[ip].add(url)

        # Prepare suspicious activity report header
        report_lines.append("=== Suspicious Activity Report ===\n")

        # Report IPs with multiple failed login attempts
        for ip, count in failed_logins.items():
            if count >= 2:
                alert = f"[!] {ip} has {count} failed login attempts."
                print(alert)
                report_lines.append(alert)

        # Report IPs accessing many unique URLs (possible scanning)
        for ip, urls in urls_per_ip.items():
            if len(urls) >= 4:
                alert = f"[!] {ip} accessed {len(urls)} unique URLs (possible scanning)."
                print(alert)
                report_lines.append(alert)

        # Report IPs accessing sensitive paths
        for ip, sensitive_urls in sensitive_accesses.items():
            alert = f"[!] {ip} accessed sensitive path(s): {', '.join(sensitive_urls)}"
            print(alert)
            report_lines.append(alert)

        # Write the aggregated report to a text file
        with open(output_file_path, "w") as f_out:
            for line in report_lines:
                f_out.write(line + "\n")

        print(f"\nReport saved to: {output_file_path}")

    except FileNotFoundError:
        print("🚫 Log file not found. Double-check 'sample_logs/access.log' exists.")

if __name__ == "__main__":
    main()
