import re

def analyze_logs(file):
    print("SIEM LOG ANALYZER STARTED\n")

    with open(file, "r") as f:
        logs = f.readlines()

    failed_attempts = {}
    suspicious_ips = set()

    for log in logs:
        if "login failed" in log:
            user = log.split()[0]
            failed_attempts[user] = failed_attempts.get(user, 0) + 1

        ip_match = re.findall(r"(\d+\.\d+\.\d+\.\d+)", log)
        if ip_match:
            suspicious_ips.add(ip_match[0])

    for user, count in failed_attempts.items():
        if count >= 5:
            print(f"[+] Brute force detected: {user}")

    for ip in suspicious_ips:
        print(f"[+] Suspicious IP: {ip}")

    print("\nScan complete")

if __name__ == "__main__":
    analyze_logs("logs.txt")
