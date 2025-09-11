# EDR_V2 Quick Command Reference

## 🚀 System Startup
```bash
# Start EDR system
cd C:\Users\admin\EDR_V2\EDR_V2\deploy
docker-compose up -d

# Create attacker container  
docker run -it --name attacker-ubuntu --network edr-attack-network ubuntu:22.04 bash

# Connect containers to network
docker network connect edr-attack-network deploy-ubuntu-agent-1
```

## 🔍 IP Discovery
```bash
# Get target IP
docker exec deploy-ubuntu-agent-1 hostname -I
# Expected: 172.18.0.3 172.19.0.2

# Get attacker IP  
docker exec attacker-ubuntu hostname -I
# Expected: 172.19.0.4

# Check network topology
docker inspect edr-attack-network | findstr IPv4Address
```

## ⚔️ Quick Attacks
```bash
# In attacker container (replace TARGET_IP with actual IP)
TARGET_IP="172.19.0.2"

# Test connectivity
ping -c 2 $TARGET_IP

# SSH brute force (will fail)
hydra -l testuser -p wrongpass ssh://$TARGET_IP -t 1 -v
hydra -l admin -p badpass ssh://$TARGET_IP -t 1 -v

# SSH brute force (will succeed)  
hydra -l testuser -p 123456 ssh://$TARGET_IP -t 1 -v

# Port scan
nmap -p 22 $TARGET_IP
```

## 📊 Check Detection Results
```bash
# EDR detection logs (real-time)
docker logs -f deploy-edr-server-1

# EDR detection logs (recent)
docker logs deploy-edr-server-1 --tail 10

# Target SSH logs
docker exec deploy-ubuntu-agent-1 cat /var/log/auth.log | tail -5

# Failed login attempts
docker exec deploy-ubuntu-agent-1 lastb -n 10

# Successful logins
docker exec deploy-ubuntu-agent-1 last -n 5
```

## 🛠️ Setup Target (One-time)
```bash
# Setup SSH server in target
docker exec deploy-ubuntu-agent-1 bash -c "
apt update && apt install -y openssh-server rsyslog
useradd -m -s /bin/bash testuser
useradd -m -s /bin/bash admin  
echo 'testuser:123456' | chpasswd
echo 'admin:password' | chpasswd
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
mkdir -p /run/sshd
/usr/sbin/rsyslogd
/usr/sbin/sshd
echo 'Target ready!'
"
```

## 🛠️ Setup Attacker (One-time)
```bash
# Install attack tools in attacker
docker exec attacker-ubuntu bash -c "
apt update
apt install -y hydra nmap netcat-traditional sshpass curl wget
echo 'Attacker ready!'
"
```

## 🔧 Common Issues & Fixes

### Network connectivity issues:
```bash
docker network connect edr-attack-network deploy-ubuntu-agent-1
docker network connect edr-attack-network attacker-ubuntu
```

### SSH not running:
```bash
docker exec deploy-ubuntu-agent-1 bash -c "
mkdir -p /run/sshd
pkill sshd 2>/dev/null
/usr/sbin/sshd
"
```

### Vector agent issues:
```bash
docker-compose restart ubuntu-agent
docker logs deploy-ubuntu-agent-1 --tail 5
```

## 📈 Expected Detection Output
When attacks are successful, you should see:
```
2025/09/11 10:55:37 DETECT idx=0 rules=[1fc0809e-06bf-4de3-ad52-25e5263b7623] event=ssh connection attempt
2025/09/11 10:55:37 DETECT idx=1 rules=[1fc0809e-06bf-4de3-ad52-25e5263b7623] event=ssh connection attempt
2025/09/11 10:55:37 /ingest accepted=8 matched=8 errors=0
```

Target logs should show:
```
admin    ssh:notty    172.19.0.4       Thu Sep 11 10:55 - 10:55  (00:00)
testuser ssh:notty    172.19.0.4       Thu Sep 11 10:55 - 10:55  (00:00)
```

## 🎯 Attack Flow Summary
1. **Start system**: `docker-compose up -d`
2. **Setup target**: Install SSH, create users, start services
3. **Setup attacker**: Install tools (hydra, nmap, etc.)
4. **Check IPs**: Target should be `172.19.0.2`, attacker `172.19.0.4`
5. **Attack**: Run hydra/nmap commands from attacker
6. **Verify**: Check EDR logs for detections and target logs for events
7. **Success**: 100% detection rate with real attack logs

---
**🚨 Detection Rate Goal: 100%**  
**🔗 Target IP: 172.19.0.2 | Attacker IP: 172.19.0.4**
