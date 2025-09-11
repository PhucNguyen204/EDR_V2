# EDR_V2 Troubleshooting Guide

## 🚨 Common Issues & Solutions

### 1. Container Network Issues

#### Problem: Cannot ping target from attacker
```
PING 172.19.0.2 (172.19.0.2) 56(84) bytes of data.
From 172.19.0.4 icmp_seq=1 Destination Host Unreachable
```

**Solution:**
```bash
# Check if containers are on same network
docker inspect edr-attack-network

# Reconnect containers
docker network connect edr-attack-network deploy-ubuntu-agent-1
docker network connect edr-attack-network attacker-ubuntu

# Verify IPs
docker exec deploy-ubuntu-agent-1 hostname -I
docker exec attacker-ubuntu hostname -I
```

#### Problem: Containers have wrong IP addresses

**Solution:**
```bash
# Check current network assignment
docker inspect deploy-ubuntu-agent-1 | findstr NetworkMode
docker inspect edr-attack-network

# Force reconnect with specific IP (optional)
docker network disconnect edr-attack-network deploy-ubuntu-agent-1
docker network connect --ip 172.19.0.2 edr-attack-network deploy-ubuntu-agent-1
```

### 2. SSH Service Issues

#### Problem: SSH connection refused
```
[ERROR] could not connect to ssh://172.19.0.2:22 - Connection refused
```

**Solution:**
```bash
# Check if SSH is running
docker exec deploy-ubuntu-agent-1 ps aux | grep sshd

# Start SSH service
docker exec deploy-ubuntu-agent-1 bash -c "
mkdir -p /run/sshd
pkill sshd 2>/dev/null
/usr/sbin/sshd
"

# Verify SSH is listening
docker exec deploy-ubuntu-agent-1 lsof -i :22
```

#### Problem: SSH authentication issues
```
[INFO] Testing if password authentication is supported by ssh://172.19.0.2:22
[ERROR] Password authentication not supported
```

**Solution:**
```bash
# Enable password authentication
docker exec deploy-ubuntu-agent-1 bash -c "
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
pkill sshd
/usr/sbin/sshd
"
```

### 3. Vector Agent Issues

#### Problem: Vector agent not starting
```
vector::cli: Configuration error. error=unknown field `interval`
```

**Solution:**
```bash
# Check Vector configuration
docker exec deploy-ubuntu-agent-1 cat /etc/vector/vector.toml

# Restart Vector with correct config
docker-compose restart ubuntu-agent

# Check Vector logs
docker logs deploy-ubuntu-agent-1 --tail 10
```

#### Problem: Vector not collecting logs
```
No events being sent to EDR server
```

**Solution:**
```bash
# Check log files exist
docker exec deploy-ubuntu-agent-1 ls -la /var/log/

# Check Vector sources
docker exec deploy-ubuntu-agent-1 bash -c "
# Test lastb command
lastb -n 5 2>/dev/null || echo 'No btmp data'

# Check auth.log
tail -3 /var/log/auth.log 2>/dev/null || echo 'No auth.log'
"

# Restart rsyslog
docker exec deploy-ubuntu-agent-1 /usr/sbin/rsyslogd
```

### 4. EDR Detection Issues

#### Problem: No detections in EDR logs
```
2025/09/11 10:55:37 /ingest accepted=0 matched=0 errors=0
```

**Solution:**
```bash
# Check if events are being sent
docker logs deploy-ubuntu-agent-1 | grep -i error

# Check EDR server is running
docker logs deploy-edr-server-1 --tail 5

# Verify Sigma rules loaded
docker logs deploy-edr-server-1 | grep "Compiled rules"

# Test with manual event
docker exec deploy-ubuntu-agent-1 bash -c "
echo '{\"timestamp\":\"$(date -Iseconds)\",\"hostname\":\"test\",\"message\":\"test event\"}' >> /data/events.ndjson
"
```

#### Problem: Events sent but no matches
```
2025/09/11 10:55:37 /ingest accepted=5 matched=0 errors=0
```

**Solution:**
```bash
# Check event format in EDR logs
docker logs deploy-edr-server-1 | grep "event="

# Verify Vector transform is working
docker exec deploy-ubuntu-agent-1 bash -c "
# Check if Vector is processing correctly
vector test /etc/vector/vector.toml --input-text 'test log line'
"
```

### 5. Attack Tool Issues

#### Problem: Hydra not installed in attacker
```
bash: hydra: command not found
```

**Solution:**
```bash
# Install attack tools
docker exec attacker-ubuntu bash -c "
apt update
apt install -y hydra nmap netcat-traditional sshpass curl wget
"
```

#### Problem: Hydra timeout errors
```
[ERROR] could not connect to ssh://172.19.0.2:22 - Timeout connecting
```

**Solution:**
```bash
# Test basic connectivity first
docker exec attacker-ubuntu ping -c 2 172.19.0.2
docker exec attacker-ubuntu telnet 172.19.0.2 22

# Use longer timeout
hydra -l testuser -p wrongpass ssh://172.19.0.2 -t 1 -w 10
```

### 6. Log File Issues

#### Problem: No SSH logs being generated
```
cat: /var/log/auth.log: No such file or directory
```

**Solution:**
```bash
# Create log files and start rsyslog
docker exec deploy-ubuntu-agent-1 bash -c "
mkdir -p /var/log
touch /var/log/auth.log /var/log/syslog
chown syslog:adm /var/log/auth.log /var/log/syslog
pkill rsyslogd 2>/dev/null
/usr/sbin/rsyslogd
"
```

#### Problem: Empty btmp/wtmp files
```
lastb: /var/log/btmp: No such file or directory
```

**Solution:**
```bash
# Create utmp files
docker exec deploy-ubuntu-agent-1 bash -c "
touch /var/log/btmp /var/log/wtmp
chmod 664 /var/log/btmp /var/log/wtmp
chown root:utmp /var/log/btmp /var/log/wtmp
"
```

## 🔧 Diagnostic Commands

### System Health Check
```bash
# Check all containers
docker ps

# Check networks
docker network ls
docker inspect edr-attack-network

# Check logs
docker logs deploy-edr-server-1 --tail 5
docker logs deploy-ubuntu-agent-1 --tail 5
```

### Service Status Check
```bash
# In target container
docker exec deploy-ubuntu-agent-1 bash -c "
echo 'SSH Status:'
ps aux | grep sshd | grep -v grep
echo 'Rsyslog Status:'  
ps aux | grep rsyslog | grep -v grep
echo 'Vector Status:'
ps aux | grep vector | grep -v grep
echo 'Listening Ports:'
lsof -i :22 2>/dev/null || echo 'Port 22 not listening'
"
```

### Network Connectivity Test
```bash
# From attacker to target
docker exec attacker-ubuntu bash -c "
echo 'Ping test:'
ping -c 2 172.19.0.2
echo 'Port test:'
telnet 172.19.0.2 22 < /dev/null
echo 'SSH test:'
ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no testuser@172.19.0.2 exit 2>/dev/null && echo 'SSH OK' || echo 'SSH Failed'
"
```

## 🚀 Reset Procedures

### Complete System Reset
```bash
# Stop all containers
docker-compose down

# Remove containers
docker rm -f attacker-ubuntu

# Remove network (optional)
docker network rm edr-attack-network

# Recreate everything
docker-compose up -d
docker run -it --name attacker-ubuntu --network edr-attack-network ubuntu:22.04 bash
```

### Soft Reset (Keep containers)
```bash
# Restart services
docker-compose restart

# Reconnect network
docker network connect edr-attack-network deploy-ubuntu-agent-1

# Clear logs in target
docker exec deploy-ubuntu-agent-1 bash -c "
> /var/log/auth.log
> /var/log/syslog
> /var/log/btmp  
> /var/log/wtmp
"
```

### Target Container Reset
```bash
# Reset SSH and logs
docker exec deploy-ubuntu-agent-1 bash -c "
pkill sshd rsyslogd 2>/dev/null
rm -f /run/sshd.pid /run/rsyslogd.pid
mkdir -p /run/sshd /var/log
> /var/log/auth.log
> /var/log/syslog
/usr/sbin/rsyslogd
/usr/sbin/sshd
echo 'Target reset complete'
"
```

## 📊 Performance Monitoring

### Check Detection Rate
```bash
# Count total events processed
docker logs deploy-edr-server-1 | grep "accepted=" | tail -5

# Count detections
docker logs deploy-edr-server-1 | grep "DETECT" | wc -l

# Calculate detection rate
EVENTS=$(docker logs deploy-edr-server-1 | grep "accepted=" | tail -1 | sed 's/.*accepted=\([0-9]*\).*/\1/')
DETECTS=$(docker logs deploy-edr-server-1 | grep "matched=" | tail -1 | sed 's/.*matched=\([0-9]*\).*/\1/')
echo "Detection Rate: $DETECTS/$EVENTS"
```

### Monitor Real-time
```bash
# Monitor EDR detections real-time
docker logs -f deploy-edr-server-1 &

# Monitor Vector agent real-time  
docker logs -f deploy-ubuntu-agent-1 &

# Monitor SSH attacks real-time
docker exec deploy-ubuntu-agent-1 tail -f /var/log/auth.log &
```

## ✅ Success Criteria

### Expected Behavior
- **Network**: Ping successful between containers
- **SSH**: Connection accepted, authentication working
- **Logs**: Failed attempts in btmp, successful logins in auth.log
- **Vector**: Events being collected and sent to EDR
- **EDR**: 100% detection rate for SSH attacks
- **Performance**: Events processed within seconds

### Expected Log Output
```
# EDR Server
2025/09/11 10:55:37 DETECT idx=0 rules=[...] event=ssh connection attempt
2025/09/11 10:55:37 /ingest accepted=8 matched=8 errors=0

# Target Auth Log  
Sep 11 10:55:17 target sshd[1787]: Failed password for testuser from 172.19.0.4
Sep 11 10:55:21 target sshd[1787]: Accepted password for testuser from 172.19.0.4

# Failed Logins
admin    ssh:notty    172.19.0.4       Thu Sep 11 10:55 - 10:55  (00:00)
testuser ssh:notty    172.19.0.4       Thu Sep 11 10:55 - 10:55  (00:00)
```

---
**🎯 Goal: 100% attack detection with zero false negatives**
