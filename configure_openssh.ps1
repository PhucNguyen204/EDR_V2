# Script cấu hình OpenSSH để log authentication failures
# Chạy với quyền Administrator

Write-Host "=== CẤU HÌNH OPENSSH ĐỂ LOG AUTHENTICATION FAILURES ===" -ForegroundColor Yellow

# Backup config file
$configPath = "C:\ProgramData\ssh\sshd_config"
$backupPath = "C:\ProgramData\ssh\sshd_config.backup"

if (Test-Path $configPath) {
    Copy-Item $configPath $backupPath -Force
    Write-Host "Đã backup config file: $backupPath" -ForegroundColor Green
}

# Đọc config hiện tại
$config = Get-Content $configPath

# Các cài đặt cần thiết
$requiredSettings = @{
    "LogLevel" = "VERBOSE"
    "SyslogFacility" = "AUTH"
    "PasswordAuthentication" = "yes"
    "PermitEmptyPasswords" = "no"
    "MaxAuthTries" = "3"
    "LoginGraceTime" = "30"
}

Write-Host "`nCập nhật OpenSSH config..." -ForegroundColor Green

# Cập nhật từng setting
foreach ($setting in $requiredSettings.GetEnumerator()) {
    $settingName = $setting.Key
    $settingValue = $setting.Value
    
    # Tìm và thay thế setting cũ
    $found = $false
    for ($i = 0; $i -lt $config.Length; $i++) {
        if ($config[$i] -match "^#?$settingName\s+") {
            $config[$i] = "$settingName $settingValue"
            Write-Host "Cập nhật: $settingName $settingValue" -ForegroundColor Yellow
            $found = $true
            break
        }
    }
    
    # Nếu không tìm thấy, thêm mới
    if (-not $found) {
        $config += "$settingName $settingValue"
        Write-Host "Thêm mới: $settingName $settingValue" -ForegroundColor Yellow
    }
}

# Ghi config mới
$config | Set-Content $configPath -Encoding UTF8
Write-Host "`nĐã cập nhật OpenSSH config" -ForegroundColor Green

# Restart OpenSSH service
Write-Host "`nRestart OpenSSH service..." -ForegroundColor Green
try {
    Restart-Service -Name "sshd" -Force
    Start-Sleep -Seconds 3
    $sshService = Get-Service -Name "sshd"
    Write-Host "OpenSSH service status: $($sshService.Status)" -ForegroundColor Green
} catch {
    Write-Host "Lỗi restart OpenSSH: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== CẤU HÌNH HOÀN TẤT ===" -ForegroundColor Green
Write-Host "Bây giờ OpenSSH sẽ log authentication failures vào Windows Security log" -ForegroundColor White
Write-Host "Chạy brute_force.ps1 để test detection" -ForegroundColor White
