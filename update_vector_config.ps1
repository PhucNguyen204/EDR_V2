# Script để tự động cập nhật Vector config với file log mới nhất
param(
    [string]$VectorConfigPath = "C:\Vector\vector.toml",
    [string]$WinlogbeatLogPath = "C:\Winlogbeat\logs"
)

Write-Host "=== Vector Config Auto-Update Script ===" -ForegroundColor Green

# 1. Tìm file log mới nhất
Write-Host "`n1. Tìm file Winlogbeat log mới nhất..."
$latestLogFile = Get-ChildItem -Path $WinlogbeatLogPath -Filter "*.ndjson" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 1

if (-not $latestLogFile) {
    Write-Host "❌ Không tìm thấy file log nào trong $WinlogbeatLogPath" -ForegroundColor Red
    exit 1
}

Write-Host "✅ File log mới nhất: $($latestLogFile.Name)" -ForegroundColor Green
Write-Host "   Size: $([math]::Round($latestLogFile.Length / 1MB, 2)) MB"
Write-Host "   Last Modified: $($latestLogFile.LastWriteTime)"

# 2. Backup config hiện tại
Write-Host "`n2. Backup Vector config hiện tại..."
$backupPath = "$VectorConfigPath.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item $VectorConfigPath $backupPath
Write-Host "✅ Backup saved to: $backupPath" -ForegroundColor Green

# 3. Đọc config hiện tại
Write-Host "`n3. Đọc Vector config hiện tại..."
$configContent = Get-Content $VectorConfigPath -Raw

# 4. Cập nhật include path với file cụ thể
Write-Host "`n4. Cập nhật include path với file cụ thể..."
$specificFile = $latestLogFile.FullName
$newIncludeLine = "  include = [""$specificFile""]"

# Tìm và thay thế dòng include
$pattern = 'include\s*=\s*\[.*?\]'
$updatedConfig = $configContent -replace $pattern, $newIncludeLine

# 5. Ghi config mới
Write-Host "`n5. Ghi Vector config mới..."
Set-Content -Path $VectorConfigPath -Value $updatedConfig -Encoding UTF8
Write-Host "✅ Config đã được cập nhật với file: $($latestLogFile.Name)" -ForegroundColor Green

# 6. Validate config
Write-Host "`n6. Validate Vector config..."
try {
    $validationResult = & "C:\Vector\bin\vector.exe" validate --config-dir "C:\Vector" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Vector config validation thành công" -ForegroundColor Green
    } else {
        Write-Host "❌ Vector config validation thất bại:" -ForegroundColor Red
        Write-Host $validationResult
        # Restore backup
        Copy-Item $backupPath $VectorConfigPath
        Write-Host "🔄 Đã restore config từ backup" -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "❌ Không thể validate Vector config: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 7. Restart Vector
Write-Host "`n7. Restart Vector service..."
Write-Host "   Stopping Vector processes..."
Get-Process | Where-Object {$_.ProcessName -like "*vector*"} | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "   Waiting 3 seconds..."
Start-Sleep -Seconds 3

Write-Host "   Starting Vector with new config..."
Start-Process -FilePath "C:\Vector\bin\vector.exe" -ArgumentList "--config", $VectorConfigPath -WindowStyle Hidden

Write-Host "   Waiting 10 seconds for Vector to start..."
Start-Sleep -Seconds 10

# 8. Kiểm tra Vector status
Write-Host "`n8. Kiểm tra Vector status..."
$vectorProcesses = Get-Process | Where-Object {$_.ProcessName -like "*vector*"}
if ($vectorProcesses) {
    Write-Host "✅ Vector đang chạy:" -ForegroundColor Green
    $vectorProcesses | Select-Object ProcessName, Id, CPU, WorkingSet | Format-Table -AutoSize
} else {
    Write-Host "❌ Vector không chạy được" -ForegroundColor Red
    exit 1
}

# 9. Test với một số events
Write-Host "`n9. Test Vector với một số events..."
Write-Host "   Chạy một số tiến trình test..."
powershell -Command "Get-Process | Where-Object {`$_.ProcessName -like '*test*'} | Stop-Process -Force" | Out-Null
cmd /c "echo Test Vector update && whoami" | Out-Null

Write-Host "   Chờ 5 giây để Vector xử lý..."
Start-Sleep -Seconds 5

# 10. Kiểm tra Vector output
Write-Host "`n10. Kiểm tra Vector output..."
$outputFile = "C:\Vector\out\all-events.ndjson"
if (Test-Path $outputFile) {
    $fileInfo = Get-Item $outputFile
    Write-Host "✅ Vector output file:" -ForegroundColor Green
    Write-Host "   File: $($fileInfo.Name)"
    Write-Host "   Size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB"
    Write-Host "   Last Modified: $($fileInfo.LastWriteTime)"
    
    Write-Host "`n   Last 3 events:"
    Get-Content $outputFile -Tail 3 | ForEach-Object {
        try {
            $event = $_ | ConvertFrom-Json
            Write-Host "   - Event Type: $($event.event_type) | Event ID: $($event.EventID) | Image: $($event.Image)"
        } catch {
            Write-Host "   - Raw: $_"
        }
    }
} else {
    Write-Host "❌ Vector output file không tồn tại" -ForegroundColor Red
}

Write-Host "`n=== Vector Config Update Completed ===" -ForegroundColor Green
Write-Host "Vector da duoc cap nhat va restart voi file log moi nhat" -ForegroundColor Green
Write-Host "File log dang duoc doc: $($latestLogFile.Name)" -ForegroundColor Cyan
Write-Host "Config backup: $backupPath" -ForegroundColor Cyan
