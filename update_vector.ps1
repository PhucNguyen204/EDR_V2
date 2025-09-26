# Simple Vector config update script
Write-Host "=== Vector Config Auto-Update Script ===" -ForegroundColor Green

# 1. Find latest log file
Write-Host "`n1. Finding latest Winlogbeat log file..."
$latestLogFile = Get-ChildItem -Path "C:\Winlogbeat\logs" -Filter "*.ndjson" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 1

if (-not $latestLogFile) {
    Write-Host "ERROR: No log files found" -ForegroundColor Red
    exit 1
}

Write-Host "Latest log file: $($latestLogFile.Name)" -ForegroundColor Green
Write-Host "Size: $([math]::Round($latestLogFile.Length / 1MB, 2)) MB"
Write-Host "Last Modified: $($latestLogFile.LastWriteTime)"

# 2. Backup current config
Write-Host "`n2. Backing up current Vector config..."
$backupPath = "C:\Vector\vector.toml.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item "C:\Vector\vector.toml" $backupPath
Write-Host "Backup saved to: $backupPath" -ForegroundColor Green

# 3. Update config with specific file
Write-Host "`n3. Updating Vector config with specific file..."
$configContent = Get-Content "C:\Vector\vector.toml" -Raw
$specificFile = $latestLogFile.FullName
$newIncludeLine = "  include = [""$specificFile""]"

# Replace include line
$pattern = 'include\s*=\s*\[.*?\]'
$updatedConfig = $configContent -replace $pattern, $newIncludeLine

# Write new config
Set-Content -Path "C:\Vector\vector.toml" -Value $updatedConfig -Encoding UTF8
Write-Host "Config updated with file: $($latestLogFile.Name)" -ForegroundColor Green

# 4. Restart Vector
Write-Host "`n4. Restarting Vector..."
Write-Host "Stopping Vector processes..."
Get-Process | Where-Object {$_.ProcessName -like "*vector*"} | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "Waiting 3 seconds..."
Start-Sleep -Seconds 3

Write-Host "Starting Vector with new config..."
Start-Process -FilePath "C:\Vector\bin\vector.exe" -ArgumentList "--config", "C:\Vector\vector.toml" -WindowStyle Hidden

Write-Host "Waiting 10 seconds for Vector to start..."
Start-Sleep -Seconds 10

# 5. Check Vector status
Write-Host "`n5. Checking Vector status..."
$vectorProcesses = Get-Process | Where-Object {$_.ProcessName -like "*vector*"}
if ($vectorProcesses) {
    Write-Host "Vector is running:" -ForegroundColor Green
    $vectorProcesses | Select-Object ProcessName, Id, CPU, WorkingSet | Format-Table -AutoSize
} else {
    Write-Host "Vector failed to start" -ForegroundColor Red
    exit 1
}

# 6. Test with some events
Write-Host "`n6. Testing Vector with some events..."
Write-Host "Running test processes..."
powershell -Command "Get-Process | Where-Object {`$_.ProcessName -like '*test*'} | Stop-Process -Force" | Out-Null
cmd /c "echo Test Vector update && whoami" | Out-Null

Write-Host "Waiting 5 seconds for Vector to process..."
Start-Sleep -Seconds 5

# 7. Check Vector output
Write-Host "`n7. Checking Vector output..."
$outputFile = "C:\Vector\out\all-events.ndjson"
if (Test-Path $outputFile) {
    $fileInfo = Get-Item $outputFile
    Write-Host "Vector output file:" -ForegroundColor Green
    Write-Host "File: $($fileInfo.Name)"
    Write-Host "Size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB"
    Write-Host "Last Modified: $($fileInfo.LastWriteTime)"
    
    Write-Host "`nLast 3 events:"
    Get-Content $outputFile -Tail 3 | ForEach-Object {
        try {
            $event = $_ | ConvertFrom-Json
            Write-Host "- Event Type: $($event.event_type) | Event ID: $($event.EventID) | Image: $($event.Image)"
        } catch {
            Write-Host "- Raw: $_"
        }
    }
} else {
    Write-Host "Vector output file not found" -ForegroundColor Red
}

Write-Host "`n=== Vector Config Update Completed ===" -ForegroundColor Green
Write-Host "Vector updated and restarted with latest log file" -ForegroundColor Green
Write-Host "Reading from: $($latestLogFile.Name)" -ForegroundColor Cyan
Write-Host "Config backup: $backupPath" -ForegroundColor Cyan
