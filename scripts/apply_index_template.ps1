Param(
  [string]$EsUrl = 'http://localhost:9200',
  [string]$EnvFile = "$PSScriptRoot/../deploy/elastic-stack/.env",
  [int]$RefreshSeconds = 1
)

$envContent = Get-Content -Raw $EnvFile
$elasticPassword = ($envContent -split "`n" | Where-Object { $_ -match '^ELASTIC_PASSWORD=' })
if (-not $elasticPassword) { throw "ELASTIC_PASSWORD not found in $EnvFile" }
$elasticPassword = $elasticPassword.Split('=')[1].Trim()

$body = @{
  index_patterns = @("logs-linux-*", "logs-linux-*-*")
  template = @{ settings = @{ index = @{ refresh_interval = "${RefreshSeconds}s" } } }
} | ConvertTo-Json -Depth 5

$args = @('-sS','-X','PUT',"$EsUrl/_index_template/logs-linux-template",'-H','Content-Type: application/json','-u',"elastic:$elasticPassword",'-d',$body)
& curl.exe @args
if ($LASTEXITCODE -ne 0) { throw "Failed to apply index template" }
Write-Host "Applied index template with refresh_interval=${RefreshSeconds}s" -ForegroundColor Green
