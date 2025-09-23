Param(
  [string]$KibanaUrl = 'http://localhost:5601',
  [string]$NdjsonPath = "$PSScriptRoot/../build/sigma-linux-all.esql.ndjson",
  [string]$EnvFile = "$PSScriptRoot/../deploy/elastic-stack/.env",
  [string]$Interval = '1m',
  [string]$From = 'now-1m',
  [int]$MaxSignals = 1000
)

if (!(Test-Path $NdjsonPath)) { throw "NDJSON not found: $NdjsonPath" }

$envContent = Get-Content -Raw $EnvFile
$elasticPassword = ($envContent -split "`n" | Where-Object { $_ -match '^ELASTIC_PASSWORD=' })
if (-not $elasticPassword) { throw "ELASTIC_PASSWORD not found in $EnvFile" }
$elasticPassword = $elasticPassword.Split('=')[1].Trim()

$ruleIds = Get-Content $NdjsonPath | ForEach-Object {
  try { ($_.Trim() | ConvertFrom-Json).rule_id } catch { $null }
} | Where-Object { $_ }

foreach ($rid in $ruleIds) {
  $payload = @{ rule_id = $rid; interval = $Interval; from = $From; max_signals = $MaxSignals } | ConvertTo-Json -Compress
  $args = @(
    '-sS','-X','PUT',"$KibanaUrl/api/detection_engine/rules",
    '-H','kbn-xsrf: true',
    '-H','Content-Type: application/json',
    '-u',"elastic:$elasticPassword",
    '-d', $payload
  )
  & curl.exe @args | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Warning "Failed to update $rid" }
}
Write-Host "Updated $(($ruleIds | Measure-Object).Count) rules to interval=$Interval from=$From" -ForegroundColor Green
