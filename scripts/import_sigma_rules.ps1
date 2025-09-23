Param(
  [string]$KibanaUrl = 'http://localhost:5601',
  [string]$NdjsonPath = "$PSScriptRoot/../build/sigma-linux-all.esql.ndjson",
  [string]$EnvFile = "$PSScriptRoot/../deploy/elastic-stack/.env"
)

if (!(Test-Path $NdjsonPath)) { throw "NDJSON not found: $NdjsonPath" }

$envContent = Get-Content -Raw $EnvFile
$elasticPassword = ($envContent -split "`n" | Where-Object { $_ -match '^ELASTIC_PASSWORD=' })
if (-not $elasticPassword) { throw "ELASTIC_PASSWORD not found in $EnvFile" }
$elasticPassword = $elasticPassword.Split('=')[1].Trim()

$args = @(
  '-sS','-X','POST',"$KibanaUrl/api/detection_engine/rules/_import",
  '-H','kbn-xsrf: true',
  '-u',"elastic:$elasticPassword",
  '-F',"file=@$NdjsonPath"
)
Write-Host "Importing rules to Kibana..." -ForegroundColor Cyan
& curl.exe @args
if ($LASTEXITCODE -ne 0) { throw "Import failed with exit code $LASTEXITCODE" }
Write-Host "Import completed." -ForegroundColor Green
