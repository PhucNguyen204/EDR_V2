Param(
  [string]$RulesRoot = "$PSScriptRoot/../rules",
  [string]$OutDir = "$PSScriptRoot/../build",
  [string]$EnvFile = "$PSScriptRoot/../deploy/elastic-stack/.env",
  [string]$KibanaUrl = 'http://localhost:5601'
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 1) Build JSONL of create-payloads using Docker + pysigma Lucene backend
$dockerArgs = @(
  'run','--rm','-i',
  '-v',"$RulesRoot`:/w/rules",
  '-v',"$OutDir`:/w/out",
  '-v',"$PSScriptRoot`:/w/scripts",
  'python:3.11','bash','-lc',
  @'
set -euo pipefail
python -m pip install --no-cache-dir pysigma==1.0.0rc2 pysigma-backend-elasticsearch==1.2.0rc1
python /w/scripts/convert_sigma_all_lucene.py
'@
)

Write-Host "Converting Sigma → Lucene rule payloads..." -ForegroundColor Cyan
& docker @dockerArgs
if ($LASTEXITCODE -ne 0) { throw "Conversion failed with exit code $LASTEXITCODE" }

$jsonl = Join-Path $OutDir 'sigma-linux-lucene-rules.jsonl'
if (!(Test-Path $jsonl)) { throw "Missing output: $jsonl" }

# 2) Create rules in Kibana via API
$envContent = Get-Content -Raw $EnvFile
$elasticPassword = ($envContent -split "`n" | Where-Object { $_ -match '^ELASTIC_PASSWORD=' })
if (-not $elasticPassword) { throw "ELASTIC_PASSWORD not found in $EnvFile" }
$elasticPassword = $elasticPassword.Split('=')[1].Trim()

$count = 0
Get-Content $jsonl | ForEach-Object {
  if (-not $_) { return }
  $tmp = Join-Path $OutDir 'create_rule_tmp.json'
  [System.IO.File]::WriteAllText($tmp, $_, (New-Object System.Text.UTF8Encoding($false)))
  $resp = & curl.exe -sS -u "elastic:$elasticPassword" -H "kbn-xsrf: true" -H "Content-Type: application/json" -X POST "$KibanaUrl/api/detection_engine/rules" --data-binary "@$tmp"
  if ($LASTEXITCODE -ne 0) { Write-Warning "Create rule failed: $resp" } else { $count++ }
}
Write-Host "Created $count Kibana rules." -ForegroundColor Green

