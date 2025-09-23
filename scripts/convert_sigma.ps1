Param(
  [string]$RulesRoot = "$PSScriptRoot/../rules",
  [string]$BackendRepo = "$PSScriptRoot/../pySigma-backend-elasticsearch",
  [string]$PipelineDir = "$PSScriptRoot/../tools/sigma",
  [string]$OutDir = "$PSScriptRoot/../build"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

${script:inner} = @'
set -euo pipefail
python -m pip install --no-cache-dir /w/backend
python -m pip install --no-cache-dir sigma-cli
export SIGMA_DISABLE_PLUGIN_AUTO_DISCOVERY=1
sigma convert \
  -r /w/rules/rules/linux/auditd \
  -t esql \
  -p /w/pipelines/esql-siemrule-ndjson.yml \
  -o /w/out/sigma-linux-auditd.esql.ndjson
sigma convert \
  -r /w/rules/rules/linux/builtin \
  -t esql \
  -p /w/pipelines/esql-siemrule-ndjson.yml \
  -o /w/out/sigma-linux-builtin.esql.ndjson
cat /w/out/sigma-linux-*.esql.ndjson > /w/out/sigma-linux-all.esql.ndjson
'@
$dockerArgs = @(
  'run','--rm','-i',
  '-v',"$RulesRoot`:/w/rules",
  '-v',"$BackendRepo`:/w/backend",
  '-v',"$PipelineDir`:/w/pipelines",
  '-v',"$OutDir`:/w/out",
  'python:3.11',
  'bash','-lc',
  ${script:inner}
)

Write-Host "Running: docker $($dockerArgs -join ' ')" -ForegroundColor Cyan
& docker @dockerArgs
if ($LASTEXITCODE -ne 0) { throw "Convert failed with exit code $LASTEXITCODE" }

Write-Host "Done. Output: $OutDir\sigma-linux-all.esql.ndjson" -ForegroundColor Green
