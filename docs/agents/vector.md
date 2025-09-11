Vector Agents for Windows and Linux

Overview
- Collect logs from endpoints with Vector, normalize to fields your engine expects, and send via HTTP to `/ingest`.
- This repo includes ready-to-use configs:
  - `deploy/vector/windows/vector_windows.toml`
  - `deploy/vector/linux/vector_linux.toml`

Server Expectations
- Engine resolves rule fields to event paths using mapping in `cmd/edr-server/main.go`.
- Preferred event paths:
  - Process: `Image`, `CommandLine`, `OriginalFileName`, `ParentImage`, `ParentCommandLine`, `CurrentDirectory`, `User`, `IntegrityLevel`.
  - Registry: `registry.path`, `registry.value`.
  - Files: `file.path`, `file.loaded`.
  - Network: `network.src.ip`, `network.src.port`, `network.dst.ip`, `network.dst.port`.
  - PowerShell: `powershell.script_block`.
  - Generic text: `Message` (used by keyword rules).

Windows Agent
- Source: `windows_event_log` channels Security, System, Sysmon, PowerShell.
- Transform: VRL remap (`win_normalize`) copies fields from `EventData` or `winlog.event_data` to canonical paths.
- Sink: HTTP POST JSON to `${EDR_SERVER_URL}` (set to `http://<host>:<port>/ingest`), gzip, batched.
- Config: `deploy/vector/windows/vector_windows.toml`.

Linux Agent
- Sources: `journald` and `file` tail of `/var/log/audit/audit.log`.
- Transform: VRL remap (`lnx_normalize`) populates `Message`, maps bash/sh command lines, and parses `exe=` and `proctitle=` from audit lines.
- Sink: HTTP POST JSON to `${EDR_SERVER_URL}`, gzip, batched.
- Config: `deploy/vector/linux/vector_linux.toml`.

How To Run
1) Start server
   - PowerShell:
     - `$env:EDR_RULES_DIR="internal\rules"`
     - `$env:EDR_SERVER_ADDR=":8080"`
     - `go run .\cmd\edr-server`
   - Note the address from logs and export `EDR_SERVER_URL`, e.g. `http://127.0.0.1:8080/ingest`.

2) Windows Endpoint
   - Install Vector: https://vector.dev/docs/setup/installation/platforms/windows/
   - Save `deploy/vector/windows/vector_windows.toml` to `C:\ProgramData\Vector\vector.toml`.
   - Set environment variable `EDR_SERVER_URL` to your server ingest URL.
   - Start Vector service: `Start-Service vector` (or use MSI installer’s service).

3) Linux Endpoint
   - Install Vector: https://vector.dev/docs/setup/installation/platforms/linux/
   - Save `deploy/vector/linux/vector_linux.toml` to `/etc/vector/vector.toml`.
   - Export `EDR_SERVER_URL` environment variable for the service, or bake it into the config.
   - Start Vector: `systemctl enable --now vector`.

Validation
- Send sample payloads to the server:
  - PowerShell: `./scripts/send_samples.ps1 -Url http://127.0.0.1:8080/ingest`
  - Bash: `scripts/send_samples.sh http://127.0.0.1:8080/ingest`
- Check `/stats` endpoint to see totals and engine compile stats.

Tuning Tips
- Increase channels: add `Microsoft-Windows-WinRM/Operational`, `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`, etc.
- Add Sysmon: install Sysmon with a community config to enrich process/network/file/registry events.
- Add auditd: ensure `auditd` is logging `EXECVE` and `SYSCALL` with `proctitle` to get command lines.
- Batch and backpressure: adjust `[sinks.*.batch]` and `[sinks.*.request]` to your throughput.

Security
- Prefer TLS and auth in the HTTP sink (Vector supports custom headers). Place server behind a TLS reverse proxy or use mutual TLS.


## Docker Compose Lab
- Configs are in `deploy/`:
  - `deploy/docker-compose.yml` server + vector + ubuntu-agent + simgen
  - `deploy/vector/lab/vector_lab.toml` tail and forward to server
  - `deploy/vector/lab/events.ndjson` optional initial sample events

### Run
1. `cd deploy` and `docker compose up --build`
2. Server logs: shows compiled rules and ingest stats; health at `/healthz`.
3. Vector tails `/data/events.ndjson`; `simgen` appends suspicious + benign events periodically.
4. Query stats: `curl -s http://127.0.0.1:8080/stats`.

### Realtime simulation
- To add more events: `docker compose exec simgen sh -c "echo '{"Message":"Django error: SuspiciousOperation"}' >> /data/events.ndjson"`
- Or change `EDR_SIM_INTERVAL` / `EDR_SIM_COUNT` in compose.

### Expected behavior
- Server detects abnormal events (reverse shell, Django SuspiciousOperation, JVM ProcessBuilder) and ignores benign lines.
- `total_accepted` increases with all lines; `total_matched` increases only for suspicious ones.

