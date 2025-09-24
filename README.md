$pw = 'lEEc3BIwwRW=ed3wlsJB'

foreach ($zip in @(
    'build/sigma-windows-vector.zip',
    'build/sigma-generic-windows.zip',
    'build/sigma-linux-vector.zip',
    'build/sigma-generic-linux.zip'
)) {
    Write-Host "Importing $zip" -ForegroundColor Cyan
    curl.exe -sS -u "elastic:$pw" -H "kbn-xsrf: true" -F "file=@$zip" `
      "http://localhost:5601/api/detection_engine/rules/_import?overwrite=true"
    Start-Sleep 2
}$pw = 'lEEc3BIwwRW=ed3wlsJB'

foreach ($zip in @(
    'build/sigma-windows-vector.zip',
    'build/sigma-generic-windows.zip',
    'build/sigma-linux-vector.zip',
    'build/sigma-generic-linux.zip'
)) {
    Write-Host "Importing $zip" -ForegroundColor Cyan
    curl.exe -sS -u "elastic:$pw" -H "kbn-xsrf: true" -F "file=@$zip" `
      "http://localhost:5601/api/detection_engine/rules/_import?overwrite=true"
    Start-Sleep 2
}

## Process tree API

- `GET /api/v1/process_tree?endpoint_id=<id>&root=<key>` truy xuat cay tien trinh hien tai cua agent.
- Tham so `endpoint_id` bat buoc; `root` tuy chon de chi dinh nut goc (entity_id hoac pid:PID).
- Phan hoi bao gom danh sach `trees` voi cay duoc sap xep theo `last_seen` moi nhat.
- Cay duoc cap nhat tu su kien trong `/api/v1/ingest` dua tren truong ECS `process.*` va `process.parent.*`.




