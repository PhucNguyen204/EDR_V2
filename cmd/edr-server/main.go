package main

import (
    "log"
    "net"
    "net/http"
    "os"
    "strings"

    "github.com/PhucNguyen204/EDR_V2/internal/rules"
    "github.com/PhucNguyen204/EDR_V2/internal/server"
    "github.com/PhucNguyen204/EDR_V2/pkg/engine"
    "github.com/PhucNguyen204/EDR_V2/pkg/sigma"
)


func main() {
	ruleDir := os.Getenv("EDR_RULES_DIR")
	if ruleDir == "" { log.Fatal("EDR_RULES_DIR not set") }

	rs, err := rules.LoadDirRecursive(ruleDir)
	if err != nil { log.Fatalf("load rules: %v", err) }

	// Mapping “chuẩn” (UEDS). Bạn có thể mở rộng thêm khi cần.
	fm := sigma.NewFieldMapping(map[string]string{
		"Image":"Image","CommandLine":"CommandLine",
		"Description":"Description","OriginalFileName":"OriginalFileName",
		"ProcessImage":"Image","ProcessCommandLine":"CommandLine",
		"ParentImage":"ParentImage","ParentCommandLine":"ParentCommandLine",
		"CurrentDirectory":"CurrentDirectory","User":"User","UserName":"UserName",
		"IntegrityLevel":"IntegrityLevel",
		"TargetObject":"registry.path","Details":"registry.value",
		"TargetFilename":"file.path","ImageLoaded":"file.loaded",
		"DestinationIp":"network.dst.ip","DestinationPort":"network.dst.port",
		"SourceIp":"network.src.ip","SourcePort":"network.src.port",
		"destination.ip":"network.dst.ip","destination.port":"network.dst.port",
		"source.ip":"network.src.ip","source.port":"network.src.port",
		"file.path":"file.path","file.name":"file.name","file.extension":"file.extension",
		"registry.key":"registry.path","registry.path":"registry.path","registry.value":"registry.value",
		"process.executable":"Image","process.command_line":"CommandLine",
		"process.commandline":"CommandLine","process.name":"Image",
		"process.parent.executable":"ParentImage","process.parent.command_line":"ParentCommandLine",
		"message":"Message","Msg":"Message",
		"ScriptBlockText":"powershell.script_block",
	})

    eng := engine.Compile(rs, fm)
    st := eng.Stats()
    log.Printf("Compiled rules: %d (no-literals: %d), prefilter literals: %d", st.Rules, st.RulesNoLiterals, st.LiteralPatterns)
    app := server.NewAppServer(eng)


    addr := strings.TrimSpace(os.Getenv("EDR_SERVER_ADDR"))
    if addr == "" {
        if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
            if strings.HasPrefix(p, ":") { addr = p } else { addr = ":" + p }
        }
    }
    if addr == "" { addr = ":8080" }

    ln, err := net.Listen("tcp", addr)
    if err != nil { log.Fatalf("listen %s: %v", addr, err) }
    log.Printf("EDR server listening on %s", ln.Addr().String())
    log.Fatal(http.Serve(ln, app.Router()))
}
