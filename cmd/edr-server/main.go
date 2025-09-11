package main

import (
	"log"
	"net/http"
	"os"

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
		"TargetObject":"registry.path","TargetFilename":"file.path",
		"DestinationIp":"network.dst.ip","DestinationPort":"network.dst.port",
		"ScriptBlockText":"powershell.script_block",
	})

	eng := engine.Compile(rs, fm)
	app := server.NewAppServer(eng)

	addr := ":8080"
	log.Printf("EDR server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, app.Router()))
}
