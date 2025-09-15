package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
	"github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
	srv "github.com/PhucNguyen204/EDR_V2/internal/server"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := getenv("EDR_ADDR", ":8080")
	dsn := getenv("EDR_DB_DSN", "postgres://postgres:postgres@localhost:5432/edr?sslmode=disable")
	// Optional rules path
	rulesPath := os.Getenv("EDR_RULES_PATH")
	if rulesPath == "" {
		if st, err := os.Stat("./rules"); err == nil && st.IsDir() {
			rulesPath = "./rules"
		}
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.Ping(); err != nil {
		log.Fatalf("ping db: %v", err)
	}

	// Initialize empty engine first
	engine, err := dag.FromRuleset(compiler.New().IntoRuleset(), dag.DefaultEngineConfig())
	if err != nil {
		log.Fatalf("init engine: %v", err)
	}

	// Create server
	server := srv.NewAppServer(db, engine)
	if err := server.InitSchema(); err != nil {
		log.Fatalf("init schema: %v", err)
	}
	if rulesPath != "" {
		if loaded, skipped, err := server.LoadRulesFromDir(context.Background(), rulesPath); err != nil {
			log.Printf("failed to load rules from %s: %v", rulesPath, err)
		} else {
			log.Printf("loaded rules from %s: loaded=%d skipped=%d", rulesPath, loaded, skipped)
		}
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	log.Printf("EDR server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
