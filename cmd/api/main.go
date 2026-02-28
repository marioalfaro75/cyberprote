// Package main provides the CSF REST API server entry point.
package main

import (
	"fmt"
	"os"

	"github.com/cloud-security-fabric/csf/api"
	"github.com/cloud-security-fabric/csf/internal/compliance"
	"github.com/cloud-security-fabric/csf/internal/graph"
	"github.com/cloud-security-fabric/csf/internal/settings"
	"github.com/cloud-security-fabric/csf/internal/threatintel"
	"github.com/cloud-security-fabric/csf/policy"
	"github.com/cloud-security-fabric/csf/scoring"
)

func main() {
	dsn := os.Getenv("CSF_DSN")
	if dsn == "" {
		dsn = "postgres://csf:csf-dev-password@localhost:5432/csf?sslmode=disable"
	}

	addr := os.Getenv("CSF_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	gs, err := graph.NewGraphService(dsn, "security_fabric")
	if err != nil {
		fmt.Fprintf(os.Stderr, "graph service: %v\n", err)
		os.Exit(1)
	}
	defer gs.Close()

	pe, err := policy.NewEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy engine: %v\n", err)
		os.Exit(1)
	}

	se := scoring.NewDefaultEngine()

	cat, err := compliance.LoadCatalog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "compliance catalog: %v\n", err)
		os.Exit(1)
	}

	am, err := threatintel.LoadAttackMatrix()
	if err != nil {
		fmt.Fprintf(os.Stderr, "attack matrix: %v\n", err)
		os.Exit(1)
	}

	settingsStore := settings.NewFileStore("./csf-settings.json", "./.csf-secrets.env")

	server := api.NewServer(gs, pe, se, settingsStore, cat, am)
	fmt.Printf("CSF API server starting on %s\n", addr)
	if err := server.Start(addr); err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		os.Exit(1)
	}
}
