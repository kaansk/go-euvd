package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/kaansk/go-euvd"
)

func main() {
	// --- Client Demonstrations ---

	// Default client
	client := euvd.NewClient()

	// Fully configured client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	customHTTPClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		},
	}
	client = euvd.NewClient(
		euvd.WithBaseURL("https://euvdservices.enisa.europa.eu/api"),
		euvd.WithTimeout(30*time.Second),
		euvd.WithLogger(logger),
		euvd.WithHTTPClient(customHTTPClient),
	)

	// --- Client Demonstrations ---

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// --- API Endpoint Demonstrations ---

	// Get latest critical vulnerabilities
	criticalVulns, err := client.GetLatestCriticalVulnerabilities(ctx)
	if err != nil {
		log.Printf("Error getting critical vulnerabilities: %v", err)
	} else if len(criticalVulns) > 0 {
		fmt.Printf("Latest critical: %s (Score: %.1f)\n", criticalVulns[0].ID, criticalVulns[0].BaseScore)
	}

	// Get latest exploited vulnerabilities
	exploitedVulns, err := client.GetLatestExploitedVulnerabilities(ctx)
	if err != nil {
		log.Printf("Error getting exploited vulnerabilities: %v", err)
	} else if len(exploitedVulns) > 0 {
		fmt.Printf("Latest exploited: %s (Score: %.1f)\n", exploitedVulns[0].ID, exploitedVulns[0].BaseScore)
	}

	// Get latest vulnerabilities
	latestVulns, err := client.GetLatestVulnerabilities(ctx)
	if err != nil {
		log.Printf("Error getting latest vulnerabilities: %v", err)
	} else if len(latestVulns) > 0 {
		fmt.Printf("Latest: %s (Score: %.1f)\n", latestVulns[0].ID, latestVulns[0].BaseScore)
	}

	// Search vulnerabilities (example: 3.0 <= score <= 4.0)
	// Note: Adjust the score range as needed for your use case
	searchOpts := &euvd.SearchOptions{
		FromScore: 3.0,
		ToScore:   4.0,
		Size:      3,
	}
	searchResults, err := client.SearchVulnerabilities(ctx, searchOpts)
	if err != nil {
		log.Printf("Error searching vulnerabilities: %v", err)
	} else {
		for _, vuln := range searchResults {
			fmt.Printf("Search result: %s (Score: %.1f)\n", vuln.ID, vuln.BaseScore)
		}
	}

	// Lookup vulnerability by ID (use one from previous results if available)
	var vulnID string
	if len(criticalVulns) > 0 {
		vulnID = criticalVulns[0].ID
	} else if len(latestVulns) > 0 {
		vulnID = latestVulns[0].ID
	} else {
		vulnID = "EUVD-2024-0001"
	}
	vuln, err := client.LookupByID(ctx, vulnID)
	if err != nil {
		log.Printf("Error looking up vulnerability %s: %v", vulnID, err)
	} else {
		fmt.Printf("Vulnerability lookup: %s\n", vuln.ID)
	}

	// Get advisory by ID
	advisoryID := "cisco-sa-ata19x-multi-RDTEqRsy"
	advisory, err := client.GetAdvisoryByID(ctx, advisoryID)
	if err != nil {
		log.Printf("Error getting advisory %s: %v", advisoryID, err)
	} else {
		fmt.Printf("Advisory lookup: %s\n", advisory.ID)
	}

	// --- API Endpoint Demonstrations ---
}
