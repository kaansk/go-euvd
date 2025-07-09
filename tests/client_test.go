package tests

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kaansk/go-euvd"
)

func TestBasicUsage(t *testing.T) {
	// Create a basic client
	client := euvd.NewClient()

	ctx := context.Background()

	// Test latest vulnerabilities
	t.Run("LatestVulnerabilities", func(t *testing.T) {
		vulns, err := client.GetLatestVulnerabilities(ctx)
		if err != nil {
			t.Fatalf("Failed to get latest vulnerabilities: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one vulnerability")
		}

		// API documentation says max 8 records
		if len(vulns) > 8 {
			t.Errorf("Expected max 8 latest vulnerabilities, got %d", len(vulns))
		}

		// Validate each vulnerability has required fields
		for i, vuln := range vulns {
			if vuln.ID == "" {
				t.Errorf("Latest vulnerability %d is missing ID", i)
			}
			if vuln.Description == "" {
				t.Errorf("Latest vulnerability %d (%s) is missing description", i, vuln.ID)
			}
		}

		t.Logf("Found %d latest vulnerabilities (max 8), all validated", len(vulns))
	})

	// Test latest exploited vulnerabilities
	t.Run("LatestExploitedVulnerabilities", func(t *testing.T) {
		vulns, err := client.GetLatestExploitedVulnerabilities(ctx)
		if err != nil {
			t.Fatalf("Failed to get exploited vulnerabilities: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one exploited vulnerability")
		}

		// API documentation says max 8 records
		if len(vulns) > 8 {
			t.Errorf("Expected max 8 exploited vulnerabilities, got %d", len(vulns))
		}

		// ALL vulnerabilities from this endpoint should be exploited
		for i, vuln := range vulns {
			if !vuln.IsExploited() {
				t.Errorf("Exploited vulnerability %d (%s) is not marked as exploited. ExploitedSince: %v",
					i, vuln.ID, vuln.ExploitedSince)
			}
		}

		t.Logf("Found %d exploited vulnerabilities (max 8), all verified as exploited", len(vulns))
	})

	// Test latest critical vulnerabilities
	t.Run("LatestCriticalVulnerabilities", func(t *testing.T) {
		vulns, err := client.GetLatestCriticalVulnerabilities(ctx)
		if err != nil {
			t.Fatalf("Failed to get critical vulnerabilities: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one critical vulnerability")
		}

		// API documentation says max 8 records
		if len(vulns) > 8 {
			t.Errorf("Expected max 8 critical vulnerabilities, got %d", len(vulns))
		}

		// ALL vulnerabilities should have high severity scores (typically 7.0+)
		lowScoreCount := 0
		for i, vuln := range vulns {
			if vuln.BaseScore < 7.0 {
				lowScoreCount++
				t.Logf("Warning: Critical vulnerability %d (%s) has relatively low score: %.1f", i, vuln.ID, vuln.BaseScore)
			}
			if vuln.BaseScore < 4.0 {
				t.Errorf("Critical vulnerability %d (%s) has very low score: %.1f (expected high severity)", i, vuln.ID, vuln.BaseScore)
			}
		}

		t.Logf("Found %d critical vulnerabilities (max 8), %d with score < 7.0", len(vulns), lowScoreCount)
	})
}

func TestSearchFunctionality(t *testing.T) {
	client := euvd.NewClient()
	ctx := context.Background()

	// Basic search
	t.Run("BasicSearch", func(t *testing.T) {
		requestSize := 5
		vulns, err := client.SearchVulnerabilities(ctx, &euvd.SearchOptions{
			Size: requestSize,
		})
		if err != nil {
			t.Fatalf("Search failed: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one vulnerability from search")
		}

		// Validate size constraint
		if len(vulns) > requestSize {
			t.Errorf("Expected max %d vulnerabilities, got %d", requestSize, len(vulns))
		}

		// Validate each vulnerability has required fields
		for i, vuln := range vulns {
			if vuln.ID == "" {
				t.Errorf("Vulnerability %d is missing ID", i)
			}
			if vuln.Description == "" {
				t.Errorf("Vulnerability %d (%s) is missing description", i, vuln.ID)
			}
			// BaseScore should be reasonable (0-10 range)
			if vuln.BaseScore < 0 || vuln.BaseScore > 10 {
				t.Errorf("Vulnerability %d (%s) has invalid BaseScore: %.1f (should be 0-10)", i, vuln.ID, vuln.BaseScore)
			}
		}

		t.Logf("Basic search returned %d vulnerabilities (requested max %d), all validated", len(vulns), requestSize)
	})

	// Search with score filter
	t.Run("SearchByScore", func(t *testing.T) {
		requestSize := 3
		minScore := 8
		vulns, err := client.SearchVulnerabilities(ctx, &euvd.SearchOptions{
			FromScore: minScore,
			Size:      requestSize,
		})
		if err != nil {
			t.Fatalf("Score search failed: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one vulnerability with score >= 8.0")
		}
		// Validate size constraint
		if len(vulns) > requestSize {
			t.Errorf("Expected max %d vulnerabilities, got %d", requestSize, len(vulns))
		}
		// Validate all returned vulnerabilities meet score criteria
		for i, vuln := range vulns {
			if vuln.BaseScore < float64(minScore) {
				t.Errorf("Vulnerability %d (%s) has score %.1f, below requested minimum %d",
					i, vuln.ID, vuln.BaseScore, minScore)
			}
		}
		t.Logf("Score search returned %d vulnerabilities (requested max %d), all with score >= %d",
			len(vulns), requestSize, minScore)
	})

	// Search with vendor filter
	t.Run("SearchByVendor", func(t *testing.T) {
		requestSize := 3
		requestVendor := "Microsoft"
		vulns, err := client.SearchVulnerabilities(ctx, &euvd.SearchOptions{
			Vendor: requestVendor,
			Size:   requestSize,
		})
		if err != nil {
			t.Fatalf("Vendor search failed: %v", err)
		}

		// Validate size constraint
		if len(vulns) > requestSize {
			t.Errorf("Expected max %d vulnerabilities, got %d", requestSize, len(vulns))
		}

		// Validate all returned vulnerabilities are from Microsoft
		for i, vuln := range vulns {
			// Check if Microsoft appears in description, assigner, or vendor data
			isMicrosoft := strings.Contains(strings.ToLower(vuln.Description), "microsoft") ||
				strings.Contains(strings.ToLower(vuln.Assigner), "microsoft")

			// Check vendor data if available
			if len(vuln.EnisaIdVendor) > 0 {
				vendorName := vuln.EnisaIdVendor[0].Vendor.Name
				isMicrosoft = isMicrosoft || strings.Contains(strings.ToLower(vendorName), "microsoft")
			}

			if !isMicrosoft {
				t.Logf("Warning: Vulnerability %d (%s) may not be Microsoft-related. Assigner: %s", i, vuln.ID, vuln.Assigner)
			}
		}

		t.Logf("Microsoft vendor search returned %d vulnerabilities (requested max %d)", len(vulns), requestSize)
	})

	// Search for exploited vulnerabilities
	t.Run("SearchExploited", func(t *testing.T) {
		requestSize := 3
		vulns, err := client.SearchVulnerabilities(ctx, &euvd.SearchOptions{
			Exploited: true,
			Size:      requestSize,
		})
		if err != nil {
			t.Fatalf("Exploited search failed: %v", err)
		}

		// Validate size constraint
		if len(vulns) > requestSize {
			t.Errorf("Expected max %d vulnerabilities, got %d", requestSize, len(vulns))
		}

		// Validate all returned vulnerabilities are actually exploited
		for i, vuln := range vulns {
			if !vuln.IsExploited() {
				t.Errorf("Vulnerability %d (%s) is not exploited but was returned in exploited search. ExploitedSince: %v",
					i, vuln.ID, vuln.ExploitedSince)
			}
		}

		t.Logf("Exploited search returned %d vulnerabilities (requested max %d), all verified as exploited", len(vulns), requestSize)
	})

	// Search with date range
	t.Run("SearchByDateRange", func(t *testing.T) {
		fromDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		requestSize := 5
		vulns, err := client.SearchVulnerabilities(ctx, &euvd.SearchOptions{
			FromDate: fromDate,
			Size:     requestSize,
		})
		if err != nil {
			t.Fatalf("Date range search failed: %v", err)
		}

		// Validate size constraint
		if len(vulns) > requestSize {
			t.Errorf("Expected max %d vulnerabilities, got %d", requestSize, len(vulns))
		}

		// Validate all returned vulnerabilities are from the specified date range
		for i, vuln := range vulns {
			if vuln.DatePublished != nil {
				if vuln.DatePublished.IsZero() {
					t.Logf("Vulnerability %d (%s) has zero DatePublished - likely missing date in API response", i, vuln.ID)
				} else if vuln.DatePublished.Before(fromDate) {
					t.Errorf("Vulnerability %d (%s) published on %v is before requested fromDate %v",
						i, vuln.ID, vuln.DatePublished.Format("2006-01-02"), fromDate.Format("2006-01-02"))
				}
			} else {
				t.Logf("Vulnerability %d (%s) has nil DatePublished", i, vuln.ID)
			}
		}

		t.Logf("Date range search returned %d vulnerabilities (requested max %d), all from %s onwards",
			len(vulns), requestSize, fromDate.Format("2006-01-02"))
	})

	// Search with score filter (note: this may fail due to API restrictions)
	t.Run("SearchByScore", func(t *testing.T) {
		requestSize := 3
		minScore := 8
		vulns, err := client.SearchVulnerabilities(ctx, &euvd.SearchOptions{
			FromScore: minScore,
			Size:      requestSize,
		})

		// This API endpoint often returns 403, so we handle both cases
		if err != nil {
			if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "Forbidden") {
				t.Skipf("Score-based search not supported by API: %v", err)
			}
			t.Fatalf("Score search failed: %v", err)
		}

		// Validate size constraint
		if len(vulns) > requestSize {
			t.Errorf("Expected max %d vulnerabilities, got %d", requestSize, len(vulns))
		}

		// Validate all returned vulnerabilities meet score criteria
		for i, vuln := range vulns {
			if vuln.BaseScore < float64(minScore) {
				t.Errorf("Vulnerability %d (%s) has score %.1f, below requested minimum %d",
					i, vuln.ID, vuln.BaseScore, minScore)
			}
		}

		t.Logf("Score search returned %d vulnerabilities (requested max %d), all with score >= %d",
			len(vulns), requestSize, minScore)
	})
}

func TestLookupAndAdvisory(t *testing.T) {
	client := euvd.NewClient()
	ctx := context.Background()

	// First get a vulnerability ID from latest vulnerabilities
	vulns, err := client.GetLatestVulnerabilities(ctx)
	if err != nil || len(vulns) == 0 {
		t.Skip("Cannot get vulnerability ID for lookup test")
	}

	vulnID := vulns[0].ID
	t.Logf("Testing lookup with ID: %s", vulnID)

	// Test vulnerability lookup
	t.Run("LookupByID", func(t *testing.T) {
		vuln, err := client.LookupByID(ctx, vulnID)
		if err != nil {
			t.Fatalf("Lookup failed: %v", err)
		}
		if vuln == nil {
			t.Fatal("Expected vulnerability, got nil")
		}

		// Validate exact ID match
		if vuln.ID != vulnID {
			t.Errorf("Expected ID %s, got %s", vulnID, vuln.ID)
		}

		// Validate required fields are present
		if vuln.Description == "" {
			t.Errorf("Looked up vulnerability %s is missing description", vuln.ID)
		}
		if vuln.BaseScore < 0 || vuln.BaseScore > 10 {
			t.Errorf("Looked up vulnerability %s has invalid BaseScore: %.1f", vuln.ID, vuln.BaseScore)
		}
		if vuln.Assigner == "" {
			t.Errorf("Looked up vulnerability %s is missing assigner", vuln.ID)
		}

		t.Logf("Successfully looked up vulnerability: %s (Score: %.1f, Assigner: %s)",
			vuln.ID, vuln.BaseScore, vuln.Assigner)
	})

	// Test advisory lookup (using known advisory ID)
	t.Run("GetAdvisoryByID", func(t *testing.T) {
		advisoryID := "cisco-sa-ata19x-multi-RDTEqRsy"
		advisory, err := client.GetAdvisoryByID(ctx, advisoryID)
		if err != nil {
			t.Fatalf("Advisory lookup failed: %v", err)
		}
		if advisory == nil {
			t.Fatal("Expected advisory, got nil")
		}

		// Validate exact ID match
		if advisory.ID != advisoryID {
			t.Errorf("Expected advisory ID %s, got %s", advisoryID, advisory.ID)
		}

		// Validate required fields
		if advisory.Description == "" {
			t.Errorf("Advisory %s is missing description", advisory.ID)
		}

		// Validate vulnerability count is reasonable
		vulnCount := len(advisory.VulnerabilityAdvisory)
		if vulnCount <= 0 {
			t.Errorf("Advisory %s should have vulnerabilities but has %d", advisory.ID, vulnCount)
		}

		// Extract and validate CVEs directly
		var cves []string
		for _, alias := range advisory.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				cves = append(cves, alias)
			}
		}
		for i, cve := range cves {
			if !strings.HasPrefix(cve, "CVE-") {
				t.Errorf("Advisory %s CVE %d (%s) does not start with 'CVE-'", advisory.ID, i, cve)
			}
		}

		t.Logf("Successfully retrieved advisory: %s (%d vulnerabilities, %d CVEs)",
			advisory.ID, vulnCount, len(cves))
	})
}

func TestClientConfiguration(t *testing.T) {
	// Test with custom timeout
	t.Run("WithTimeout", func(t *testing.T) {
		client := euvd.NewClient(
			euvd.WithTimeout(10 * time.Second),
		)

		ctx := context.Background()
		vulns, err := client.GetLatestVulnerabilities(ctx)
		if err != nil {
			t.Fatalf("Client with timeout failed: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one vulnerability")
		}
		t.Logf("Client with custom timeout worked, got %d vulnerabilities", len(vulns))
	})

	// Test with custom logger
	t.Run("WithLogger", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))

		client := euvd.NewClient(
			euvd.WithLogger(logger),
		)

		ctx := context.Background()
		vulns, err := client.GetLatestVulnerabilities(ctx)
		if err != nil {
			t.Fatalf("Client with logger failed: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one vulnerability")
		}
		t.Logf("Client with custom logger worked, got %d vulnerabilities", len(vulns))
	})

	// Test with custom HTTP client
	t.Run("WithHTTPClient", func(t *testing.T) {
		httpClient := &http.Client{
			Timeout: 15 * time.Second,
		}

		client := euvd.NewClient(
			euvd.WithHTTPClient(httpClient),
		)

		ctx := context.Background()
		vulns, err := client.GetLatestVulnerabilities(ctx)
		if err != nil {
			t.Fatalf("Client with HTTP client failed: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one vulnerability")
		}
		t.Logf("Client with custom HTTP client worked, got %d vulnerabilities", len(vulns))
	})

	// Test with multiple options
	t.Run("WithMultipleOptions", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelError, // Quiet for test
		}))

		client := euvd.NewClient(
			euvd.WithTimeout(20*time.Second),
			euvd.WithLogger(logger),
		)

		ctx := context.Background()
		vulns, err := client.GetLatestVulnerabilities(ctx)
		if err != nil {
			t.Fatalf("Client with multiple options failed: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("Expected at least one vulnerability")
		}
		t.Logf("Client with multiple options worked, got %d vulnerabilities", len(vulns))
	})
}

func TestVulnerabilityHelpers(t *testing.T) {
	client := euvd.NewClient()
	ctx := context.Background()

	// Get some vulnerabilities to test helper methods
	vulns, err := client.GetLatestVulnerabilities(ctx)
	if err != nil || len(vulns) == 0 {
		t.Skip("Cannot get vulnerabilities for helper tests")
	}

	vuln := vulns[0]
	t.Logf("Testing helpers with vulnerability: %s", vuln.ID)

	t.Run("HelperMethods", func(t *testing.T) {
		// Test CVE extraction from aliases
		var cve string
		for _, alias := range vuln.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				cve = alias
				break
			}
		}
		t.Logf("CVE: %s", cve)

		// Test vendor access
		var vendor string
		if len(vuln.EnisaIdVendor) > 0 {
			vendor = vuln.EnisaIdVendor[0].Vendor.Name
		}
		t.Logf("Primary vendor: %s", vendor)

		// Test product access
		var product string
		if len(vuln.EnisaIdProduct) > 0 {
			product = vuln.EnisaIdProduct[0].Product.Name
		}
		t.Logf("Primary product: %s", product)

		// Test exploitation status
		isExploited := vuln.IsExploited()
		t.Logf("Is exploited: %v", isExploited)
	})
}
