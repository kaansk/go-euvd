package euvd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type APIError struct {
	StatusCode int    `json:"statusCode"`
	Message    any    `json:"message"`
	Endpoint   string `json:"endpoint,omitempty"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("EUVD API error (status %d): %s", e.StatusCode, e.Message)
}

func NewAPIError(resp *http.Response) *APIError {
	var responseBody any
	json.NewDecoder(resp.Body).Decode(&responseBody)

	return &APIError{
		StatusCode: resp.StatusCode,
		Message:    responseBody,
		Endpoint:   resp.Request.URL.Path,
	}
}

// Vulnerability represents a vulnerability record from the EUVD API
type Vulnerability struct {
	ID                   string                 `json:"id"`
	Description          string                 `json:"description,omitempty"`
	DatePublished        *time.Time             `json:"datePublished,omitempty"`
	DateUpdated          *time.Time             `json:"dateUpdated,omitempty"`
	BaseScore            float64                `json:"baseScore,omitempty"`
	BaseScoreVersion     string                 `json:"baseScoreVersion,omitempty"`
	BaseScoreVector      string                 `json:"baseScoreVector,omitempty"`
	References           []string               `json:"references,omitempty"`
	Aliases              []string               `json:"aliases,omitempty"`
	Assigner             string                 `json:"assigner,omitempty"`
	EPSS                 float64                `json:"epss,omitempty"`
	ExploitedSince       *time.Time             `json:"exploitedSince,omitempty"`
	EnisaIdProduct       []EnisaIdProduct       `json:"enisaIdProduct,omitempty"`
	EnisaIdVendor        []EnisaIdVendor        `json:"enisaIdVendor,omitempty"`
	EnisaIdVulnerability []EnisaIdVulnerability `json:"enisaIdVulnerability,omitempty"`
	EnisaIdAdvisory      []EnisaIdAdvisory      `json:"enisaIdAdvisory,omitempty"`
}

// vulnerabilityRaw is used for unmarshaling the raw API response
type vulnerabilityRaw struct {
	ID                   string                 `json:"id"`
	Description          string                 `json:"description,omitempty"`
	DatePublished        string                 `json:"datePublished,omitempty"`
	DateUpdated          string                 `json:"dateUpdated,omitempty"`
	BaseScore            float64                `json:"baseScore,omitempty"`
	BaseScoreVersion     string                 `json:"baseScoreVersion,omitempty"`
	BaseScoreVector      string                 `json:"baseScoreVector,omitempty"`
	References           string                 `json:"references,omitempty"`
	Aliases              string                 `json:"aliases,omitempty"`
	Assigner             string                 `json:"assigner,omitempty"`
	EPSS                 float64                `json:"epss,omitempty"`
	ExploitedSince       string                 `json:"exploitedSince,omitempty"`
	EnisaIdProduct       []EnisaIdProduct       `json:"enisaIdProduct,omitempty"`
	EnisaIdVendor        []EnisaIdVendor        `json:"enisaIdVendor,omitempty"`
	EnisaIdVulnerability []EnisaIdVulnerability `json:"enisaIdVulnerability,omitempty"`
	EnisaIdAdvisory      []EnisaIdAdvisory      `json:"enisaIdAdvisory,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling to convert newline-delimited strings to arrays
func (v *Vulnerability) UnmarshalJSON(data []byte) error {
	var raw vulnerabilityRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	v.ID = raw.ID
	v.Description = raw.Description
	// Parse date fields
	if raw.DatePublished != "" {
		if dt, err := parseTimeString(raw.DatePublished); err == nil {
			v.DatePublished = &dt
		}
	}
	if raw.DateUpdated != "" {
		if dt, err := parseTimeString(raw.DateUpdated); err == nil {
			v.DateUpdated = &dt
		}
	}
	v.BaseScore = raw.BaseScore
	v.BaseScoreVersion = raw.BaseScoreVersion
	v.BaseScoreVector = raw.BaseScoreVector
	v.Assigner = raw.Assigner
	v.EPSS = raw.EPSS
	if raw.ExploitedSince != "" {
		if dt, err := parseTimeString(raw.ExploitedSince); err == nil {
			v.ExploitedSince = &dt
		}
	}
	v.EnisaIdProduct = raw.EnisaIdProduct
	v.EnisaIdVendor = raw.EnisaIdVendor
	v.EnisaIdVulnerability = raw.EnisaIdVulnerability
	v.EnisaIdAdvisory = raw.EnisaIdAdvisory

	// Convert newline-delimited strings to arrays
	v.References = splitAndClean(raw.References)
	v.Aliases = splitAndClean(raw.Aliases)

	return nil
}

// splitAndClean splits a newline-delimited string and removes empty entries
func splitAndClean(s string) []string {
	if s == "" {
		return []string{}
	}

	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// parseTimeString attempts to parse a date string using common formats
func parseTimeString(dateStr string) (time.Time, error) {
	dateStr = strings.TrimSpace(dateStr)
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"January 2, 2006, 3:04:05 PM", // long month
		"Jan 2, 2006, 3:04:05 PM",     // short month
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, nil
}

// IsExploited returns true if the vulnerability is currently being exploited
func (v *Vulnerability) IsExploited() bool {
	return v.ExploitedSince != nil && !v.ExploitedSince.IsZero()
}

type EnisaIdProduct struct {
	ID             string  `json:"id"`
	Product        Product `json:"product"`
	ProductVersion string  `json:"product_version"`
}

type EnisaIdVendor struct {
	ID     string `json:"id"`
	Vendor Vendor `json:"vendor"`
}

type EnisaIdVulnerability struct {
	ID            string           `json:"id"`
	Vulnerability VulnerabilityRef `json:"vulnerability"`
}

type Product struct {
	Name string `json:"name"`
}

type Vendor struct {
	Name string `json:"name"`
}

type VulnerabilityRef struct {
	ID                   string                 `json:"id"`
	Description          string                 `json:"description,omitempty"`
	DatePublished        string                 `json:"datePublished,omitempty"`
	DateUpdated          string                 `json:"dateUpdated,omitempty"`
	Status               string                 `json:"status,omitempty"`
	BaseScore            float64                `json:"baseScore,omitempty"`
	BaseScoreVersion     string                 `json:"baseScoreVersion,omitempty"`
	BaseScoreVector      string                 `json:"baseScoreVector,omitempty"`
	References           string                 `json:"references,omitempty"`
	EnisaID              string                 `json:"enisa_id,omitempty"`
	Assigner             string                 `json:"assigner,omitempty"`
	EPSS                 float64                `json:"epss,omitempty"`
	ExploitedSince       string                 `json:"exploitedSince,omitempty"`
	VulnerabilityProduct []VulnerabilityProduct `json:"vulnerabilityProduct,omitempty"`
	VulnerabilityVendor  []VulnerabilityVendor  `json:"vulnerabilityVendor,omitempty"`
}

type VulnerabilityProduct struct {
	ID             string  `json:"id"`
	Product        Product `json:"product"`
	ProductVersion string  `json:"product_version"`
}

type VulnerabilityVendor struct {
	ID     string `json:"id"`
	Vendor Vendor `json:"vendor"`
}

type SearchOptions struct {
	// Search parameters
	Assigner string `json:"assigner,omitempty"`
	Product  string `json:"product,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Text     string `json:"text,omitempty"`

	// Date range
	FromDate time.Time `json:"fromDate,omitempty"`
	ToDate   time.Time `json:"toDate,omitempty"`

	// Score range (0-10)
	FromScore int `json:"fromScore,omitempty"`
	ToScore   int `json:"toScore,omitempty"`

	// EPSS range (0-100)
	FromEPSS int `json:"fromEPSS,omitempty"`
	ToEPSS   int `json:"toEPSS,omitempty"`

	// Exploitation status - use Bool(true) or Bool(false)
	Exploited bool `json:"-"`

	// Pagination
	Page int `json:"page,omitempty"`
	Size int `json:"size,omitempty"`
}

// SearchResponse represents the response from the search endpoint
type SearchResponse struct {
	Items []Vulnerability `json:"items"`
	Total int             `json:"total"`
}

// Advisory represents a security advisory
type Advisory struct {
	ID                    string                  `json:"id"`
	Description           string                  `json:"description"`
	Summary               string                  `json:"summary"`
	DatePublished         *time.Time              `json:"datePublished,omitempty"`
	DateUpdated           *time.Time              `json:"dateUpdated,omitempty"`
	BaseScore             float64                 `json:"baseScore"`
	References            []string                `json:"references"`
	Aliases               []string                `json:"aliases"`
	Source                *Source                 `json:"source,omitempty"`
	AdvisoryProduct       []AdvisoryProduct       `json:"advisoryProduct"`
	EnisaIdAdvisories     []EnisaIdAdvisory       `json:"enisaIdAdvisories"`
	VulnerabilityAdvisory []VulnerabilityAdvisory `json:"vulnerabilityAdvisory"`
}

// Source represents the source of an advisory
type Source struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// AdvisoryProduct represents a product associated with an advisory
type AdvisoryProduct struct {
	ID      string  `json:"id"`
	Product Product `json:"product"`
}

// EnisaIdAdvisory represents ENISA ID information within an advisory
type EnisaIdAdvisory struct {
	ID      string       `json:"id"`
	EnisaId AdvisoryEuvd `json:"enisaId"`
}

// AdvisoryEuvd represents EUVD information within an advisory
type AdvisoryEuvd struct {
	ID               string          `json:"id"`
	Description      string          `json:"description"`
	DatePublished    *time.Time      `json:"datePublished,omitempty"`
	DateUpdated      *time.Time      `json:"dateUpdated,omitempty"`
	BaseScore        float64         `json:"baseScore"`
	BaseScoreVersion string          `json:"baseScoreVersion"`
	BaseScoreVector  string          `json:"baseScoreVector"`
	References       []string        `json:"references"`
	Aliases          []string        `json:"aliases"`
	Assigner         string          `json:"assigner"`
	EPSS             float64         `json:"epss"`
	EnisaIdVendor    []EnisaIdVendor `json:"enisaIdVendor"`
}

// VulnerabilityAdvisory represents vulnerability information within an advisory
type VulnerabilityAdvisory struct {
	ID            string                `json:"id"`
	Vulnerability AdvisoryVulnerability `json:"vulnerability"`
}

// AdvisoryVulnerability represents vulnerability details within an advisory
type AdvisoryVulnerability struct {
	ID                  string                `json:"id"`
	Description         string                `json:"description"`
	DatePublished       *time.Time            `json:"datePublished,omitempty"`
	DateUpdated         *time.Time            `json:"dateUpdated,omitempty"`
	Status              string                `json:"status"`
	BaseScore           float64               `json:"baseScore"`
	BaseScoreVersion    string                `json:"baseScoreVersion"`
	BaseScoreVector     string                `json:"baseScoreVector"`
	References          []string              `json:"references"`
	EnisaId             []string              `json:"enisa_id"`
	Assigner            string                `json:"assigner"`
	EPSS                float64               `json:"epss"`
	VulnerabilityVendor []VulnerabilityVendor `json:"vulnerabilityVendor"`
}

// Raw types for unmarshaling API responses

type AdvisoryRaw struct {
	ID                    string                  `json:"id"`
	Description           string                  `json:"description"`
	Summary               string                  `json:"summary"`
	DatePublished         string                  `json:"datePublished"`
	DateUpdated           string                  `json:"dateUpdated"`
	BaseScore             float64                 `json:"baseScore"`
	References            string                  `json:"references"`
	Aliases               string                  `json:"aliases"`
	Source                *Source                 `json:"source,omitempty"`
	AdvisoryProduct       []AdvisoryProduct       `json:"advisoryProduct"`
	EnisaIdAdvisories     []EnisaIdAdvisory       `json:"enisaIdAdvisories"`
	VulnerabilityAdvisory []VulnerabilityAdvisory `json:"vulnerabilityAdvisory"`
}

type AdvisoryEuvdRaw struct {
	ID               string          `json:"id"`
	Description      string          `json:"description"`
	DatePublished    string          `json:"datePublished"`
	DateUpdated      string          `json:"dateUpdated"`
	BaseScore        float64         `json:"baseScore"`
	BaseScoreVersion string          `json:"baseScoreVersion"`
	BaseScoreVector  string          `json:"baseScoreVector"`
	References       string          `json:"references"`
	Aliases          string          `json:"aliases"`
	Assigner         string          `json:"assigner"`
	EPSS             float64         `json:"epss"`
	EnisaIdVendor    []EnisaIdVendor `json:"enisaIdVendor"`
}

type AdvisoryVulnerabilityRaw struct {
	ID                  string                `json:"id"`
	Description         string                `json:"description"`
	DatePublished       string                `json:"datePublished"`
	DateUpdated         string                `json:"dateUpdated"`
	Status              string                `json:"status"`
	BaseScore           float64               `json:"baseScore"`
	BaseScoreVersion    string                `json:"baseScoreVersion"`
	BaseScoreVector     string                `json:"baseScoreVector"`
	References          string                `json:"references"`
	EnisaId             string                `json:"enisa_id"`
	Assigner            string                `json:"assigner"`
	EPSS                float64               `json:"epss"`
	VulnerabilityVendor []VulnerabilityVendor `json:"vulnerabilityVendor"`
}

// UnmarshalJSON implements custom JSON unmarshaling for Advisory
func (a *Advisory) UnmarshalJSON(data []byte) error {
	var raw AdvisoryRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// Copy simple fields
	a.ID = raw.ID
	a.Description = raw.Description
	a.Summary = raw.Summary
	a.BaseScore = raw.BaseScore
	a.Source = raw.Source
	a.AdvisoryProduct = raw.AdvisoryProduct
	a.EnisaIdAdvisories = raw.EnisaIdAdvisories
	a.VulnerabilityAdvisory = raw.VulnerabilityAdvisory
	// Convert date strings to time.Time objects
	if raw.DatePublished != "" {
		if dt, err := parseTimeString(raw.DatePublished); err == nil {
			a.DatePublished = &dt
		}
	}
	if raw.DateUpdated != "" {
		if dt, err := parseTimeString(raw.DateUpdated); err == nil {
			a.DateUpdated = &dt
		}
	}
	// Convert newline-separated strings to arrays
	a.References = splitAndClean(raw.References)
	a.Aliases = splitAndClean(raw.Aliases)
	return nil
}

// UnmarshalJSON implements custom JSON unmarshaling for AdvisoryEuvd
func (ae *AdvisoryEuvd) UnmarshalJSON(data []byte) error {
	var raw AdvisoryEuvdRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// Copy simple fields
	ae.ID = raw.ID
	ae.Description = raw.Description
	ae.BaseScore = raw.BaseScore
	ae.BaseScoreVersion = raw.BaseScoreVersion
	ae.BaseScoreVector = raw.BaseScoreVector
	ae.Assigner = raw.Assigner
	ae.EPSS = raw.EPSS
	ae.EnisaIdVendor = raw.EnisaIdVendor
	// Convert date strings to time.Time objects
	if raw.DatePublished != "" {
		if dt, err := parseTimeString(raw.DatePublished); err == nil {
			ae.DatePublished = &dt
		}
	}
	if raw.DateUpdated != "" {
		if dt, err := parseTimeString(raw.DateUpdated); err == nil {
			ae.DateUpdated = &dt
		}
	}
	// Convert newline-separated strings to arrays
	ae.References = splitAndClean(raw.References)
	ae.Aliases = splitAndClean(raw.Aliases)
	return nil
}

// UnmarshalJSON implements custom JSON unmarshaling for AdvisoryVulnerability
func (av *AdvisoryVulnerability) UnmarshalJSON(data []byte) error {
	var raw AdvisoryVulnerabilityRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// Copy simple fields
	av.ID = raw.ID
	av.Description = raw.Description
	av.Status = raw.Status
	av.BaseScore = raw.BaseScore
	av.BaseScoreVersion = raw.BaseScoreVersion
	av.BaseScoreVector = raw.BaseScoreVector
	av.Assigner = raw.Assigner
	av.EPSS = raw.EPSS
	av.VulnerabilityVendor = raw.VulnerabilityVendor
	// Convert date strings to time.Time objects
	if raw.DatePublished != "" {
		if dt, err := parseTimeString(raw.DatePublished); err == nil {
			av.DatePublished = &dt
		}
	}
	if raw.DateUpdated != "" {
		if dt, err := parseTimeString(raw.DateUpdated); err == nil {
			av.DateUpdated = &dt
		}
	}
	// Convert newline-separated strings to arrays
	av.References = splitAndClean(raw.References)
	av.EnisaId = splitAndClean(raw.EnisaId)
	return nil
}
