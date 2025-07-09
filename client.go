package euvd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	// API endpoints
	EndpointCritical  = "/criticalvulnerabilities"
	EndpointExploited = "/exploitedvulnerabilities"
	EndpointLatest    = "/lastvulnerabilities"
	EndpointSearch    = "/search"
	EndpointLookup    = "/enisaid"
	EndpointAdvisory  = "/advisory"

	// HTTP headers
	HeaderAccept    = "Accept"
	HeaderUserAgent = "User-Agent"

	// Default values
	DefaultBaseURL = "https://euvdservices.enisa.europa.eu/api"
	DefaultTimeout = 30 * time.Second
	UserAgentValue = "go-euvd/2.0"
)

// Client represents the EUVD API client
type Client struct {
	BaseURL    string        `json:"baseURL"`
	Timeout    time.Duration `json:"timeout"`
	HTTPClient *http.Client  `json:"-"` // Not serializable
	Logger     *slog.Logger  `json:"-"` // Not serializable
	UserAgent  string        `json:"userAgent"`
}

// ClientOption is a function type for configuring the EUVD client
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL for the EUVD API
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		c.BaseURL = baseURL
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.HTTPClient = httpClient
	}
}

// WithLogger sets a custom logger
func WithLogger(logger *slog.Logger) ClientOption {
	return func(c *Client) {
		c.Logger = logger
	}
}

// WithTimeout sets the request timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.Timeout = timeout
		if c.HTTPClient == nil {
			c.HTTPClient = &http.Client{Timeout: timeout}
		} else {
			c.HTTPClient.Timeout = timeout
		}
	}
}

// WithUserAgent sets a custom User-Agent header
func WithUserAgent(userAgent string) ClientOption {
	return func(c *Client) {
		c.UserAgent = userAgent
	}
}

// NewClient creates a new EUVD client with optional configuration
func NewClient(opts ...ClientOption) *Client {
	EUVDClient := &Client{
		BaseURL:    DefaultBaseURL,
		Timeout:    DefaultTimeout,
		HTTPClient: &http.Client{Timeout: DefaultTimeout},
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		UserAgent: UserAgentValue,
	}

	// Apply options
	for _, opt := range opts {
		opt(EUVDClient)
	}

	return EUVDClient
}

// GetLatestCriticalVulnerabilities retrieves the latest vulnerabilities with high severity scores (max 8 records)
func (c *Client) GetLatestCriticalVulnerabilities(ctx context.Context) ([]Vulnerability, error) {
	return c.makeRequest(ctx, EndpointCritical, nil)
}

// GetLatestExploitedVulnerabilities retrieves the latest vulnerabilities that are currently being exploited (max 8 records)
func (c *Client) GetLatestExploitedVulnerabilities(ctx context.Context) ([]Vulnerability, error) {
	return c.makeRequest(ctx, EndpointExploited, nil)
}

// GetLatestVulnerabilities retrieves the most recently published vulnerabilities
func (c *Client) GetLatestVulnerabilities(ctx context.Context) ([]Vulnerability, error) {
	return c.makeRequest(ctx, EndpointLatest, nil)
}

// SearchVulnerabilities performs a filtered search for vulnerabilities
// Only integer values are allowed for fromScore and toScore (ENISA API quirk).
// Query parameters are encoded in the standard way.
func (c *Client) SearchVulnerabilities(ctx context.Context, opts *SearchOptions) ([]Vulnerability, error) {
	params := url.Values{}

	// String parameters
	if opts != nil {
		if opts.Assigner != "" {
			params.Set("assigner", opts.Assigner)
		}
		if opts.Product != "" {
			params.Set("product", opts.Product)
		}
		if opts.Vendor != "" {
			params.Set("vendor", opts.Vendor)
		}
		if opts.Text != "" {
			params.Set("text", opts.Text)
		}

		// Date parameters
		if !opts.FromDate.IsZero() {
			params.Set("fromDate", opts.FromDate.Format("2006-01-02"))
		}
		if !opts.ToDate.IsZero() {
			params.Set("toDate", opts.ToDate.Format("2006-01-02"))
		}

		// Score parameters (only integer allowed)
		if opts.FromScore > 0 {
			params.Set("fromScore", strconv.Itoa(int(opts.FromScore)))
		}
		if opts.ToScore > 0 {
			params.Set("toScore", strconv.Itoa(int(opts.ToScore)))
		}

		// EPSS parameters
		if opts.FromEPSS > 0 {
			params.Set("fromEpss", strconv.Itoa(int(opts.FromEPSS)))
		}
		if opts.ToEPSS > 0 {
			params.Set("toEpss", strconv.Itoa(int(opts.ToEPSS)))
		}

		params.Set("exploited", strconv.FormatBool(opts.Exploited))

		// Pagination parameters
		if opts.Page > 0 {
			params.Set("page", strconv.Itoa(opts.Page))
		}
		if opts.Size > 0 {
			params.Set("size", strconv.Itoa(opts.Size))
		}
	}

	fullURL := c.BaseURL + EndpointSearch
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", EndpointSearch, err)
	}

	// Set headers
	req.Header.Set(HeaderAccept, "application/json")
	req.Header.Set(HeaderUserAgent, c.UserAgent)

	c.Logger.Debug("making HTTP request",
		"method", "GET",
		"url", req.URL.String(),
	)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed for %s: %w", EndpointSearch, err)
	}
	defer resp.Body.Close()

	c.Logger.Debug("HTTP request completed",
		"status", resp.StatusCode,
		"url", req.URL.String(),
	)

	if resp.StatusCode != http.StatusOK {
		return nil, NewAPIError(resp)
	}

	var searchResponse SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResponse); err != nil {
		return nil, fmt.Errorf("failed to decode search response from %s: %w", EndpointSearch, err)
	}

	return searchResponse.Items, nil
}

// LookupByID retrieves a specific vulnerability by its EUVD identifier
func (c *Client) LookupByID(ctx context.Context, id string) (*Vulnerability, error) {
	if id == "" {
		return nil, fmt.Errorf("vulnerability ID cannot be empty")
	}

	queryParams := url.Values{"id": {id}}
	fullURL := c.BaseURL + EndpointLookup

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", EndpointLookup, err)
	}

	if len(queryParams) > 0 {
		req.URL.RawQuery = queryParams.Encode()
	}

	// Set headers
	req.Header.Set(HeaderAccept, "application/json")
	req.Header.Set(HeaderUserAgent, c.UserAgent)

	c.Logger.Debug("making HTTP request",
		"method", "GET",
		"url", req.URL.String(),
	)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed for %s: %w", EndpointLookup, err)
	}
	defer resp.Body.Close()

	c.Logger.Debug("HTTP request completed",
		"status", resp.StatusCode,
		"url", req.URL.String(),
	)

	if resp.StatusCode != http.StatusOK {
		return nil, NewAPIError(resp)
	}

	// Try to decode as single object first
	var vulnerability Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vulnerability); err != nil {
		return nil, fmt.Errorf("lookup vulnerability %q: failed to decode response: %w", id, err)
	}

	return &vulnerability, nil
}

// GetAdvisoryByID retrieves a specific advisory by its ID
func (c *Client) GetAdvisoryByID(ctx context.Context, id string) (*Advisory, error) {
	if id == "" {
		return nil, fmt.Errorf("advisory ID cannot be empty")
	}

	queryParams := url.Values{"id": {id}}
	fullURL := c.BaseURL + EndpointAdvisory

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", EndpointAdvisory, err)
	}

	if len(queryParams) > 0 {
		req.URL.RawQuery = queryParams.Encode()
	}

	// Set headers
	req.Header.Set(HeaderAccept, "application/json")
	req.Header.Set(HeaderUserAgent, c.UserAgent)

	c.Logger.Debug("making HTTP request",
		"method", "GET",
		"url", req.URL.String(),
	)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed for %s: %w", EndpointAdvisory, err)
	}
	defer resp.Body.Close()

	c.Logger.Debug("HTTP request completed",
		"status", resp.StatusCode,
		"url", req.URL.String(),
	)

	if resp.StatusCode != http.StatusOK {
		return nil, NewAPIError(resp)
	}

	// Try to decode as single object
	var advisory Advisory
	if err := json.NewDecoder(resp.Body).Decode(&advisory); err != nil {
		return nil, fmt.Errorf("get advisory %q: failed to decode response: %w", id, err)
	}

	return &advisory, nil
}

// makeRequest performs an HTTP request and returns parsed vulnerabilities
func (c *Client) makeRequest(ctx context.Context, endpoint string, queryParams map[string]string) ([]Vulnerability, error) {
	fullURL := c.BaseURL + endpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", endpoint, err)
	}

	if len(queryParams) > 0 {
		uv := url.Values{}
		for k, v := range queryParams {
			uv.Set(k, v)
		}
		req.URL.RawQuery = uv.Encode()
	}

	// Set headers
	req.Header.Set(HeaderAccept, "application/json")
	req.Header.Set(HeaderUserAgent, c.UserAgent)

	c.Logger.Debug("making HTTP request",
		"method", "GET",
		"url", req.URL.String(),
	)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed for %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	c.Logger.Debug("HTTP request completed",
		"status", resp.StatusCode,
		"url", req.URL.String(),
	)

	if resp.StatusCode != http.StatusOK {
		return nil, NewAPIError(resp)
	}
	var vulnerabilities []Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vulnerabilities); err != nil {
		return nil, fmt.Errorf("failed to decode response from %s: %w", endpoint, err)
	}

	return vulnerabilities, nil
}
