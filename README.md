# go-euvd

[![Go Reference](https://pkg.go.dev/badge/github.com/kaansk/go-euvd.svg)](https://pkg.go.dev/github.com/kaansk/go-euvd)
[![Go Report Card](https://goreportcard.com/badge/github.com/kaansk/go-euvd)](https://goreportcard.com/report/github.com/kaansk/go-euvd)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive Go client library for the **ENISA EU Vulnerability Database (EUVD)** API, providing access to vulnerability data, security advisories, and threat intelligence.

> [!IMPORTANT]
> **Implementation Notes & API Behavior**
>
> - **Opinionated Data Handling:** This library takes a pragmatic approach to data returned by the remote API. For example, some fields are returned as single strings with embedded `\n` newlines. The library automatically parses these into Go string slices, providing a more idiomatic and convenient interface for consumers.
>
> - **Remote Search API Limitations:** While this library fully implements the official EUVD API specification, it has been observed that the remote search functionality has issues. Certain query parameter combinations (e.g., using `vendor` together with `toScore` or `fromScore`) may result in some parameters being ignored or omitted by the remote service. This is a limitation of the upstream API, not the client library.
>
> In case the mentioned shortcomings are implementation related, feel free to open an issue.

---

## Data Source
The [**ENISA EU Vulnerability Database**](https://euvd.enisa.europa.eu/) serves as the European Union's central repository. Api documentation is provided via [**Official API Documentation**](https://euvd.enisa.europa.eu/apidoc). API offers:

- **Real-time vulnerability data** from multiple sources
- **Security advisories** from vendors and security organizations  
- **CVSS scores** and exploitability metrics (EPSS)
- **Product and vendor mappings** for affected systems
- **Exploitation status** and timeline information

## Key Features

- ✅ **Complete API Coverage** - All EUVD endpoints supported
- ⚡ **High Performance** - Optimized HTTP client with connection pooling
- 🔧 **Flexible Configuration** - Custom timeouts, loggers, and HTTP clients
- 🪶 **Zero External Dependencies** - Maximum portability, following standard library and best Go practices

## Getting Started

### Installation

```bash
go get github.com/kaansk/go-euvd
```

### Usage

#### Default Client
```go
client := euvd.NewClient()
```

#### Customized Client
```go
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
```

#### Examples
Check [**example implementation**](./examples/main.go) to check usage and all endpoints.

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/kaansk/go-euvd"
)

func main() {
	// Default client
	client := euvd.NewClient()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
    
    // Get latest critical vulnerabilities
    vulnerabilities, err := client.GetLatestCriticalVulnerabilities(ctx)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Found %d critical vulnerabilities\n", len(vulnerabilities))
    for _, vuln := range vulnerabilities {
        fmt.Printf("- %s (Score: %.1f)\n", vuln.ID, vuln.BaseScore)
    }
}
```

## Devcontainer

A ready-to-use [devcontainer](.devcontainer/) is provided for rapid onboarding and consistent development environments. It includes:
- Latest stable Go (fetched from official releases)
- All recommended Go tools (gopls, golangci-lint, goimports, staticcheck, delve)
- Non-root user
- Minimal, reproducible setup based on Debian/Ubuntu

---