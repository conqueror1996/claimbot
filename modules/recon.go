package modules

import (
	"fmt"
	"strings"

	"casinoprobe/core"
	"casinoprobe/report"
	"casinoprobe/utils"

	"github.com/PuerkitoBio/goquery"
)

// ReconModule performs reconnaissance on the target casino application.
type ReconModule struct {
	Client   *core.ProbeClient
	Session  *core.Session
	Logger   *utils.Logger
	BaseURL  string
	Findings []report.Finding
}

// NewReconModule creates a new reconnaissance module.
func NewReconModule(client *core.ProbeClient, session *core.Session, baseURL string, logger *utils.Logger) *ReconModule {
	return &ReconModule{
		Client:   client,
		Session:  session,
		Logger:   logger,
		BaseURL:  strings.TrimRight(baseURL, "/"),
		Findings: make([]report.Finding, 0),
	}
}

// Run executes all reconnaissance checks.
func (r *ReconModule) Run() []report.Finding {
	r.Logger.Section("Module: Reconnaissance")

	r.fingerprint()
	r.auditSecurityHeaders()
	r.checkRobots()
	r.discoverEndpoints()

	r.Logger.Info("Recon complete — %d findings", len(r.Findings))
	return r.Findings
}

// fingerprint identifies the technology stack and WAF.
func (r *ReconModule) fingerprint() {
	r.Logger.Info("Fingerprinting target: %s", r.BaseURL)

	resp, _, err := r.Client.GET(r.BaseURL)
	if err != nil {
		r.Logger.Error("Fingerprint failed: %v", err)
		return
	}
	defer resp.Body.Close()

	// Detect server
	server := resp.Header.Get("Server")
	if server != "" {
		r.Logger.Info("Server: %s", server)
		r.addFinding("INFO", "Server Header Exposed", fmt.Sprintf("Server header reveals: %s", server),
			"Remove or obfuscate the Server header")
	}

	// Detect framework
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		r.Logger.Vuln("LOW", "X-Powered-By Exposed", fmt.Sprintf("Framework revealed: %s", poweredBy))
		r.addFinding("LOW", "Technology Disclosure via X-Powered-By",
			fmt.Sprintf("X-Powered-By header reveals: %s", poweredBy),
			"Remove the X-Powered-By header from responses")
	}

	// Detect WAF
	wafHeaders := map[string]string{
		"cf-ray":              "Cloudflare",
		"x-sucuri-id":         "Sucuri",
		"x-akamai-transformed": "Akamai",
		"x-amz-cf-id":         "AWS CloudFront",
		"x-cdn":               "Generic CDN",
		"x-cache":             "Caching Proxy",
	}
	for header, waf := range wafHeaders {
		if resp.Header.Get(header) != "" {
			r.Logger.Info("WAF/CDN detected: %s (via %s header)", waf, header)
			r.addFinding("INFO", "WAF/CDN Detected",
				fmt.Sprintf("Detected %s via %s header", waf, header),
				"WAF presence noted — may affect testing methodology")
		}
	}

	// Parse HTML for additional fingerprinting
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err == nil {
		// Check for common framework meta tags
		doc.Find("meta[name='generator']").Each(func(i int, s *goquery.Selection) {
			gen, _ := s.Attr("content")
			r.Logger.Info("Generator: %s", gen)
		})

		// Count forms and inputs
		formCount := doc.Find("form").Length()
		inputCount := doc.Find("input").Length()
		r.Logger.Info("Page structure: %d forms, %d inputs", formCount, inputCount)
	}
}

// auditSecurityHeaders checks for missing or misconfigured security headers.
func (r *ReconModule) auditSecurityHeaders() {
	r.Logger.Info("Auditing security headers...")

	resp, _, err := r.Client.GET(r.BaseURL)
	if err != nil {
		r.Logger.Error("Security header audit failed: %v", err)
		return
	}
	resp.Body.Close()

	for _, sh := range utils.SecurityHeaders {
		value := resp.Header.Get(sh.Name)
		if value == "" {
			severity := "LOW"
			if sh.Required {
				severity = "MEDIUM"
			}
			r.Logger.Vuln(severity, "Missing Security Header", fmt.Sprintf("%s — %s", sh.Name, sh.Description))
			r.addFinding(severity, fmt.Sprintf("Missing Security Header: %s", sh.Name),
				fmt.Sprintf("The %s header is not present. %s", sh.Name, sh.Description),
				fmt.Sprintf("Add the %s header to all responses", sh.Name))
		} else {
			r.Logger.Success("Header present: %s = %s", sh.Name, value[:min(50, len(value))])

			// Check for weak values
			if sh.Name == "X-Frame-Options" && strings.ToUpper(value) == "ALLOWALL" {
				r.Logger.Vuln("HIGH", "Weak X-Frame-Options", "ALLOWALL permits clickjacking")
				r.addFinding("HIGH", "Weak X-Frame-Options Header",
					"X-Frame-Options is set to ALLOWALL, which permits framing from any origin",
					"Set X-Frame-Options to DENY or SAMEORIGIN")
			}
		}
	}
}

// checkRobots checks robots.txt for interesting disallowed paths.
func (r *ReconModule) checkRobots() {
	r.Logger.Info("Checking robots.txt...")

	resp, _, err := r.Client.GET(r.BaseURL + "/robots.txt")
	if err != nil || resp.StatusCode != 200 {
		r.Logger.Info("No robots.txt found")
		return
	}

	body, _ := core.ReadBody(resp)
	if body == "" {
		return
	}

	r.Logger.Success("robots.txt found (%d bytes)", len(body))

	// Extract interesting paths
	interestingKeywords := []string{"admin", "api", "login", "panel", "dashboard", "internal", "debug", "test", "backup", "config"}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "disallow:"))
			for _, kw := range interestingKeywords {
				if strings.Contains(path, kw) {
					r.Logger.Vuln("LOW", "Interesting Path in robots.txt", path)
					r.addFinding("LOW", "Sensitive Path in robots.txt",
						fmt.Sprintf("robots.txt disallows: %s — may reveal sensitive endpoints", path),
						"Review disallowed paths for information disclosure")
					break
				}
			}
		}
	}
}

// discoverEndpoints crawls the target to find interesting endpoints.
func (r *ReconModule) discoverEndpoints() {
	r.Logger.Info("Discovering endpoints...")

	commonPaths := []string{
		"/api", "/api/v1", "/api/v2", "/api2/v2/login",
		"/login", "/register", "/admin", "/dashboard",
		"/promotions", "/bonus", "/joinPromotion",
		"/profile", "/account", "/deposit", "/withdraw",
		"/sitemap.xml", "/.well-known/security.txt",
		"/swagger", "/api-docs", "/graphql",
	}

	found := 0
	for i, path := range commonPaths {
		r.Logger.Progress(i+1, len(commonPaths), path)

		fullURL := r.BaseURL + path
		resp, _, err := r.Client.GET(fullURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			found++
			status := "accessible"
			if resp.StatusCode >= 300 {
				status = fmt.Sprintf("redirects (%d)", resp.StatusCode)
			}
			r.Logger.Success("Endpoint found: %s — %s", path, status)
			r.addFinding("INFO", "Endpoint Discovered",
				fmt.Sprintf("Path %s is %s (HTTP %d)", path, status, resp.StatusCode),
				"Verify this endpoint should be publicly accessible")
		}
	}

	r.Logger.Info("Endpoint scan complete — %d/%d paths accessible", found, len(commonPaths))
}

func (r *ReconModule) addFinding(severity, title, detail, remediation string) {
	r.Findings = append(r.Findings, report.Finding{
		Module:      "Reconnaissance",
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		Remediation: remediation,
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
