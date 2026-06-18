package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"casinoprobe/core"
	"casinoprobe/report"
	"casinoprobe/utils"
)

// RedirectModule analyzes redirect chains and tests for open redirect vulnerabilities.
type RedirectModule struct {
	Client   *core.ProbeClient
	Session  *core.Session
	Logger   *utils.Logger
	BaseURL  string
	Findings []report.Finding
}

// NewRedirectModule creates a new redirect analysis module.
func NewRedirectModule(client *core.ProbeClient, session *core.Session, baseURL string, logger *utils.Logger) *RedirectModule {
	return &RedirectModule{
		Client:   client,
		Session:  session,
		Logger:   logger,
		BaseURL:  strings.TrimRight(baseURL, "/"),
		Findings: make([]report.Finding, 0),
	}
}

// Run executes all redirect security tests.
func (rd *RedirectModule) Run() []report.Finding {
	rd.Logger.Section("Module: Redirect Analysis")

	rd.mapRedirectChain()
	rd.testOpenRedirects()
	rd.testTokenLeakage()

	rd.Logger.Info("Redirect testing complete — %d findings", len(rd.Findings))
	return rd.Findings
}

// mapRedirectChain traces the full redirect chain from the base URL.
func (rd *RedirectModule) mapRedirectChain() {
	rd.Logger.Info("Mapping redirect chain from %s", rd.BaseURL)

	// Create a client that doesn't follow redirects
	req, err := http.NewRequest("GET", rd.BaseURL, nil)
	if err != nil {
		rd.Logger.Error("Failed to create request: %v", err)
		return
	}

	chain := []string{rd.BaseURL}
	currentURL := rd.BaseURL
	maxHops := 15

	for i := 0; i < maxHops; i++ {
		req, err = http.NewRequest("GET", currentURL, nil)
		if err != nil {
			break
		}

		resp, _, err := rd.Client.DoNoRedirect(req)
		if err != nil {
			break
		}
		resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			rd.Logger.Success("Chain end: %s → HTTP %d", currentURL, resp.StatusCode)
			break
		}

		location := resp.Header.Get("Location")
		if location == "" {
			break
		}

		// Resolve relative URLs
		if !strings.HasPrefix(location, "http") {
			base, _ := url.Parse(currentURL)
			rel, _ := url.Parse(location)
			location = base.ResolveReference(rel).String()
		}

		chain = append(chain, location)
		rd.Logger.Info("  [%d] %d → %s", i+1, resp.StatusCode, location)
		currentURL = location
	}

	if len(chain) > 2 {
		rd.Logger.Vuln("LOW", "Long Redirect Chain",
			fmt.Sprintf("%d hops detected", len(chain)))
		rd.addFinding("LOW", "Long Redirect Chain",
			fmt.Sprintf("The application uses a redirect chain with %d hops: %s", len(chain), strings.Join(chain, " → ")),
			"Minimize redirect chains. Long chains can be exploited for open redirect chaining.")
	}

	// Check if any redirect goes to external domain
	baseDomain := extractDomain(rd.BaseURL)
	for _, u := range chain {
		domain := extractDomain(u)
		if domain != baseDomain && domain != "" {
			rd.Logger.Vuln("MEDIUM", "External Redirect",
				fmt.Sprintf("Redirect goes to external domain: %s", domain))
			rd.addFinding("MEDIUM", "Redirect to External Domain",
				fmt.Sprintf("The redirect chain includes external domain '%s'. This may be intentional (CDN/SSO) or an open redirect.", domain),
				"Review if external redirects are intentional. Whitelist allowed redirect domains.")
		}
	}
}

// testOpenRedirects tests common redirect parameters for open redirect vulnerabilities.
func (rd *RedirectModule) testOpenRedirects() {
	rd.Logger.Info("Testing for open redirect vulnerabilities...")

	// Common redirect parameter names
	redirectParams := []string{
		"url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
		"returnTo", "next", "goto", "target", "destination", "rurl", "callback",
		"continue", "forward", "out", "view", "ref", "site",
	}

	for _, param := range redirectParams {
		for _, payload := range utils.SecurityPayloads.OpenRedirect {
			testURL := fmt.Sprintf("%s/login?%s=%s", rd.BaseURL, param, url.QueryEscape(payload))

			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}

			resp, _, err := rd.Client.DoNoRedirect(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if location != "" && isExternalRedirect(location, rd.BaseURL) {
					rd.Logger.Vuln("HIGH", "Open Redirect Found",
						fmt.Sprintf("param=%s, payload=%s → redirects to %s", param, payload, location))
					rd.addFinding("HIGH", "Open Redirect Vulnerability",
						fmt.Sprintf("The parameter '%s' with value '%s' caused a redirect to '%s'. This can be used for phishing attacks.", param, payload, location),
						"Validate redirect URLs against a whitelist of allowed domains. Never redirect to user-supplied URLs without validation.")
					break // One finding per parameter is enough
				}
			}
		}
	}
}

// testTokenLeakage checks if authentication tokens leak via redirect URLs.
func (rd *RedirectModule) testTokenLeakage() {
	rd.Logger.Info("Testing for token leakage in redirects...")

	// If we're logged in, check if the redirect URLs contain tokens
	if !rd.Session.IsLoggedIn {
		rd.Logger.Info("Not logged in — skipping token leakage test")
		return
	}

	// Fetch authenticated pages and check redirect URLs
	testPaths := []string{"/", "/dashboard", "/profile", "/account"}

	for _, path := range testPaths {
		req, err := http.NewRequest("GET", rd.BaseURL+path, nil)
		if err != nil {
			continue
		}

		resp, _, err := rd.Client.DoNoRedirect(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")

			// Check if the redirect URL contains sensitive tokens
			sensitiveParams := []string{"token", "session", "auth", "key", "secret", "access_token", "jwt"}
			parsedURL, err := url.Parse(location)
			if err != nil {
				continue
			}

			for _, param := range sensitiveParams {
				if parsedURL.Query().Get(param) != "" {
					rd.Logger.Vuln("HIGH", "Token Leakage via Redirect",
						fmt.Sprintf("%s contains '%s' parameter in redirect URL", path, param))
					rd.addFinding("HIGH", "Authentication Token Leaked in Redirect URL",
						fmt.Sprintf("The path '%s' redirects to '%s' which contains the sensitive parameter '%s' in the URL. This token may be logged in server access logs, browser history, and referrer headers.", path, location, param),
						"Never include authentication tokens in URLs. Use HTTP headers or request bodies instead.")
				}
			}
		}
	}
}

func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isExternalRedirect(location, baseURL string) bool {
	baseDomain := extractDomain(baseURL)
	redirectDomain := extractDomain(location)

	if redirectDomain == "" {
		// Check for protocol-relative URLs like //evil.com
		if strings.HasPrefix(location, "//") {
			return true
		}
		return false
	}

	return redirectDomain != baseDomain
}

func (rd *RedirectModule) addFinding(severity, title, detail, remediation string) {
	rd.Findings = append(rd.Findings, report.Finding{
		Module:      "Redirect",
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		Remediation: remediation,
	})
}
