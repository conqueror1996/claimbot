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

// AuthModule tests authentication security: CSRF validation, session management, brute-force protection.
type AuthModule struct {
	Client   *core.ProbeClient
	Session  *core.Session
	Logger   *utils.Logger
	BaseURL  string
	LoginURL string
	Username string
	Password string
	CSRFSel  string
	Findings []report.Finding
}

// NewAuthModule creates a new authentication testing module.
func NewAuthModule(client *core.ProbeClient, session *core.Session, baseURL, loginURL, username, password, csrfSel string, logger *utils.Logger) *AuthModule {
	return &AuthModule{
		Client:   client,
		Session:  session,
		Logger:   logger,
		BaseURL:  strings.TrimRight(baseURL, "/"),
		LoginURL: loginURL,
		Username: username,
		Password: password,
		CSRFSel:  csrfSel,
		Findings: make([]report.Finding, 0),
	}
}

// Run executes all authentication security tests.
func (a *AuthModule) Run() []report.Finding {
	a.Logger.Section("Module: Authentication Testing")

	a.testCSRFValidation()
	a.testCSRFReuse()
	a.testLoginWithoutCSRF()
	a.testSessionFixation()
	a.testBruteForceProtection()
	a.testSessionCookieFlags()

	a.Logger.Info("Auth testing complete — %d findings", len(a.Findings))
	return a.Findings
}

// testCSRFValidation checks if the server actually validates CSRF tokens.
func (a *AuthModule) testCSRFValidation() {
	a.Logger.Info("Testing CSRF token validation...")

	for _, payload := range utils.SecurityPayloads.CSRFBypass {
		label := payload
		if label == "" {
			label = "(empty)"
		}

		formData := url.Values{}
		formData.Set("username", a.Username)
		formData.Set("password", a.Password)
		formData.Set("_token", payload)

		fullURL := a.BaseURL + a.LoginURL
		resp, _, err := a.Client.POST(fullURL, formData)
		if err != nil {
			continue
		}
		body, _ := core.ReadBody(resp)

		// If login succeeds with fake CSRF token, it's a vulnerability
		if resp.StatusCode == 200 && !strings.Contains(strings.ToLower(body), "invalid") &&
			!strings.Contains(strings.ToLower(body), "token") &&
			!strings.Contains(strings.ToLower(body), "csrf") {
			a.Logger.Vuln("HIGH", "CSRF Token Not Validated",
				fmt.Sprintf("Login succeeded with CSRF token: %s", label))
			a.addFinding("HIGH", "CSRF Token Not Validated",
				fmt.Sprintf("The server accepted a login request with CSRF token value '%s'. This means CSRF protection is not properly enforced.", label),
				"Implement server-side CSRF token validation. Reject requests with missing, empty, or invalid tokens.")
		} else {
			a.Logger.Success("CSRF token '%s' correctly rejected", label)
		}
	}
}

// testCSRFReuse checks if CSRF tokens can be reused across sessions.
func (a *AuthModule) testCSRFReuse() {
	a.Logger.Info("Testing CSRF token reusability...")

	// Extract a valid CSRF token
	token, err := a.Session.ExtractCSRF(a.BaseURL, a.CSRFSel)
	if err != nil || token == "" {
		a.Logger.Warn("Could not extract CSRF token for reuse test")
		return
	}

	// Try to use the same token twice
	formData := url.Values{}
	formData.Set("username", a.Username)
	formData.Set("password", "wrong_password_test")
	formData.Set("_token", token)

	fullURL := a.BaseURL + a.LoginURL

	// First use
	resp1, _, _ := a.Client.POST(fullURL, formData)
	if resp1 != nil {
		resp1.Body.Close()
	}

	// Second use of same token
	resp2, _, err := a.Client.POST(fullURL, formData)
	if err != nil {
		return
	}
	body2, _ := core.ReadBody(resp2)

	if resp2.StatusCode == 200 && !strings.Contains(strings.ToLower(body2), "token") {
		a.Logger.Vuln("MEDIUM", "CSRF Token Reusable", "Same CSRF token accepted on multiple requests")
		a.addFinding("MEDIUM", "CSRF Token Replay Possible",
			"The same CSRF token was accepted on multiple POST requests. Tokens should be single-use.",
			"Implement single-use CSRF tokens that are invalidated after each request")
	} else {
		a.Logger.Success("CSRF token correctly invalidated after first use")
	}
}

// testLoginWithoutCSRF tests if login works with no CSRF token field at all.
func (a *AuthModule) testLoginWithoutCSRF() {
	a.Logger.Info("Testing login without any CSRF token...")

	formData := url.Values{}
	formData.Set("username", a.Username)
	formData.Set("password", a.Password)
	// Deliberately omitting _token field

	fullURL := a.BaseURL + a.LoginURL
	resp, _, err := a.Client.POST(fullURL, formData)
	if err != nil {
		return
	}
	body, _ := core.ReadBody(resp)

	if resp.StatusCode == 200 && !strings.Contains(strings.ToLower(body), "token") {
		a.Logger.Vuln("HIGH", "Login Without CSRF Token", "Login succeeded without any CSRF token field")
		a.addFinding("HIGH", "CSRF Protection Missing",
			"The login endpoint accepted a POST request without any CSRF token field present.",
			"Require a valid CSRF token on all state-changing requests")
	} else {
		a.Logger.Success("Login correctly requires CSRF token")
	}
}

// testSessionFixation checks for session fixation vulnerabilities.
func (a *AuthModule) testSessionFixation() {
	a.Logger.Info("Testing session fixation...")

	// Get pre-login session cookies
	resp1, _, err := a.Client.GET(a.BaseURL)
	if err != nil {
		return
	}
	resp1.Body.Close()

	preLoginCookies := make(map[string]string)
	for _, c := range a.Client.GetCookies(a.BaseURL) {
		preLoginCookies[c.Name] = c.Value
	}

	if len(preLoginCookies) == 0 {
		a.Logger.Info("No pre-login session cookies found, skipping fixation test")
		return
	}

	// Login
	csrf, _ := a.Session.ExtractCSRF(a.BaseURL, a.CSRFSel)
	formData := url.Values{}
	formData.Set("username", a.Username)
	formData.Set("password", a.Password)
	if csrf != "" {
		formData.Set("_token", csrf)
	}

	resp2, _, err := a.Client.POST(a.BaseURL+a.LoginURL, formData)
	if err != nil {
		return
	}
	resp2.Body.Close()

	// Check if session cookie changed after login
	postLoginCookies := a.Client.GetCookies(a.BaseURL)
	for _, c := range postLoginCookies {
		if preVal, exists := preLoginCookies[c.Name]; exists {
			if preVal == c.Value {
				a.Logger.Vuln("HIGH", "Session Fixation",
					fmt.Sprintf("Cookie '%s' unchanged after login", c.Name))
				a.addFinding("HIGH", "Session Fixation Vulnerability",
					fmt.Sprintf("The session cookie '%s' remains the same before and after authentication. An attacker could fix a session ID and hijack the session after the victim logs in.", c.Name),
					"Regenerate the session ID after successful authentication")
			} else {
				a.Logger.Success("Cookie '%s' regenerated after login ✓", c.Name)
			}
		}
	}
}

// testBruteForceProtection checks if there's rate limiting on login attempts.
func (a *AuthModule) testBruteForceProtection() {
	a.Logger.Info("Testing brute-force protection (5 rapid attempts)...")

	attempts := 5
	blocked := false

	for i := 0; i < attempts; i++ {
		formData := url.Values{}
		formData.Set("username", a.Username)
		formData.Set("password", fmt.Sprintf("wrong_password_%d", i))
		formData.Set("_token", "test")

		resp, _, err := a.Client.POST(a.BaseURL+a.LoginURL, formData)
		if err != nil {
			if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "blocked") {
				blocked = true
				break
			}
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
			blocked = true
			a.Logger.Success("Brute-force protection triggered after %d attempts (HTTP %d)", i+1, resp.StatusCode)
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}

	if !blocked {
		a.Logger.Vuln("MEDIUM", "No Brute-Force Protection",
			fmt.Sprintf("No rate limiting detected after %d rapid login attempts", attempts))
		a.addFinding("MEDIUM", "Missing Brute-Force Protection",
			fmt.Sprintf("The login endpoint accepted %d rapid-fire login attempts without any rate limiting, CAPTCHA, or account lockout.", attempts),
			"Implement account lockout after N failed attempts, add CAPTCHA, and/or rate-limit login requests by IP")
	}
}

// testSessionCookieFlags checks if session cookies have proper security flags.
func (a *AuthModule) testSessionCookieFlags() {
	a.Logger.Info("Auditing session cookie flags...")

	resp, _, err := a.Client.GET(a.BaseURL)
	if err != nil {
		return
	}
	resp.Body.Close()

	setCookies := resp.Header.Values("Set-Cookie")
	for _, sc := range setCookies {
		sc = strings.ToLower(sc)
		name := strings.Split(sc, "=")[0]

		if !strings.Contains(sc, "httponly") {
			a.Logger.Vuln("MEDIUM", "Missing HttpOnly Flag", fmt.Sprintf("Cookie '%s'", name))
			a.addFinding("MEDIUM", fmt.Sprintf("Cookie '%s' Missing HttpOnly Flag", name),
				"Cookie is accessible via JavaScript, enabling XSS-based session theft",
				"Add the HttpOnly flag to all session cookies")
		}

		if !strings.Contains(sc, "secure") {
			a.Logger.Vuln("MEDIUM", "Missing Secure Flag", fmt.Sprintf("Cookie '%s'", name))
			a.addFinding("MEDIUM", fmt.Sprintf("Cookie '%s' Missing Secure Flag", name),
				"Cookie may be transmitted over unencrypted HTTP connections",
				"Add the Secure flag to all session cookies")
		}

		if !strings.Contains(sc, "samesite") {
			a.Logger.Vuln("LOW", "Missing SameSite Flag", fmt.Sprintf("Cookie '%s'", name))
			a.addFinding("LOW", fmt.Sprintf("Cookie '%s' Missing SameSite Flag", name),
				"Cookie may be sent with cross-site requests, enabling CSRF",
				"Add SameSite=Strict or SameSite=Lax to all session cookies")
		}
	}
}

func (a *AuthModule) addFinding(severity, title, detail, remediation string) {
	a.Findings = append(a.Findings, report.Finding{
		Module:      "Authentication",
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		Remediation: remediation,
	})
}
