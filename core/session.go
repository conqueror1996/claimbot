package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"casinoprobe/utils"

	"github.com/PuerkitoBio/goquery"
)

// Session manages authentication state, tokens, and cookies for the security test.
type Session struct {
	Client      *ProbeClient
	Logger      *utils.Logger
	BaseURL     string
	CSRFToken   string
	AuthToken   string
	IsLoggedIn  bool
	Cookies     map[string]string
	LoginLogs   []*RequestLog
}

// NewSession creates a new session manager bound to a ProbeClient.
func NewSession(client *ProbeClient, baseURL string, logger *utils.Logger) *Session {
	return &Session{
		Client:    client,
		Logger:    logger,
		BaseURL:   strings.TrimRight(baseURL, "/"),
		Cookies:   make(map[string]string),
		LoginLogs: make([]*RequestLog, 0),
	}
}

// ExtractCSRF fetches a page and extracts the CSRF token using the given CSS selector.
func (s *Session) ExtractCSRF(pageURL, selector string) (string, error) {
	s.Logger.Info("Extracting CSRF token from %s", pageURL)

	resp, reqLog, err := s.Client.GET(pageURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch page for CSRF: %w", err)
	}
	s.LoginLogs = append(s.LoginLogs, reqLog)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML for CSRF: %w", err)
	}

	// Try the configured selector first
	token, exists := doc.Find(selector).Attr("content")
	if exists && token != "" {
		s.CSRFToken = token
		s.Logger.Success("CSRF token extracted: %s...%s", token[:min(8, len(token))], token[max(0, len(token)-4):])
		return token, nil
	}

	// Fallback: try common CSRF patterns
	fallbacks := []struct {
		sel  string
		attr string
	}{
		{"meta[name='csrf-token']", "content"},
		{"meta[name='_csrf']", "content"},
		{"meta[name='csrf_token']", "content"},
		{"input[name='_token']", "value"},
		{"input[name='csrf_token']", "value"},
		{"input[name='_csrf_token']", "value"},
		{"input[name='authenticity_token']", "value"},
	}

	for _, fb := range fallbacks {
		val, ex := doc.Find(fb.sel).Attr(fb.attr)
		if ex && val != "" {
			s.CSRFToken = val
			s.Logger.Success("CSRF token found via fallback (%s): %s...", fb.sel, val[:min(12, len(val))])
			return val, nil
		}
	}

	s.Logger.Warn("No CSRF token found on page")
	return "", nil
}

// Login performs authentication against the target with CSRF token handling.
func (s *Session) Login(loginURL, username, password, csrfSelector string) error {
	s.Logger.Info("[*] Attempting Login...")

	// Step 1: Extract CSRF token from homepage
	pageURL := s.BaseURL
	csrf, err := s.ExtractCSRF(pageURL, csrfSelector)
	if err != nil {
		s.Logger.Warn("CSRF extraction failed, attempting login without token: %v", err)
	}

	// Step 2: Build login form
	// REAL field name is "email" (confirmed from live request capture)
	formData := url.Values{}
	formData.Set("email", username)
	formData.Set("password", password)
	formData.Set("remember_me", "true")

	// Step 3: Build request manually so we can set custom headers
	fullLoginURL := s.BaseURL + loginURL
	body := strings.NewReader(formData.Encode())
	req, err := http.NewRequest("POST", fullLoginURL, body)
	if err != nil {
		return fmt.Errorf("failed to build login request: %w", err)
	}

	// Set headers matching the real browser request exactly
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", s.BaseURL)
	req.Header.Set("Referer", s.BaseURL+"/")
	if csrf != "" {
		// CSRF is sent as a HEADER, not a form field
		req.Header.Set("X-Csrf-Token", csrf)
	}

	s.Logger.Info("    -> Login URL: %s", fullLoginURL)

	// Step 4: Execute
	resp, reqLog, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	s.LoginLogs = append(s.LoginLogs, reqLog)

	body2, _ := ReadBody(resp)

	// Step 5: Check response (200-399 and 302 redirect = success)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		s.IsLoggedIn = true
		s.Logger.Success("[+] Login Successful!")

		// Try to extract auth token from response
		var jsonResp map[string]interface{}
		if err := json.Unmarshal([]byte(body2), &jsonResp); err == nil {
			if token, ok := jsonResp["token"].(string); ok {
				s.AuthToken = token
			}
		}

		// Store cookies
		cookies := s.Client.GetCookies(s.BaseURL)
		for _, c := range cookies {
			s.Cookies[c.Name] = c.Value
		}
	} else {
		// Try to extract server error message
		var jsonResp map[string]interface{}
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if err := json.Unmarshal([]byte(body2), &jsonResp); err == nil {
			if m, ok := jsonResp["message"].(string); ok {
				msg = m
			}
		}
		s.Logger.Error("[!] Login failed! Server Message: %s", msg)
	}

	return nil
}


// CheckSession verifies if the current session is still valid.
func (s *Session) CheckSession() bool {
	resp, _, err := s.Client.GET(s.BaseURL)
	if err != nil {
		return false
	}
	resp.Body.Close()

	// If we get a redirect to login page, session expired
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		s.IsLoggedIn = false
		return false
	}
	return resp.StatusCode == http.StatusOK
}

// GetSessionCookies returns a formatted string of all session cookies.
func (s *Session) GetSessionCookies() string {
	cookies := s.Client.GetCookies(s.BaseURL)
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	return strings.Join(parts, "; ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
