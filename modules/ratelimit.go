package modules

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"casinoprobe/core"
	"casinoprobe/report"
	"casinoprobe/utils"
)

// RateLimitModule tests rate limiting effectiveness and bypass techniques.
type RateLimitModule struct {
	Client   *core.ProbeClient
	Session  *core.Session
	Logger   *utils.Logger
	BaseURL  string
	LoginURL string
	Findings []report.Finding
}

// NewRateLimitModule creates a new rate limit testing module.
func NewRateLimitModule(client *core.ProbeClient, session *core.Session, baseURL, loginURL string, logger *utils.Logger) *RateLimitModule {
	return &RateLimitModule{
		Client:   client,
		Session:  session,
		Logger:   logger,
		BaseURL:  strings.TrimRight(baseURL, "/"),
		LoginURL: loginURL,
		Findings: make([]report.Finding, 0),
	}
}

// Run executes all rate limit tests.
func (rl *RateLimitModule) Run() []report.Finding {
	rl.Logger.Section("Module: Rate Limit Testing")

	rl.testThresholdDetection()
	rl.testHeaderBypass()
	rl.testMethodSwitching()
	rl.testConcurrentBurst()

	rl.Logger.Info("Rate limit testing complete — %d findings", len(rl.Findings))
	return rl.Findings
}

// testThresholdDetection sends increasing requests to find the rate limit threshold.
func (rl *RateLimitModule) testThresholdDetection() {
	rl.Logger.Info("Detecting rate limit threshold on login endpoint...")

	fullURL := rl.BaseURL + rl.LoginURL
	threshold := -1
	maxAttempts := 30

	for i := 1; i <= maxAttempts; i++ {
		req, err := http.NewRequest("POST", fullURL, strings.NewReader("username=test&password=test"))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, _, err := rl.Client.Do(req)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "connection") {
				threshold = i
				rl.Logger.Info("Connection dropped at request #%d", i)
				break
			}
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			threshold = i
			rl.Logger.Success("Rate limit hit at request #%d (HTTP 429)", i)
			resp.Body.Close()
			break
		}

		if resp.StatusCode == http.StatusForbidden {
			threshold = i
			rl.Logger.Success("Blocked at request #%d (HTTP 403)", i)
			resp.Body.Close()
			break
		}

		resp.Body.Close()
		rl.Logger.Progress(i, maxAttempts, fmt.Sprintf("Request #%d — HTTP %d", i, resp.StatusCode))
	}

	if threshold == -1 {
		rl.Logger.Vuln("HIGH", "No Rate Limit Detected",
			fmt.Sprintf("Sent %d rapid requests without being rate-limited", maxAttempts))
		rl.addFinding("HIGH", "Missing Rate Limiting",
			fmt.Sprintf("The login endpoint accepted %d rapid-fire requests without any rate limiting. This allows brute-force attacks.", maxAttempts),
			"Implement rate limiting (e.g., 5 attempts per minute per IP). Use exponential backoff or CAPTCHA after failed attempts.")
	} else {
		rl.Logger.Info("Rate limit threshold: ~%d requests", threshold)
		if threshold > 20 {
			rl.addFinding("MEDIUM", "Permissive Rate Limit",
				fmt.Sprintf("Rate limit triggers after %d requests, which may be too permissive for a login endpoint.", threshold),
				"Consider lowering the rate limit threshold to 5-10 requests per minute for authentication endpoints.")
		}
	}
}

// testHeaderBypass tests if rate limits can be bypassed using spoofed headers.
func (rl *RateLimitModule) testHeaderBypass() {
	rl.Logger.Info("Testing rate limit bypass via header spoofing...")

	fullURL := rl.BaseURL + rl.LoginURL

	// First, trigger the rate limit
	for i := 0; i < 15; i++ {
		req, _ := http.NewRequest("POST", fullURL, strings.NewReader("username=test&password=test"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, _, err := rl.Client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			break
		}
	}

	// Now try to bypass with spoofed headers
	for headerName, headerValues := range utils.SecurityPayloads.RateLimitBypass {
		for _, headerVal := range headerValues {
			req, err := http.NewRequest("POST", fullURL, strings.NewReader("username=test&password=test"))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set(headerName, headerVal)

			resp, _, err := rl.Client.Do(req)
			if err != nil {
				continue
			}
			body, _ := core.ReadBody(resp)

			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusForbidden {
				if !containsRateLimit(body) {
					rl.Logger.Vuln("HIGH", "Rate Limit Bypass via Header",
						fmt.Sprintf("%s: %s bypassed rate limit", headerName, headerVal))
					rl.addFinding("HIGH", "Rate Limit Bypass via Header Spoofing",
						fmt.Sprintf("Setting the header '%s: %s' bypassed the rate limit. An attacker can use this to perform unlimited login attempts.", headerName, headerVal),
						"Do not trust client-supplied IP headers for rate limiting. Use the actual TCP connection IP address.")
					return // One bypass is enough to report
				}
			}
		}
	}

	rl.Logger.Success("No header-based rate limit bypasses found")
}

// testMethodSwitching tests if changing HTTP method bypasses rate limits.
func (rl *RateLimitModule) testMethodSwitching() {
	rl.Logger.Info("Testing rate limit bypass via HTTP method switching...")

	fullURL := rl.BaseURL + rl.LoginURL
	methods := []string{"PUT", "PATCH", "DELETE", "OPTIONS"}

	for _, method := range methods {
		req, err := http.NewRequest(method, fullURL, strings.NewReader("username=test&password=test"))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, _, err := rl.Client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			rl.Logger.Vuln("MEDIUM", "Method Switching Bypass",
				fmt.Sprintf("%s method accepted on login endpoint", method))
			rl.addFinding("MEDIUM", "Unexpected HTTP Method Accepted",
				fmt.Sprintf("The login endpoint accepted %s method (HTTP %d). This may bypass method-specific rate limits.", method, resp.StatusCode),
				"Only allow expected HTTP methods (POST for login). Return 405 Method Not Allowed for others.")
		}
	}
}

// testConcurrentBurst tests rate limiting under a burst of concurrent requests.
func (rl *RateLimitModule) testConcurrentBurst() {
	rl.Logger.Info("Testing rate limit under concurrent burst (10 simultaneous requests)...")

	fullURL := rl.BaseURL + rl.LoginURL
	burstSize := 10

	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0
	rateLimitedCount := 0

	start := time.Now()
	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req, err := http.NewRequest("POST", fullURL, strings.NewReader("username=test&password=test"))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, _, err := rl.Client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			mu.Lock()
			if resp.StatusCode == http.StatusTooManyRequests {
				rateLimitedCount++
			} else {
				successCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	rl.Logger.Info("Burst results: %d succeeded, %d rate-limited (in %v)", successCount, rateLimitedCount, elapsed)

	if rateLimitedCount == 0 {
		rl.Logger.Vuln("HIGH", "No Burst Protection",
			fmt.Sprintf("All %d concurrent requests succeeded without rate limiting", burstSize))
		rl.addFinding("HIGH", "No Concurrent Request Rate Limiting",
			fmt.Sprintf("All %d simultaneous requests were processed without rate limiting. Burst protection is not implemented.", burstSize),
			"Implement concurrent request limiting per IP. Use a token bucket or sliding window algorithm.")
	}
}

func containsRateLimit(body string) bool {
	lower := strings.ToLower(body)
	indicators := []string{"rate limit", "too many", "throttled", "slow down", "try again later"}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func (rl *RateLimitModule) addFinding(severity, title, detail, remediation string) {
	rl.Findings = append(rl.Findings, report.Finding{
		Module:      "Rate Limiting",
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		Remediation: remediation,
	})
}
