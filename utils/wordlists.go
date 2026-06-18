package utils

// SecurityPayloads contains built-in payloads for various security tests.
var SecurityPayloads = struct {
	// CSRF bypass test values
	CSRFBypass []string
	// Redirect test payloads
	OpenRedirect []string
	// Header injection payloads
	HeaderInjection []string
	// Parameter tampering values for numeric fields
	NumericTamper []string
	// Common promo codes for fuzzing
	PromoCodes []string
	// Rate limit bypass headers
	RateLimitBypass map[string][]string
}{
	CSRFBypass: []string{
		"",                          // empty token
		"null",                      // null string
		"undefined",                 // undefined string
		"0",                         // zero
		"aaaaaaaaaaaaaaaaaaaaaaaaa",  // wrong token
		"%00",                       // null byte
		"{{csrf_token}}",            // template injection
	},

	OpenRedirect: []string{
		"//evil.com",
		"///evil.com",
		"/\\evil.com",
		"//evil.com/%2f..",
		"https://evil.com",
		"//evil%00.com",
		"/redirect?url=//evil.com",
		"/.evil.com",
		"////evil.com",
		"https:evil.com",
		"http://evil.com@legitimate.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	},

	HeaderInjection: []string{
		"test\r\nInjected-Header: true",
		"test\r\n\r\n<html>injected</html>",
		"test%0d%0aInjected: true",
		"test%0aInjected: true",
		"test\rInjected: true",
	},

	NumericTamper: []string{
		"0",           // zero
		"-1",          // negative
		"-100",        // large negative
		"0.01",        // minimal
		"99999999",    // very large
		"1e10",        // scientific notation
		"NaN",         // not a number
		"Infinity",    // infinity
		"0x10",        // hex
		"1; DROP TABLE", // SQL injection attempt
	},

	PromoCodes: []string{
		"WELCOME",
		"BONUS100",
		"FREE50",
		"SIGNUP",
		"NEWUSER",
		"VIP",
		"TEST",
		"ADMIN",
		"' OR '1'='1",  // SQL injection
		"{{7*7}}",       // template injection
	},

	RateLimitBypass: map[string][]string{
		"X-Forwarded-For":   {"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1"},
		"X-Real-IP":         {"127.0.0.1", "10.0.0.1"},
		"X-Originating-IP":  {"127.0.0.1"},
		"X-Remote-IP":       {"127.0.0.1"},
		"X-Client-IP":       {"127.0.0.1"},
		"X-Remote-Addr":     {"127.0.0.1"},
		"X-Forwarded-Host":  {"localhost"},
		"True-Client-IP":    {"127.0.0.1"},
	},
}

// SecurityHeaders lists important HTTP security headers to audit.
var SecurityHeaders = []struct {
	Name        string
	Required    bool
	Description string
}{
	{"Content-Security-Policy", true, "Prevents XSS and data injection attacks"},
	{"Strict-Transport-Security", true, "Enforces HTTPS connections"},
	{"X-Content-Type-Options", true, "Prevents MIME type sniffing"},
	{"X-Frame-Options", true, "Prevents clickjacking attacks"},
	{"X-XSS-Protection", false, "Legacy XSS filter (deprecated but still checked)"},
	{"Referrer-Policy", true, "Controls referrer information leakage"},
	{"Permissions-Policy", false, "Controls browser feature access"},
	{"Cross-Origin-Opener-Policy", false, "Isolates browsing context"},
	{"Cross-Origin-Resource-Policy", false, "Controls cross-origin resource sharing"},
	{"Cache-Control", true, "Prevents caching of sensitive data"},
}
