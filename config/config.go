package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds the full configuration for a CasinoProbe security test run.
type Config struct {
	Target  TargetConfig  `json:"target"`
	Auth    AuthConfig    `json:"auth"`
	Modules ModuleConfig  `json:"modules"`
	Client  ClientConfig  `json:"client"`
	Output  OutputConfig  `json:"output"`
}

// TargetConfig defines the target application to test.
type TargetConfig struct {
	Name         string   `json:"name"`
	BaseURL      string   `json:"base_url"`
	Scope        []string `json:"scope"`          // allowed domains
	LoginURL     string   `json:"login_url"`      // login endpoint path
	PromoURL     string   `json:"promo_url"`      // promotion endpoint path
	CSRFSelector string   `json:"csrf_selector"` // CSS selector for CSRF token
}

// AuthConfig holds authentication credentials for testing.
type AuthConfig struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	CSRFSelector string `json:"csrf_selector"` // CSS selector for CSRF token
	RememberMe   bool   `json:"remember_me"`
}

// ModuleConfig enables/disables individual testing modules.
type ModuleConfig struct {
	Recon     bool `json:"recon"`
	Auth      bool `json:"auth"`
	Bonus     bool `json:"bonus"`
	Redirect  bool `json:"redirect"`
	RateLimit bool `json:"rate_limit"`
}

// ClientConfig configures the HTTP client behavior.
type ClientConfig struct {
	Timeout       int      `json:"timeout_seconds"`
	MaxRetries    int      `json:"max_retries"`
	RateLimit     float64  `json:"rate_limit_rps"`     // requests per second
	Workers       int      `json:"workers"`             // concurrent workers
	ProxyList     []string `json:"proxy_list"`
	RotateProxy   bool     `json:"rotate_proxy"`
	SkipTLSVerify bool     `json:"skip_tls_verify"`
	HeaderProfile string   `json:"header_profile"`      // "mobile", "desktop", "api"
}

// OutputConfig configures report output.
type OutputConfig struct {
	LogFile    string `json:"log_file"`
	ReportJSON string `json:"report_json"`
	ReportHTML string `json:"report_html"`
	Verbose    bool   `json:"verbose"`
}

// DefaultConfig returns a default configuration suitable for most tests.
func DefaultConfig() *Config {
	return &Config{
		Target: TargetConfig{
			Name:         "Target Casino",
			CSRFSelector: "meta[name='csrf-token']",
		},
		Auth: AuthConfig{
			CSRFSelector: "meta[name='csrf-token']",
			RememberMe:   true,
		},
		Modules: ModuleConfig{
			Recon:     true,
			Auth:      true,
			Bonus:     true,
			Redirect:  true,
			RateLimit: true,
		},
		Client: ClientConfig{
			Timeout:       30,
			MaxRetries:    3,
			RateLimit:     5.0,
			Workers:       3,
			SkipTLSVerify: true,
			HeaderProfile: "mobile",
		},
		Output: OutputConfig{
			LogFile:    "casinoprobe.log",
			ReportJSON: "report.json",
			Verbose:    true,
		},
	}
}

// LoadConfig reads a JSON config file. Returns default config if path is empty or not found.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// SaveConfig writes the configuration to a JSON file.
func SaveConfig(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// Validate checks if the configuration is valid for testing.
func (c *Config) Validate() error {
	if c.Target.BaseURL == "" {
		return fmt.Errorf("target base_url is required")
	}
	if c.Auth.Username == "" || c.Auth.Password == "" {
		return fmt.Errorf("auth username and password are required")
	}
	if c.Client.Workers < 1 {
		c.Client.Workers = 1
	}
	if c.Client.RateLimit <= 0 {
		c.Client.RateLimit = 1.0
	}
	return nil
}

// InScope checks if a URL is within the allowed testing scope.
func (c *Config) InScope(url string) bool {
	if len(c.Target.Scope) == 0 {
		// If no scope defined, only allow the base URL domain
		return true
	}
	for _, domain := range c.Target.Scope {
		if containsDomain(url, domain) {
			return true
		}
	}
	return false
}

func containsDomain(url, domain string) bool {
	return len(url) >= len(domain) && (url == domain ||
		(len(url) > len(domain) && url[len(url)-len(domain)-1] == '/' || url[len(url)-len(domain)-1] == '.'))
}
