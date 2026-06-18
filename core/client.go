package core

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"casinoprobe/config"
	"casinoprobe/utils"
)

// ProbeClient is the advanced HTTP client for security testing with proxy rotation,
// rate limiting, request logging, and cookie persistence.
type ProbeClient struct {
	Client     *http.Client
	Jar        *cookiejar.Jar
	Config     *config.ClientConfig
	Logger     *utils.Logger
	Headers    *HeaderProfile
	ReqCount   int
	mu         sync.Mutex
	rateLimiter *time.Ticker
	proxyIndex int
}

// RequestLog stores a full HTTP request/response for reporting.
type RequestLog struct {
	Timestamp  time.Time         `json:"timestamp"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	ReqHeaders map[string]string `json:"request_headers"`
	ResHeaders map[string]string `json:"response_headers"`
	ReqBody    string            `json:"request_body,omitempty"`
	ResBody    string            `json:"response_body,omitempty"`
	Duration   time.Duration     `json:"duration"`
	Error      string            `json:"error,omitempty"`
}

// NewProbeClient creates a new advanced HTTP client with all pentesting features.
func NewProbeClient(cfg *config.ClientConfig, logger *utils.Logger) (*ProbeClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Set up proxy if configured
	if len(cfg.ProxyList) > 0 {
		proxyURL, err := url.Parse(cfg.ProxyList[0])
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			logger.Info("Using proxy: %s", cfg.ProxyList[0])
		}
	}

	client := &http.Client{
		Jar:       jar,
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	// Set up rate limiter
	var limiter *time.Ticker
	if cfg.RateLimit > 0 {
		interval := time.Duration(float64(time.Second) / cfg.RateLimit)
		limiter = time.NewTicker(interval)
	}

	pc := &ProbeClient{
		Client:      client,
		Jar:         jar,
		Config:      cfg,
		Logger:      logger,
		Headers:     GetHeaderProfile(cfg.HeaderProfile),
		rateLimiter: limiter,
	}

	return pc, nil
}

// Do executes an HTTP request with rate limiting, header injection, and logging.
func (pc *ProbeClient) Do(req *http.Request) (*http.Response, *RequestLog, error) {
	// Rate limiting
	if pc.rateLimiter != nil {
		<-pc.rateLimiter.C
	}

	// Apply headers
	pc.Headers.Apply(req)

	// Track request count
	pc.mu.Lock()
	pc.ReqCount++
	count := pc.ReqCount
	pc.mu.Unlock()

	// Log the request
	reqLog := &RequestLog{
		Timestamp:  time.Now(),
		Method:     req.Method,
		URL:        req.URL.String(),
		ReqHeaders: flattenHeaders(req.Header),
	}

	pc.Logger.Debug("[#%d] %s %s", count, req.Method, req.URL.String())

	// Execute request with retry logic
	start := time.Now()
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= pc.Config.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * 500 * time.Millisecond
			jitter := time.Duration(rand.Intn(500)) * time.Millisecond
			time.Sleep(backoff + jitter)
			pc.Logger.Debug("Retry #%d for %s", attempt, req.URL.String())
		}

		resp, err = pc.Client.Do(req)
		if err == nil {
			break
		}
	}

	reqLog.Duration = time.Since(start)

	if err != nil {
		reqLog.Error = err.Error()
		pc.Logger.Error("Request failed: %s %s — %v", req.Method, req.URL, err)
		return nil, reqLog, err
	}

	reqLog.StatusCode = resp.StatusCode
	reqLog.ResHeaders = flattenHeaders(resp.Header)

	pc.Logger.Debug("[#%d] %d %s (%v)", count, resp.StatusCode, req.URL.String(), reqLog.Duration)

	return resp, reqLog, nil
}

// GET performs an HTTP GET request.
func (pc *ProbeClient) GET(targetURL string) (*http.Response, *RequestLog, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GET request: %w", err)
	}
	return pc.Do(req)
}

// POST performs an HTTP POST request with form-encoded body.
func (pc *ProbeClient) POST(targetURL string, data url.Values) (*http.Response, *RequestLog, error) {
	body := data.Encode()
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return pc.Do(req)
}

// POSTJson performs an HTTP POST request with JSON body.
func (pc *ProbeClient) POSTJson(targetURL string, jsonBody string) (*http.Response, *RequestLog, error) {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(jsonBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return pc.Do(req)
}

// DoNoRedirect executes a request without following redirects.
func (pc *ProbeClient) DoNoRedirect(req *http.Request) (*http.Response, *RequestLog, error) {
	// Temporarily override redirect policy
	origPolicy := pc.Client.CheckRedirect
	pc.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { pc.Client.CheckRedirect = origPolicy }()

	return pc.Do(req)
}

// ReadBody reads and returns the response body as a string, then closes the body.
func ReadBody(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// RotateProxy switches to the next proxy in the list.
func (pc *ProbeClient) RotateProxy() {
	if len(pc.Config.ProxyList) <= 1 {
		return
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.proxyIndex = (pc.proxyIndex + 1) % len(pc.Config.ProxyList)
	proxyURL, err := url.Parse(pc.Config.ProxyList[pc.proxyIndex])
	if err != nil {
		pc.Logger.Error("Invalid proxy URL: %s", pc.Config.ProxyList[pc.proxyIndex])
		return
	}

	pc.Client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
	pc.Logger.Info("Rotated to proxy: %s", pc.Config.ProxyList[pc.proxyIndex])
}

// GetCookies returns all cookies for a given URL.
func (pc *ProbeClient) GetCookies(rawURL string) []*http.Cookie {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return pc.Jar.Cookies(u)
}

// Close cleans up the client resources.
func (pc *ProbeClient) Close() {
	if pc.rateLimiter != nil {
		pc.rateLimiter.Stop()
	}
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string)
	for k, v := range h {
		flat[k] = strings.Join(v, "; ")
	}
	return flat
}
