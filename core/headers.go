package core

import (
	"math/rand"
	"net/http"
)

// HeaderProfile defines a set of HTTP headers that mimic a specific browser/client.
type HeaderProfile struct {
	Name       string
	UserAgents []string
	Accept     string
	AcceptLang string
	AcceptEnc  string
	Extra      map[string]string
}

// Apply sets the profile headers on the given request. User-Agent is randomized from the pool.
func (hp *HeaderProfile) Apply(req *http.Request) {
	// Randomize User-Agent
	if len(hp.UserAgents) > 0 {
		ua := hp.UserAgents[rand.Intn(len(hp.UserAgents))]
		req.Header.Set("User-Agent", ua)
	}

	if hp.Accept != "" {
		req.Header.Set("Accept", hp.Accept)
	}
	if hp.AcceptLang != "" {
		req.Header.Set("Accept-Language", hp.AcceptLang)
	}
	if hp.AcceptEnc != "" {
		req.Header.Set("Accept-Encoding", hp.AcceptEnc)
	}

	for k, v := range hp.Extra {
		req.Header.Set(k, v)
	}
}

// GetHeaderProfile returns a predefined header profile by name.
func GetHeaderProfile(name string) *HeaderProfile {
	switch name {
	case "mobile":
		return mobileProfile()
	case "desktop":
		return desktopProfile()
	case "api":
		return apiProfile()
	default:
		return mobileProfile()
	}
}

func mobileProfile() *HeaderProfile {
	return &HeaderProfile{
		Name: "Mobile Browser",
		UserAgents: []string{
			"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
			"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
			"Mozilla/5.0 (Linux; Android 13; Redmi Note 12 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
			"Mozilla/5.0 (Linux; Android 13; V2219) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
		},
		Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		AcceptLang: "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
		AcceptEnc:  "gzip, deflate, br",
		Extra: map[string]string{
			"Sec-Ch-Ua-Mobile":   "?1",
			"Sec-Ch-Ua-Platform": "\"Android\"",
			"Sec-Fetch-Dest":     "document",
			"Sec-Fetch-Mode":     "navigate",
			"Sec-Fetch-Site":     "same-origin",
			"Upgrade-Insecure-Requests": "1",
		},
	}
}

func desktopProfile() *HeaderProfile {
	return &HeaderProfile{
		Name: "Desktop Browser",
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		},
		Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		AcceptLang: "en-US,en;q=0.9",
		AcceptEnc:  "gzip, deflate, br",
		Extra: map[string]string{
			"Sec-Ch-Ua-Mobile":   "?0",
			"Sec-Ch-Ua-Platform": "\"Windows\"",
			"Sec-Fetch-Dest":     "document",
			"Sec-Fetch-Mode":     "navigate",
			"Sec-Fetch-Site":     "same-origin",
			"Upgrade-Insecure-Requests": "1",
		},
	}
}

func apiProfile() *HeaderProfile {
	return &HeaderProfile{
		Name: "API Client",
		UserAgents: []string{
			"CasinoProbe/1.0 SecurityScanner",
		},
		Accept:     "application/json, text/plain, */*",
		AcceptLang: "en-US,en;q=0.9",
		AcceptEnc:  "gzip, deflate",
		Extra:      map[string]string{},
	}
}
