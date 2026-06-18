package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"casinoprobe/config"
	"casinoprobe/core"

	"github.com/PuerkitoBio/goquery"
)

// ─── Hardcoded Domains (same as Android binary) ───

var domains = []Domain{
	{ID: "1", Name: "PlayKaro 365", URL: "https://playkaro365.com"},
	{ID: "2", Name: "JeetExch 99", URL: "https://jeetexch99.com"},
	{ID: "3", Name: "SpinJeet 365", URL: "https://spinjeet365.com"},
	{ID: "4", Name: "WinClash 365", URL: "https://winclash365.com"},
}

// Domain represents a target casino site.
type Domain struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ─── Bot States ───

const (
	StateIdle     = "idle"
	StateRunning  = "running"
	StateComplete = "complete"
	StateError    = "error"
)

// ─── Request / Response ───

type BotRequest struct {
	DomainID string `json:"domain_id"`
	Amount   string `json:"amount"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ─── Server ───

type Server struct {
	Bus   *EventBus
	State string
	mu    sync.Mutex
}

// Start launches the web server on the given port.
func Start(port string) {
	srv := &Server{
		Bus:   NewEventBus(),
		State: StateIdle,
	}

	mux := http.NewServeMux()

	// Static assets
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/static/", srv.handleStatic)

	// API endpoints
	mux.HandleFunc("/api/domains", srv.handleDomains)
	mux.HandleFunc("/api/status", srv.handleStatus)
	mux.HandleFunc("/api/bot/start", srv.handleBotStart)
	mux.HandleFunc("/api/bot/events", srv.handleSSE)

	fmt.Printf("\n  ╔═══════════════════════════════════════════════════════╗\n")
	fmt.Printf("  ║   ♠ ♥ ♦ ♣  Casino Automation Bot  ♣ ♦ ♥ ♠            ║\n")
	fmt.Printf("  ║   Running at http://localhost%s                  ║\n", port)
	fmt.Printf("  ╚═══════════════════════════════════════════════════════╝\n")
	fmt.Printf("\n  Press Ctrl+C to stop the server.\n\n")

	if err := http.ListenAndServe(port, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// ─── Static File Handlers ───

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	webDir := getWebDir()
	http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	webDir := getWebDir()
	filename := strings.TrimPrefix(r.URL.Path, "/static/")
	http.ServeFile(w, r, filepath.Join(webDir, filename))
}

func getWebDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "web"
	}
	return filepath.Join(filepath.Dir(exe), "web")
}

// ─── API: Domains List ───

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

// ─── API: Status ───

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	state := s.State
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": state})
}

// ─── API: Bot Start ───

func (s *Server) handleBotStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	if s.State == StateRunning {
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "Bot is already running"})
		return
	}
	s.State = StateRunning
	s.mu.Unlock()

	var req BotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.mu.Lock()
		s.State = StateIdle
		s.mu.Unlock()
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate
	if req.DomainID == "" || req.Username == "" || req.Password == "" || req.Amount == "" {
		s.mu.Lock()
		s.State = StateIdle
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Domain, amount, username and password are required"})
		return
	}

	// Find domain
	var domain *Domain
	for _, d := range domains {
		if d.ID == req.DomainID {
			domain = &d
			break
		}
	}
	if domain == nil {
		s.mu.Lock()
		s.State = StateIdle
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid choice! Exiting..."})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started", "domain": domain.URL})

	// Run bot in background (same flow as Android binary)
	go s.runBot(domain, req.Amount, req.Username, req.Password)
}

// ─── Bot Flow (replicates Android binary exactly) ───

func (s *Server) runBot(domain *Domain, amount, username, password string) {
	logger := NewWebLogger(s.Bus)

	// ─── Banner ───
	logger.Section("Automation Bot: Select Domain")
	PublishStatus(s.Bus, "running", "Bot started")

	logger.Info("Selected domain: %s (%s)", domain.Name, domain.URL)
	logger.Info("    -> Login URL: %s/api2/v2/login", domain.URL)
	logger.Info("    -> Amount: %s INR", amount)

	// ─── Build Configuration ───
	cfg := config.DefaultConfig()
	cfg.Target.BaseURL = domain.URL
	cfg.Target.LoginURL = "/api2/v2/login"
	cfg.Target.PromoURL = "/joinPromotion/"
	cfg.Client.HeaderProfile = "mobile"

	// ─── Create HTTP Client ───
	client, err := core.NewProbeClient(&cfg.Client, logger.Logger)
	if err != nil {
		logger.Error("Failed to create HTTP client: %v", err)
		PublishStatus(s.Bus, "error", fmt.Sprintf("Failed to create HTTP client: %v", err))
		s.mu.Lock()
		s.State = StateError
		s.mu.Unlock()
		return
	}
	defer client.Close()

	// ─── Create Session ───
	session := core.NewSession(client, domain.URL, logger.Logger)

	// ─── Login (same as Android binary) ───
	err = session.Login("/api2/v2/login", username, password, "meta[name='csrf-token']")
	if err != nil {
		PublishStatus(s.Bus, "error", fmt.Sprintf("Login failed: %v", err))
		s.mu.Lock()
		s.State = StateError
		s.mu.Unlock()
		return
	}

	if !session.IsLoggedIn {
		logger.Error("[!] Login failed! Server Message: Invalid credentials")
		PublishStatus(s.Bus, "error", "Login failed: Invalid credentials")
		s.mu.Lock()
		s.State = StateError
		s.mu.Unlock()
		return
	}

	// ─── Wait for session to settle (same as Android binary) ───
	logger.Info("[*] Waiting 3 seconds for session to settle...")
	time.Sleep(3 * time.Second)

	// ─── Bonus Flow (same as Android binary) ───
	logger.Section(fmt.Sprintf("Starting Bonus Flow for: %s", domain.URL))
	logger.Info("[*] Firing parallel promotion claims...")

	promoBaseURL := domain.URL + "/joinPromotion/"

	// ─── Scrape real promotion IDs from the site (like the binary does) ───
	logger.Info("[*] Fetching promotion list from site...")
	promoIDs := fetchPromoIDs(client, domain.URL, logger)
	if len(promoIDs) == 0 {
		logger.Info("[!] No promotions found — using known IDs: 14, 17")
		promoIDs = []string{"14", "17"}
	}
	logger.Info("[*] Found %d promotions to claim", len(promoIDs))

	// ─── Get fresh CSRF token for promotion claims ───
	// Binary confirmed field name: "Accept_token" (from binary string block)
	acceptToken, _ := session.ExtractCSRF(domain.URL+"/promotions", "meta[name='csrf-token']")

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]struct {
		ID     string
		Status string
	}, 0)

	for _, promoID := range promoIDs {
		wg.Add(1)
		go func(pid string) {
			defer wg.Done()

			// Binary confirmed POST fields: Accept_token + amount
			formData := url.Values{}
			formData.Set("Accept_token", acceptToken)
			formData.Set("amount", amount)

			// Log exact format from binary: [->] Firing Promo 17 at: 10:18:28.540658
			logger.Info("    [->] Firing Promo %s at: %s", pid, time.Now().Format("15:04:05.000000"))

			// Build request manually to set AJAX headers (same as login)
			claimURL := promoBaseURL + pid
			req, _ := http.NewRequest("POST", claimURL, strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
			req.Header.Set("X-Csrf-Token", acceptToken)
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Origin", domain.URL)
			req.Header.Set("Referer", domain.URL+"/promotions/"+pid)

			resp, _, err := client.Do(req)
			status := "error"
			if err == nil {
				body, _ := core.ReadBody(resp)
				// 200, 201, 202 = success; 302 = redirect (also success for this site)
				if (resp.StatusCode >= 200 && resp.StatusCode < 400) || resp.StatusCode == 302 {
					var jsonResp map[string]interface{}
					if json.Unmarshal([]byte(body), &jsonResp) == nil {
						if s, ok := jsonResp["status"].(string); ok {
							status = s
						} else if s, ok := jsonResp["message"].(string); ok {
							status = s
						} else {
							status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
						}
					} else {
						status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
					}
				} else {
					status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
				}
			} else {
				status = err.Error()
			}

			mu.Lock()
			results = append(results, struct {
				ID     string
				Status string
			}{pid, status})
			mu.Unlock()

			// Publish individual result
			logger.Info("[+] Promotion %s Status: %s", pid, status)
		}(promoID)
	}

	wg.Wait()

	logger.Success("[+] Bonus Flow Completed.")
	logger.Info("")
	logger.Success("[*] All done Good Luck! :)")

	// ─── Done ───
	s.mu.Lock()
	s.State = StateComplete
	s.mu.Unlock()

	PublishStatus(s.Bus, "complete", fmt.Sprintf(
		"Bot complete — %d promotion claims processed on %s",
		len(results), domain.Name))
}

// fetchPromoIDs scrapes /promotions page after login and extracts IDs
// from links like /promotions/14, /promotions/17
// Confirmed: playkaro365.com/promotions/14 and /promotions/17
func fetchPromoIDs(client *core.ProbeClient, baseURL string, logger *WebLogger) []string {
	var ids []string
	seen := make(map[string]bool)

	// The promotions listing page
	promoPageURL := baseURL + "/promotions"

	resp, _, err := client.GET(promoPageURL)
	if err != nil {
		logger.Warn("[!] Could not fetch %s: %v", promoPageURL, err)
		return ids
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	resp.Body.Close()
	if err != nil {
		logger.Warn("[!] Could not parse promotions page: %v", err)
		return ids
	}

	// Find all <a href="/promotions/{number}"> links
	doc.Find("a[href]").Each(func(i int, sel *goquery.Selection) {
		href, _ := sel.Attr("href")
		id := extractPromoIDFromHref(href)
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	})

	// Also check data-id, data-promo-id on any element
	doc.Find("[data-id], [data-promo-id], [data-promotion-id]").Each(func(i int, sel *goquery.Selection) {
		for _, attr := range []string{"data-id", "data-promo-id", "data-promotion-id"} {
			if val, exists := sel.Attr(attr); exists && val != "" && !seen[val] {
				// Only numeric-looking IDs
				if isNumeric(val) {
					seen[val] = true
					ids = append(ids, val)
				}
			}
		}
	})

	return ids
}

// extractPromoIDFromHref extracts a numeric ID from paths like:
//   /promotions/14   → "14"
//   /joinPromotion/17 → "17"
func extractPromoIDFromHref(href string) string {
	// Patterns to check in order
	patterns := []string{"/promotions/", "/joinPromotion/", "/promotion/"}
	for _, pat := range patterns {
		idx := strings.Index(href, pat)
		if idx == -1 {
			continue
		}
		rest := href[idx+len(pat):]
		// Take the numeric part
		end := strings.IndexAny(rest, "/?&#\" ")
		if end == -1 {
			end = len(rest)
		}
		id := strings.TrimSpace(rest[:end])
		if id != "" && isNumeric(id) {
			return id
		}
	}
	return ""
}

// isNumeric returns true if the string is a pure number
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}


// ─── SSE Handler ───

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := s.Bus.Subscribe()
	defer s.Bus.Unsubscribe(ch)

	ctx := r.Context()
	for {
		select {
		case event := <-ch:
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}
