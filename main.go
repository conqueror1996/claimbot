package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"casinoprobe/config"
	"casinoprobe/core"
	"casinoprobe/modules"
	"casinoprobe/report"
	"casinoprobe/server"
	"casinoprobe/utils"
)

func main() {
	// Check for --web flag to launch web UI
	if len(os.Args) > 1 && (os.Args[1] == "--web" || os.Args[1] == "-web") {
		port := ":8844"
		if len(os.Args) > 2 {
			port = ":" + os.Args[2]
		}
		server.Start(port)
		return
	}

	logger := utils.NewLogger(utils.LevelDebug, "")
	logger.Banner()

	scanner := bufio.NewScanner(os.Stdin)

	// ─── Authorization Confirmation ───
	fmt.Printf("\n  %s%sAre you authorized to test the target application? (yes/no): %s", utils.Bold, utils.Yellow, utils.Reset)
	scanner.Scan()
	if strings.TrimSpace(strings.ToLower(scanner.Text())) != "yes" {
		fmt.Printf("\n  %s❌ You must have written authorization before testing. Exiting.%s\n\n", utils.Red, utils.Reset)
		os.Exit(1)
	}

	// ─── Target Configuration ───
	logger.Section("Target Configuration")

	fmt.Printf("  %sEnter target base URL%s (e.g., https://example.com): ", utils.Bold, utils.Reset)
	scanner.Scan()
	baseURL := strings.TrimSpace(scanner.Text())
	if baseURL == "" {
		logger.Error("Base URL is required")
		os.Exit(1)
	}

	fmt.Printf("  %sLogin endpoint path%s (default: /api2/v2/login): ", utils.Bold, utils.Reset)
	scanner.Scan()
	loginURL := strings.TrimSpace(scanner.Text())
	if loginURL == "" {
		loginURL = "/api2/v2/login"
	}

	fmt.Printf("  %sPromotion endpoint path%s (default: /joinPromotion/): ", utils.Bold, utils.Reset)
	scanner.Scan()
	promoURL := strings.TrimSpace(scanner.Text())
	if promoURL == "" {
		promoURL = "/joinPromotion/"
	}

	fmt.Printf("  %sCSRF selector%s (default: meta[name='csrf-token']): ", utils.Bold, utils.Reset)
	scanner.Scan()
	csrfSel := strings.TrimSpace(scanner.Text())
	if csrfSel == "" {
		csrfSel = "meta[name='csrf-token']"
	}

	// ─── Authentication Credentials ───
	logger.Section("Authentication Credentials")

	fmt.Printf("  %sUsername: %s", utils.Bold, utils.Reset)
	scanner.Scan()
	username := strings.TrimSpace(scanner.Text())

	fmt.Printf("  %sPassword: %s", utils.Bold, utils.Reset)
	scanner.Scan()
	password := strings.TrimSpace(scanner.Text())

	// ─── Module Selection ───
	logger.Section("Module Selection")

	fmt.Println("  Select modules to run:")
	fmt.Printf("  %s1%s. Reconnaissance (fingerprint, headers, endpoints)\n", utils.Cyan+utils.Bold, utils.Reset)
	fmt.Printf("  %s2%s. Authentication Testing (CSRF, sessions, brute-force)\n", utils.Cyan+utils.Bold, utils.Reset)
	fmt.Printf("  %s3%s. Bonus/Promotion Logic Testing (parameter tampering, race conditions)\n", utils.Cyan+utils.Bold, utils.Reset)
	fmt.Printf("  %s4%s. Redirect Analysis (open redirects, token leakage)\n", utils.Cyan+utils.Bold, utils.Reset)
	fmt.Printf("  %s5%s. Rate Limit Testing (threshold detection, bypass techniques)\n", utils.Cyan+utils.Bold, utils.Reset)
	fmt.Printf("  %sA%s. Run ALL modules\n", utils.Green+utils.Bold, utils.Reset)
	fmt.Println()
	fmt.Printf("  %sChoice (comma-separated, e.g., 1,2,3 or A for all): %s", utils.Bold, utils.Reset)
	scanner.Scan()
	moduleChoice := strings.TrimSpace(strings.ToUpper(scanner.Text()))

	// ─── Header Profile ───
	fmt.Println()
	fmt.Printf("  %sHeader profile%s (mobile/desktop/api, default: mobile): ", utils.Bold, utils.Reset)
	scanner.Scan()
	headerProfile := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if headerProfile == "" {
		headerProfile = "mobile"
	}

	// ─── Build Configuration ───
	cfg := config.DefaultConfig()
	cfg.Target.BaseURL = baseURL
	cfg.Target.LoginURL = loginURL
	cfg.Target.PromoURL = promoURL
	cfg.Auth.Username = username
	cfg.Auth.Password = password
	cfg.Auth.CSRFSelector = csrfSel
	cfg.Client.HeaderProfile = headerProfile

	// Parse module selection
	runAll := moduleChoice == "A" || moduleChoice == ""
	runRecon := runAll || strings.Contains(moduleChoice, "1")
	runAuth := runAll || strings.Contains(moduleChoice, "2")
	runBonus := runAll || strings.Contains(moduleChoice, "3")
	runRedirect := runAll || strings.Contains(moduleChoice, "4")
	runRateLimit := runAll || strings.Contains(moduleChoice, "5")

	// ─── Initialize ───
	logger.Section("Initializing CasinoProbe")

	// Set up log file
	logger = utils.NewLogger(utils.LevelDebug, cfg.Output.LogFile)
	defer logger.Close()

	logger.Info("Target: %s", baseURL)
	logger.Info("Login endpoint: %s", loginURL)
	logger.Info("Promo endpoint: %s", promoURL)
	logger.Info("Header profile: %s", headerProfile)

	// Create HTTP client
	client, err := core.NewProbeClient(&cfg.Client, logger)
	if err != nil {
		logger.Error("Failed to create HTTP client: %v", err)
		os.Exit(1)
	}
	defer client.Close()

	// Create session
	session := core.NewSession(client, baseURL, logger)

	// Create report
	rpt := report.NewReport(baseURL)

	// ─── Login ───
	if username != "" && password != "" {
		err = session.Login(loginURL, username, password, csrfSel)
		if err != nil {
			logger.Error("Login failed: %v", err)
			logger.Warn("Continuing with unauthenticated testing...")
		}
	}

	// ─── Execute Modules ───
	if runRecon {
		recon := modules.NewReconModule(client, session, baseURL, logger)
		rpt.AddFindings(recon.Run())
	}

	if runAuth {
		auth := modules.NewAuthModule(client, session, baseURL, loginURL, username, password, csrfSel, logger)
		rpt.AddFindings(auth.Run())
	}

	if runBonus {
		bonus := modules.NewBonusModule(client, session, baseURL, promoURL, cfg.Client.Workers, logger)
		rpt.AddFindings(bonus.Run())
	}

	if runRedirect {
		redirect := modules.NewRedirectModule(client, session, baseURL, logger)
		rpt.AddFindings(redirect.Run())
	}

	if runRateLimit {
		rateLimit := modules.NewRateLimitModule(client, session, baseURL, loginURL, logger)
		rpt.AddFindings(rateLimit.Run())
	}

	// ─── Generate Reports ───
	logger.Section("Report Generation")

	rpt.Finalize(client.ReqCount)

	// JSON Report
	jsonPath := cfg.Output.ReportJSON
	if jsonPath != "" {
		if err := rpt.SaveJSON(jsonPath); err != nil {
			logger.Error("Failed to save JSON report: %v", err)
		} else {
			logger.Success("JSON report saved: %s", jsonPath)
		}
	}

	// HTML Report
	htmlPath := cfg.Output.ReportHTML
	if htmlPath == "" {
		htmlPath = "report.html"
	}
	if err := rpt.SaveHTML(htmlPath); err != nil {
		logger.Error("Failed to save HTML report: %v", err)
	} else {
		logger.Success("HTML report saved: %s", htmlPath)
	}

	// Terminal Summary
	rpt.PrintSummary()

	logger.Info("Log file: %s", cfg.Output.LogFile)
	logger.Info("Total HTTP requests: %d", client.ReqCount)
	fmt.Printf("\n  %s%s♠ CasinoProbe assessment complete ♠%s\n\n", utils.Bold, utils.Cyan, utils.Reset)
}
