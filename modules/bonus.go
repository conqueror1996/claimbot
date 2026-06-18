package modules

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"casinoprobe/core"
	"casinoprobe/report"
	"casinoprobe/utils"
)

// BonusModule tests bonus/promotion endpoint logic for business logic flaws.
type BonusModule struct {
	Client   *core.ProbeClient
	Session  *core.Session
	Logger   *utils.Logger
	BaseURL  string
	PromoURL string
	Workers  int
	Findings []report.Finding
}

// NewBonusModule creates a new bonus/promotion testing module.
func NewBonusModule(client *core.ProbeClient, session *core.Session, baseURL, promoURL string, workers int, logger *utils.Logger) *BonusModule {
	return &BonusModule{
		Client:   client,
		Session:  session,
		Logger:   logger,
		BaseURL:  strings.TrimRight(baseURL, "/"),
		PromoURL: promoURL,
		Workers:  workers,
		Findings: make([]report.Finding, 0),
	}
}

// Run executes all bonus/promotion security tests.
func (b *BonusModule) Run() []report.Finding {
	b.Logger.Section("Module: Bonus/Promotion Logic Testing")

	b.testParameterTampering()
	b.testRaceCondition()
	b.testNegativeValues()
	b.testReplayAttack()
	b.testPromoCodeFuzzing()

	b.Logger.Info("Bonus testing complete — %d findings", len(b.Findings))
	return b.Findings
}

// testParameterTampering tests if amount and other parameters can be tampered.
func (b *BonusModule) testParameterTampering() {
	b.Logger.Info("Testing parameter tampering on promotion endpoint...")

	promoFullURL := b.BaseURL + b.PromoURL

	for _, tamperVal := range utils.SecurityPayloads.NumericTamper {
		formData := url.Values{}
		formData.Set("amount", tamperVal)
		formData.Set("promo_code", "TEST")

		resp, _, err := b.Client.POST(promoFullURL, formData)
		if err != nil {
			continue
		}
		body, _ := core.ReadBody(resp)

		// Check if the server accepted an unusual value
		if resp.StatusCode == 200 && !containsError(body) {
			b.Logger.Vuln("HIGH", "Parameter Tampering Accepted",
				fmt.Sprintf("Amount value '%s' was accepted", tamperVal))
			b.addFinding("HIGH", "Parameter Tampering — Amount Field",
				fmt.Sprintf("The promotion endpoint accepted amount value '%s' without proper validation. This could allow attackers to claim arbitrary bonus amounts.", tamperVal),
				"Implement strict server-side validation for all numeric parameters. Use allowlists for acceptable values and ranges.")
		} else {
			b.Logger.Success("Tampered amount '%s' correctly rejected", tamperVal)
		}
	}
}

// testRaceCondition uses concurrent requests to test for TOCTOU race conditions.
func (b *BonusModule) testRaceCondition() {
	b.Logger.Info("Testing race condition (concurrent bonus claims)...")

	promoFullURL := b.BaseURL + b.PromoURL
	workers := b.Workers
	if workers < 2 {
		workers = 3
	}

	results := make([]int, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0

	// Fire multiple concurrent requests
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			formData := url.Values{}
			formData.Set("amount", "100")
			formData.Set("promo_code", "WELCOME")

			resp, _, err := b.Client.POST(promoFullURL, formData)
			if err != nil {
				results[idx] = 0
				return
			}
			body, _ := core.ReadBody(resp)
			results[idx] = resp.StatusCode

			if resp.StatusCode == 200 && !containsError(body) {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	if successCount > 1 {
		b.Logger.Vuln("CRITICAL", "Race Condition — Multiple Claims",
			fmt.Sprintf("%d out of %d concurrent requests succeeded", successCount, workers))
		b.addFinding("CRITICAL", "Race Condition in Promotion Claiming",
			fmt.Sprintf("%d out of %d simultaneous promotion claim requests succeeded. This indicates a Time-of-Check to Time-of-Use (TOCTOU) vulnerability allowing multiple claims.", successCount, workers),
			"Implement database-level locking or use atomic operations to prevent concurrent claims. Use a unique constraint on user+promotion combination.")
	} else {
		b.Logger.Success("Race condition test passed — only %d/%d succeeded", successCount, workers)
	}
}

// testNegativeValues tests if negative amounts are accepted.
func (b *BonusModule) testNegativeValues() {
	b.Logger.Info("Testing negative value injection...")

	promoFullURL := b.BaseURL + b.PromoURL
	negativeValues := []string{"-1", "-100", "-0.01", "-999999"}

	for _, val := range negativeValues {
		formData := url.Values{}
		formData.Set("amount", val)

		resp, _, err := b.Client.POST(promoFullURL, formData)
		if err != nil {
			continue
		}
		body, _ := core.ReadBody(resp)

		if resp.StatusCode == 200 && !containsError(body) {
			b.Logger.Vuln("CRITICAL", "Negative Value Accepted",
				fmt.Sprintf("Amount '%s' was accepted — potential fund reversal", val))
			b.addFinding("CRITICAL", "Negative Amount Injection",
				fmt.Sprintf("The promotion endpoint accepted negative amount value '%s'. This could allow attackers to reverse transactions or credit their account.", val),
				"Reject negative values server-side. Validate that amounts are positive and within acceptable bounds.")
		} else {
			b.Logger.Success("Negative value '%s' correctly rejected", val)
		}
	}
}

// testReplayAttack tests if the same promotion claim can be replayed.
func (b *BonusModule) testReplayAttack() {
	b.Logger.Info("Testing replay attack (submitting same claim twice)...")

	promoFullURL := b.BaseURL + b.PromoURL
	formData := url.Values{}
	formData.Set("amount", "50")
	formData.Set("promo_code", "WELCOME")

	// First submission
	resp1, _, err := b.Client.POST(promoFullURL, formData)
	if err != nil {
		b.Logger.Error("First claim failed: %v", err)
		return
	}
	body1, _ := core.ReadBody(resp1)
	firstSuccess := resp1.StatusCode == 200 && !containsError(body1)

	// Wait a moment
	time.Sleep(1 * time.Second)

	// Replay the exact same request
	resp2, _, err := b.Client.POST(promoFullURL, formData)
	if err != nil {
		return
	}
	body2, _ := core.ReadBody(resp2)
	secondSuccess := resp2.StatusCode == 200 && !containsError(body2)

	if firstSuccess && secondSuccess {
		b.Logger.Vuln("HIGH", "Replay Attack Possible",
			"Same promotion claim accepted twice")
		b.addFinding("HIGH", "Promotion Claim Replay Possible",
			"The same promotion claim request was accepted twice, indicating no replay protection. An attacker could claim the same bonus multiple times.",
			"Implement idempotency keys or track claimed promotions per user to prevent duplicate claims")
	} else {
		b.Logger.Success("Replay correctly prevented — second claim rejected")
	}
}

// testPromoCodeFuzzing fuzzes promotion codes for weak validation.
func (b *BonusModule) testPromoCodeFuzzing() {
	b.Logger.Info("Fuzzing promotion codes...")

	promoFullURL := b.BaseURL + b.PromoURL

	for i, code := range utils.SecurityPayloads.PromoCodes {
		b.Logger.Progress(i+1, len(utils.SecurityPayloads.PromoCodes), code)

		formData := url.Values{}
		formData.Set("amount", "10")
		formData.Set("promo_code", code)

		resp, _, err := b.Client.POST(promoFullURL, formData)
		if err != nil {
			continue
		}
		body, _ := core.ReadBody(resp)

		if resp.StatusCode == 200 && !containsError(body) {
			b.Logger.Vuln("MEDIUM", "Promo Code Accepted",
				fmt.Sprintf("Code '%s' was accepted", code))
			b.addFinding("MEDIUM", "Weak Promotion Code Validation",
				fmt.Sprintf("The promotion code '%s' was accepted. If this is not a valid code, it indicates weak validation.", code),
				"Validate promotion codes against a database of active codes. Log and alert on fuzzing attempts.")
		}

		// Check for injection in error messages
		if strings.Contains(body, code) && (strings.Contains(code, "'") || strings.Contains(code, "{{")) {
			b.Logger.Vuln("HIGH", "Input Reflection in Response",
				fmt.Sprintf("Payload '%s' reflected in response", code))
			b.addFinding("HIGH", "Input Reflection — Potential Injection",
				fmt.Sprintf("The input '%s' was reflected in the server response, indicating potential SQL injection or template injection vulnerability.", code),
				"Sanitize all user input before including in responses. Use parameterized queries.")
		}
	}
}

func containsError(body string) bool {
	lower := strings.ToLower(body)
	errorIndicators := []string{"error", "invalid", "failed", "denied", "unauthorized", "forbidden", "expired", "not found", "not allowed"}
	for _, indicator := range errorIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

func (b *BonusModule) addFinding(severity, title, detail, remediation string) {
	b.Findings = append(b.Findings, report.Finding{
		Module:      "Bonus/Promotion",
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		Remediation: remediation,
	})
}
