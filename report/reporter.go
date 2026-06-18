package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Finding represents a single security finding from any module.
type Finding struct {
	Module      string `json:"module"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

// Report is the complete security assessment report.
type Report struct {
	ToolName   string    `json:"tool_name"`
	Version    string    `json:"version"`
	Target     string    `json:"target"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Duration   string    `json:"duration"`
	TotalReqs  int       `json:"total_requests"`
	Findings   []Finding `json:"findings"`
	Summary    Summary   `json:"summary"`
}

// Summary holds aggregate statistics about findings.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// NewReport creates a new report.
func NewReport(target string) *Report {
	return &Report{
		ToolName:  "CasinoProbe",
		Version:   "1.0.0",
		Target:    target,
		StartTime: time.Now(),
		Findings:  make([]Finding, 0),
	}
}

// AddFindings adds a batch of findings to the report.
func (r *Report) AddFindings(findings []Finding) {
	r.Findings = append(r.Findings, findings...)
}

// Finalize calculates the summary and end time.
func (r *Report) Finalize(totalReqs int) {
	r.EndTime = time.Now()
	r.Duration = r.EndTime.Sub(r.StartTime).Round(time.Second).String()
	r.TotalReqs = totalReqs

	// Sort findings by severity
	severityOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	sort.Slice(r.Findings, func(i, j int) bool {
		return severityOrder[r.Findings[i].Severity] < severityOrder[r.Findings[j].Severity]
	})

	// Calculate summary
	for _, f := range r.Findings {
		r.Summary.Total++
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			r.Summary.Critical++
		case "HIGH":
			r.Summary.High++
		case "MEDIUM":
			r.Summary.Medium++
		case "LOW":
			r.Summary.Low++
		case "INFO":
			r.Summary.Info++
		}
	}
}

// SaveJSON writes the report as a JSON file.
func (r *Report) SaveJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// SaveHTML writes the report as a styled HTML file.
func (r *Report) SaveHTML(path string) error {
	html := r.generateHTML()
	return os.WriteFile(path, []byte(html), 0644)
}

// PrintSummary outputs the report summary to the terminal.
func (r *Report) PrintSummary() {
	const (
		Reset  = "\033[0m"
		Bold   = "\033[1m"
		Red    = "\033[31m"
		Green  = "\033[32m"
		Yellow = "\033[33m"
		Cyan   = "\033[36m"
		BgRed  = "\033[41m"
		White  = "\033[37m"
	)

	fmt.Println()
	fmt.Printf("%s%s╔══════════════════════════════════════════════════╗%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s║         ♠ CasinoProbe Assessment Report ♠        ║%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════╝%s\n", Bold, Cyan, Reset)
	fmt.Println()
	fmt.Printf("  %sTarget:%s     %s\n", Bold, Reset, r.Target)
	fmt.Printf("  %sDuration:%s   %s\n", Bold, Reset, r.Duration)
	fmt.Printf("  %sRequests:%s   %d\n", Bold, Reset, r.TotalReqs)
	fmt.Println()
	fmt.Printf("  %s┌─────────────────────────────────────────┐%s\n", Cyan, Reset)
	fmt.Printf("  %s│ Severity    │ Count                     │%s\n", Cyan, Reset)
	fmt.Printf("  %s├─────────────────────────────────────────┤%s\n", Cyan, Reset)

	if r.Summary.Critical > 0 {
		fmt.Printf("  %s│%s %s CRITICAL  %s │ %-25d %s│%s\n", Cyan, Reset, BgRed+White+Bold, Reset, r.Summary.Critical, Cyan, Reset)
	}
	if r.Summary.High > 0 {
		fmt.Printf("  %s│%s %s HIGH      %s │ %-25d %s│%s\n", Cyan, Reset, Red+Bold, Reset, r.Summary.High, Cyan, Reset)
	}
	if r.Summary.Medium > 0 {
		fmt.Printf("  %s│%s %s MEDIUM    %s │ %-25d %s│%s\n", Cyan, Reset, Yellow+Bold, Reset, r.Summary.Medium, Cyan, Reset)
	}
	if r.Summary.Low > 0 {
		fmt.Printf("  %s│%s %s LOW       %s │ %-25d %s│%s\n", Cyan, Reset, Cyan, Reset, r.Summary.Low, Cyan, Reset)
	}
	if r.Summary.Info > 0 {
		fmt.Printf("  %s│%s   INFO      │ %-25d %s│%s\n", Cyan, Reset, r.Summary.Info, Cyan, Reset)
	}
	fmt.Printf("  %s├─────────────────────────────────────────┤%s\n", Cyan, Reset)
	fmt.Printf("  %s│%s %s TOTAL     %s │ %-25d %s│%s\n", Cyan, Reset, Bold, Reset, r.Summary.Total, Cyan, Reset)
	fmt.Printf("  %s└─────────────────────────────────────────┘%s\n", Cyan, Reset)
	fmt.Println()

	if r.Summary.Critical > 0 || r.Summary.High > 0 {
		fmt.Printf("  %s%s⚠  CRITICAL/HIGH issues found — immediate action required%s\n", Bold, Red, Reset)
	} else if r.Summary.Total == 0 {
		fmt.Printf("  %s%s✓  No vulnerabilities detected%s\n", Bold, Green, Reset)
	} else {
		fmt.Printf("  %s%s●  Review findings and apply remediations%s\n", Bold, Yellow, Reset)
	}
	fmt.Println()
}

func (r *Report) generateHTML() string {
	findingsHTML := ""
	for _, f := range r.Findings {
		severityClass := strings.ToLower(f.Severity)
		findingsHTML += fmt.Sprintf(`
		<div class="finding %s">
			<div class="finding-header">
				<span class="severity-badge %s">%s</span>
				<span class="finding-module">[%s]</span>
				<strong>%s</strong>
			</div>
			<div class="finding-detail">
				<p><strong>Detail:</strong> %s</p>
				<p><strong>Remediation:</strong> %s</p>
			</div>
		</div>`, severityClass, severityClass, f.Severity, f.Module, f.Title, f.Detail, f.Remediation)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CasinoProbe Security Report — %s</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0a0e17; color: #e1e8f0; line-height: 1.6; }
.container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }
.header { text-align: center; margin-bottom: 40px; padding: 30px; background: linear-gradient(135deg, #1a1f36, #0d1117); border: 1px solid #30363d; border-radius: 16px; }
.header h1 { font-size: 2em; background: linear-gradient(135deg, #58a6ff, #bc8cff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.header .subtitle { color: #8b949e; margin-top: 8px; }
.meta { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 30px; }
.meta-card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 16px; }
.meta-card label { color: #8b949e; font-size: 0.85em; text-transform: uppercase; }
.meta-card .value { font-size: 1.2em; font-weight: 600; color: #58a6ff; }
.summary { display: flex; gap: 12px; margin-bottom: 30px; flex-wrap: wrap; }
.summary-badge { padding: 8px 20px; border-radius: 8px; font-weight: 700; font-size: 1.1em; }
.summary-badge.critical { background: #d32f2f22; color: #ff5252; border: 1px solid #ff5252; }
.summary-badge.high { background: #f4433622; color: #ff7043; border: 1px solid #ff7043; }
.summary-badge.medium { background: #ff980022; color: #ffb74d; border: 1px solid #ffb74d; }
.summary-badge.low { background: #00bcd422; color: #4dd0e1; border: 1px solid #4dd0e1; }
.summary-badge.info { background: #9e9e9e22; color: #bdbdbd; border: 1px solid #bdbdbd; }
.finding { margin-bottom: 16px; background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; border-left: 4px solid #30363d; }
.finding.critical { border-left-color: #ff5252; }
.finding.high { border-left-color: #ff7043; }
.finding.medium { border-left-color: #ffb74d; }
.finding.low { border-left-color: #4dd0e1; }
.finding.info { border-left-color: #bdbdbd; }
.finding-header { margin-bottom: 12px; }
.severity-badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 700; text-transform: uppercase; margin-right: 8px; }
.severity-badge.critical { background: #ff525233; color: #ff5252; }
.severity-badge.high { background: #ff704333; color: #ff7043; }
.severity-badge.medium { background: #ffb74d33; color: #ffb74d; }
.severity-badge.low { background: #4dd0e133; color: #4dd0e1; }
.severity-badge.info { background: #bdbdbd33; color: #bdbdbd; }
.finding-module { color: #8b949e; font-size: 0.85em; margin-right: 8px; }
.finding-detail p { margin-top: 8px; color: #b1bac4; }
.footer { text-align: center; margin-top: 40px; color: #484f58; font-size: 0.85em; }
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>♠ ♥ CasinoProbe Report ♦ ♣</h1>
<p class="subtitle">Casino Application Security Assessment</p>
</div>
<div class="meta">
<div class="meta-card"><label>Target</label><div class="value">%s</div></div>
<div class="meta-card"><label>Duration</label><div class="value">%s</div></div>
<div class="meta-card"><label>Requests Sent</label><div class="value">%d</div></div>
<div class="meta-card"><label>Date</label><div class="value">%s</div></div>
</div>
<div class="summary">
<div class="summary-badge critical">Critical: %d</div>
<div class="summary-badge high">High: %d</div>
<div class="summary-badge medium">Medium: %d</div>
<div class="summary-badge low">Low: %d</div>
<div class="summary-badge info">Info: %d</div>
</div>
<h2 style="margin-bottom: 20px; color: #58a6ff;">Findings</h2>
%s
<div class="footer">
<p>Generated by CasinoProbe v1.0.0 — For Authorized Testing Only</p>
<p>%s</p>
</div>
</div>
</body>
</html>`,
		r.Target, r.Target, r.Duration, r.TotalReqs,
		r.StartTime.Format("2006-01-02 15:04:05"),
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info,
		findingsHTML,
		r.EndTime.Format("2006-01-02 15:04:05 MST"))
}
