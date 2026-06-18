package utils

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ANSI color codes
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"

	BgRed    = "\033[41m"
	BgGreen  = "\033[42m"
	BgYellow = "\033[43m"
	BgBlue   = "\033[44m"
	BgCyan   = "\033[46m"
)

// LogLevel represents the severity of a log message.
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelSuccess
	LevelWarning
	LevelError
	LevelCritical
	LevelVuln
)

// Logger provides structured, colored logging for the security testing framework.
type Logger struct {
	Level   LogLevel
	LogFile *os.File
}

// NewLogger creates a new Logger instance. If logPath is non-empty, logs are also written to a file.
func NewLogger(level LogLevel, logPath string) *Logger {
	l := &Logger{Level: level}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			l.LogFile = f
		}
	}
	return l
}

func (l *Logger) log(level LogLevel, prefix, color, msg string, args ...interface{}) {
	if level < l.Level {
		return
	}
	timestamp := time.Now().Format("15:04:05")
	formatted := fmt.Sprintf(msg, args...)
	consoleLine := fmt.Sprintf("%s%s %s[%s]%s %s", Dim, timestamp, color, prefix, Reset, formatted)
	fmt.Println(consoleLine)

	if l.LogFile != nil {
		fileLine := fmt.Sprintf("[%s] [%s] %s\n", timestamp, prefix, formatted)
		l.LogFile.WriteString(fileLine)
	}
}

// Debug logs a debug-level message.
func (l *Logger) Debug(msg string, args ...interface{}) {
	l.log(LevelDebug, "DBG", Dim, msg, args...)
}

// Info logs an informational message.
func (l *Logger) Info(msg string, args ...interface{}) {
	l.log(LevelInfo, "INF", Blue, msg, args...)
}

// Success logs a success message.
func (l *Logger) Success(msg string, args ...interface{}) {
	l.log(LevelSuccess, " ✓ ", Green, msg, args...)
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.log(LevelWarning, "WRN", Yellow, msg, args...)
}

// Error logs an error message.
func (l *Logger) Error(msg string, args ...interface{}) {
	l.log(LevelError, "ERR", Red, msg, args...)
}

// Critical logs a critical-level message with background highlight.
func (l *Logger) Critical(msg string, args ...interface{}) {
	l.log(LevelCritical, "CRT", BgRed+White, msg, args...)
}

// Vuln logs a discovered vulnerability.
func (l *Logger) Vuln(severity, title, detail string) {
	var color string
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		color = BgRed + White
	case "HIGH":
		color = Red
	case "MEDIUM":
		color = Yellow
	case "LOW":
		color = Cyan
	default:
		color = Dim
	}
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("%s%s %s[VULN:%s]%s %s%s — %s%s\n",
		Dim, timestamp, color, severity, Reset, Bold, title, Reset, detail)

	if l.LogFile != nil {
		l.LogFile.WriteString(fmt.Sprintf("[%s] [VULN:%s] %s — %s\n", timestamp, severity, title, detail))
	}
}

// Banner prints the CasinoProbe startup banner.
func (l *Logger) Banner() {
	banner := `
` + Cyan + Bold + `
   ╔═══════════════════════════════════════════════════════╗
   ║` + White + `   ♠ ♥ ♦ ♣  CasinoProbe  ♣ ♦ ♥ ♠` + Cyan + `                    ║
   ║` + Dim + `   Casino Application Security Testing Framework` + Reset + Cyan + Bold + `     ║
   ║` + Dim + `   v1.0.0 — For Authorized Testing Only` + Reset + Cyan + Bold + `              ║
   ╚═══════════════════════════════════════════════════════╝` + Reset + `
` + Yellow + `
   ⚠  WARNING: This tool is for AUTHORIZED security testing only.
   ⚠  Unauthorized access to computer systems is illegal.
   ⚠  Ensure you have written permission before proceeding.
` + Reset
	fmt.Print(banner)
}

// Section prints a section header divider.
func (l *Logger) Section(title string) {
	line := strings.Repeat("─", 50)
	fmt.Printf("\n%s%s┌%s┐%s\n", Bold, Cyan, line, Reset)
	fmt.Printf("%s%s│ %-48s │%s\n", Bold, Cyan, title, Reset)
	fmt.Printf("%s%s└%s┘%s\n\n", Bold, Cyan, line, Reset)
}

// Progress prints a progress indicator.
func (l *Logger) Progress(current, total int, msg string) {
	pct := float64(current) / float64(total) * 100
	barLen := 30
	filled := int(float64(barLen) * float64(current) / float64(total))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)
	fmt.Printf("\r%s  [%s%s%s] %s%.0f%%%s %s",
		Dim, Green, bar, Reset, Bold, pct, Reset, msg)
	if current == total {
		fmt.Println()
	}
}

// Close closes the log file if one is open.
func (l *Logger) Close() {
	if l.LogFile != nil {
		l.LogFile.Close()
	}
}
