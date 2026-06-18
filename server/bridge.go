package server

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"casinoprobe/utils"
)

// ─── SSE Event Types ───

const (
	EventLog    = "log"
	EventStatus = "status"
)

// SSEEvent is a single event pushed to the browser via Server-Sent Events.
type SSEEvent struct {
	Type      string      `json:"type"`
	Timestamp string      `json:"timestamp"`
	Level     string      `json:"level,omitempty"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
}

// ─── Event Bus (pub/sub for SSE) ───

type EventBus struct {
	subscribers map[chan SSEEvent]bool
	mu          sync.RWMutex
}

func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[chan SSEEvent]bool),
	}
}

func (eb *EventBus) Subscribe() chan SSEEvent {
	ch := make(chan SSEEvent, 128)
	eb.mu.Lock()
	eb.subscribers[ch] = true
	eb.mu.Unlock()
	return ch
}

func (eb *EventBus) Unsubscribe(ch chan SSEEvent) {
	eb.mu.Lock()
	delete(eb.subscribers, ch)
	eb.mu.Unlock()
	close(ch)
}

func (eb *EventBus) Publish(event SSEEvent) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	for ch := range eb.subscribers {
		select {
		case ch <- event:
		default:
			// Drop if buffer full
		}
	}
}

func (eb *EventBus) PublishJSON(event SSEEvent) {
	event.Timestamp = time.Now().Format("15:04:05")
	eb.Publish(event)
}

// ─── Helper Publishers ───

func PublishStatus(bus *EventBus, level, message string) {
	bus.Publish(SSEEvent{
		Type:      EventStatus,
		Timestamp: time.Now().Format("15:04:05"),
		Level:     level,
		Message:   message,
	})
}

// ─── WebLogger (dual output: terminal + SSE) ───

type WebLogger struct {
	*utils.Logger
	Bus *EventBus
}

func NewWebLogger(bus *EventBus) *WebLogger {
	return &WebLogger{
		Logger: utils.NewLogger(utils.LevelDebug, ""),
		Bus:    bus,
	}
}

// Override methods to send ONLY to SSE (suppress stdout in web mode)

func (wl *WebLogger) Info(format string, args ...interface{}) {
	wl.emit("info", format, args...)
}

func (wl *WebLogger) Success(format string, args ...interface{}) {
	wl.emit("success", format, args...)
}

func (wl *WebLogger) Warn(format string, args ...interface{}) {
	wl.emit("warning", format, args...)
}

func (wl *WebLogger) Error(format string, args ...interface{}) {
	wl.emit("error", format, args...)
}

func (wl *WebLogger) Section(title string) {
	wl.Bus.Publish(SSEEvent{
		Type:      EventLog,
		Timestamp: time.Now().Format("15:04:05"),
		Level:     "section",
		Message:   title,
	})
}

func (wl *WebLogger) Banner() {
	// No-op in web mode
}

func (wl *WebLogger) emit(level, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	wl.Bus.Publish(SSEEvent{
		Type:      EventLog,
		Timestamp: time.Now().Format("15:04:05"),
		Level:     level,
		Message:   msg,
	})
}

// MarshalEvent serializes an SSE event to JSON bytes.
func MarshalEvent(event SSEEvent) ([]byte, error) {
	return json.Marshal(event)
}
