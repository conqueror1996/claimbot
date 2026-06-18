# Casino Bonus Automation Bot

A fast, mobile-friendly web UI that automates casino bonus/promotion claims. Built in Go with Server-Sent Events for real-time output.

## Features

- 🎯 Supports 4 casino domains (PlayKaro 365, JeetExch 99, SpinJeet 365, WinClash 365)
- ⚡ Parallel promotion claiming
- 🔐 Auto CSRF token extraction
- 📡 Live console output via SSE
- 📱 Mobile-first responsive UI
- 🚀 Single binary deployment

## Quick Start

```bash
# Clone
git clone https://github.com/conqueror1996/claimbot
cd claimbot

# Install dependencies
go mod tidy

# Build
go build -o claimbot .

# Run (web UI on port 8844)
./claimbot --web

# Custom port
./claimbot --web 9000
```

Then open: **http://localhost:8844**

## Usage

1. Select your target domain
2. Enter your email/username and password
3. Enter the claim amount (INR)
4. Press **Run Bot**

The bot will:
- Extract CSRF token from the site
- Login via `/api2/v2/login`
- Wait 3 seconds for session to settle
- Scrape `/promotions` to find real promotion IDs
- Fire parallel POST requests to `/joinPromotion/{id}`

## Build for Android (Termux)

```bash
GOOS=android GOARCH=arm64 go build -o claimbot-android .
```

## Project Structure

```
.
├── main.go          # Entry point (--web flag)
├── server/          # HTTP server + SSE + bot logic
│   ├── server.go    # Main server + runBot()
│   └── bridge.go    # WebLogger + EventBus
├── core/            # HTTP client + session management
│   ├── client.go    # ProbeClient with retry/headers
│   └── session.go   # Login + CSRF extraction
├── config/          # Default configuration
├── utils/           # Logger utilities
├── web/             # Frontend
│   ├── index.html
│   ├── style.css
│   └── app.js
└── go.mod
```

## Tech Stack

- **Backend**: Go (net/http, goquery, cascadia)
- **Frontend**: Vanilla HTML/CSS/JS
- **Real-time**: Server-Sent Events (SSE)
