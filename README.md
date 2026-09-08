# NextDNS Telegram & Desktop Manager

A powerful dual-mode application (Desktop GUI + Headless daemon) to monitor, manage, and automate [NextDNS](https://nextdns.io/) profiles. Features an interactive Telegram Bot with actionable inline alerts and automated threat intelligence enrichment via URLhaus and urlscan.io.

---

## Highlights

- 🖥️ **Desktop GUI (Tkinter)**: Full-featured desktop control center with tabs for Live Logs, Denylists, TLD blocking, Alert tuning, and API settings.
- 🤖 **Interactive Telegram Bot**: Receive instant notifications on blocked queries, inspect logs, and manage denylists / TLDs directly from Telegram.
- ⚡ **One-Click Actions**: Approve, block, or ignore domains directly within Telegram chat via inline buttons.
- 🛡️ **Threat Intelligence Enrichment**: Automatic domain lookups through [URLhaus](https://urlhaus.abuse.ch/) and [urlscan.io](https://urlscan.io/) for enriched security context.
- 🚀 **Headless Server Mode**: Run as a lightweight background service on a VPS, Raspberry Pi, or home server without GUI dependencies.
- 🔒 **Privacy-First**: Sensitive tokens are redacted in logs and errors; local state files and `.env` credentials remain isolated on your machine.

---

## Architecture Overview

```
NextDNS-telegram/
├── nextdns_manager/           # Core modular package
│   ├── gui/                   # Desktop interface tabs & widgets
│   │   ├── alerts_tab.py      # Alert rules & background poller tuning
│   │   ├── apis_tab.py        # API credentials manager
│   │   ├── app.py             # Main GUI application window
│   │   ├── denylist_tab.py    # Denylist management & bulk tools
│   │   ├── logs_tab.py        # Real-time DNS query inspector
│   │   ├── settings_tab.py    # General preferences
│   │   ├── tlds_tab.py        # Top-Level Domain blocking
│   │   └── widgets.py         # Reusable UI components
│   ├── alerts.py              # Alert batching & deduplication logic
│   ├── caches.py              # In-memory TTL caches
│   ├── cli.py                 # CLI argument parsing & launcher
│   ├── constants.py           # Application constants & defaults
│   ├── headless.py            # Headless poller daemon
│   ├── nextdns_api.py         # NextDNS REST API client
│   ├── state.py               # Local state & persistence manager
│   ├── telegram_bot.py        # Telegram transport, menus & callbacks
│   ├── threat_intel.py        # URLhaus & urlscan.io threat enrichment
│   └── utils.py               # Helpers, sanitizers & validators
├── nextdns_manager_gui.py     # Main application launcher
├── .env.example               # Environment variables template
└── README.md
```

---

## Prerequisites

- **Python 3.10** or higher.
- A **NextDNS account** and API key (found in [NextDNS Account Settings](https://my.nextdns.io/account)).
- A **Telegram Bot Token** (from [@BotFather](https://t.me/botfather)) and your Telegram User ID.
- *(Optional)* Free API keys from [URLhaus](https://urlhaus.abuse.ch/api/) and [urlscan.io](https://urlscan.io/user/signup) for enhanced threat intelligence.

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/p0lygraph/NextDNS-telegram.git
cd NextDNS-telegram
```

### 2. Install dependencies

The project relies on standard Python libraries plus `requests` and `python-dotenv`:

```bash
pip install requests python-dotenv
```

### 3. Configure environment variables

Copy the sample environment file:

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# NextDNS API Key (from https://my.nextdns.io/account)
NEXTDNS_API_KEY=your_nextdns_api_key_here

# Telegram Bot configuration
TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
TELEGRAM_USER_ID=your_telegram_user_numeric_id

# Optional Threat Intelligence APIs
URLHAUS_API_KEY=your_urlhaus_key_here
URLSCAN_API_KEY=your_urlscan_key_here
```

---

## Usage

### Running the Desktop GUI

Launch the desktop interface for interactive management:

```bash
python nextdns_manager_gui.py
```

#### GUI Capabilities:
- **Logs**: View and search live DNS query streams across profiles and devices.
- **Denylist**: Search, add, remove, and bulk-import domain rules.
- **TLDs**: Toggle blocking for risky or unwanted top-level domains.
- **Alerts**: Enable/disable automated query polling and configure Telegram alert thresholds.
- **APIs**: Test connectivity to NextDNS and threat intelligence providers in real time.

---

### Running in Headless Mode (Daemon / Server)

For background monitoring on a server, VPS, or Raspberry Pi:

```bash
python nextdns_manager_gui.py --headless
```

In headless mode:
- No GUI or display server (`DISPLAY` / `X11`) is required.
- The daemon continuously polls NextDNS logs for blocked or suspicious queries.
- Sends actionable alerts directly to your Telegram chat.
- Processes Telegram inline buttons and commands asynchronously.

---

## Telegram Bot Interface

Once running, interact with your bot in Telegram using the built-in commands or interactive menu:

| Command | Description |
|---|---|
| `/start` | Open the main interactive navigation menu |
| `/status` | View monitoring status, active profiles, and statistics |
| `/logs` | Select a profile and view recent DNS query logs |
| `/deny <domain>` | Quickly add a domain to a profile's denylist |
| `/tld <tld>` | Quickly block a specific Top-Level Domain (e.g. `com`, `org`, `net`) |
| `/list` | View currently ignored alert rules |

### Actionable Alert Notifications
When a blocked query occurs, the bot delivers an alert with instant inline actions:
- 🟢 **Allow**: Add the domain to the profile allowlist.
- 🔴 **Deny**: Permanently add the domain to the profile denylist.
- ⚪ **Ignore**: Suppress future alerts for this specific domain pattern.
- 🔍 **Enrichment**: Inspect results from URLhaus and urlscan.io without leaving the chat.

---

## Security & Privacy

- **Credential Isolation**: Secrets are kept in your local `.env` and `gui_state.json`, which are excluded from version control via `.gitignore`.
- **Token Redaction**: Telegram tokens and sensitive URLs are automatically redacted in error logs and console outputs.
- **Access Control**: The bot only responds to messages from the authorized `TELEGRAM_USER_ID` configured in your settings.

---

## License

This project is licensed under the MIT License — feel free to use, modify, and distribute.
