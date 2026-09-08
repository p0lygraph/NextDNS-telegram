# NextDNS Telegram & Desktop Manager

[![CodeQL](https://img.shields.io/badge/CodeQL-passing-brightgreen?logo=github)](https://github.com/p0lygraph/NextDNS-telegram/security/code-scanning)
[![Security: Protected](https://img.shields.io/badge/Security-Protected-brightgreen.svg?logo=github)](https://github.com/p0lygraph/NextDNS-telegram/security)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-025e8c.svg?logo=dependabot&logoColor=white)](https://github.com/p0lygraph/NextDNS-telegram/security/dependabot)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A powerful dual-mode application (Desktop GUI + Headless daemon) to monitor, manage, and automate [NextDNS](https://nextdns.io/) profiles. Features an interactive Telegram Bot with actionable inline alerts and automated threat intelligence enrichment via URLhaus and urlscan.io.

<p align="center">
  <img src="https://github.com/user-attachments/assets/60c5a8ce-9886-4250-b2c8-2aedc5e93ffe" alt="NextDNS Manager GUI Logs" width="850">
</p>

---

## Highlights

- 🖥️ **Desktop GUI (Tkinter)**: Full-featured desktop control center with tabs for Live Logs, Denylists, TLD blocking, Alert tuning, and API settings.
- 🤖 **Interactive Telegram Bot**: Receive instant notifications on blocked queries, inspect logs, and manage denylists / TLDs directly from Telegram.
- ⚡ **Instant Lookups & Noise Suppression**: Direct one-click links to live URLhaus and urlscan.io reports, plus an instant Ignore button for repetitive alerts.
- 🛡️ **Threat Intelligence Enrichment**: Automatic domain lookups through [URLhaus](https://urlhaus.abuse.ch/) and [urlscan.io](https://urlscan.io/) for enriched security context.
- 🚀 **Headless Server Mode**: Run as a lightweight background service on a VPS, Raspberry Pi, or home server without GUI dependencies.
- 🔒 **Zero Middleman**: Direct communication exclusively with official APIs; your credentials and queries never touch third-party servers.

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
- A **Telegram Bot Token** (from [@BotFather](https://t.me/botfather)) and your numeric **Telegram User ID** (obtain it by sending `/start` to [@userinfobot](https://t.me/userinfobot)).
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

*(Linux users: if running the desktop GUI on Ubuntu/Debian, also ensure `sudo apt install python3-tk` is installed).*

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

## Modes of Operation

### 1. Running the Desktop GUI

Launch the desktop interface for interactive management:

```bash
python nextdns_manager_gui.py
```

### GUI Capabilities

Click any section below to expand detailed features:

<details>
<summary><strong>Logs</strong>: View and search live DNS query streams across profiles and devices.</summary>

- **Live Query Stream**: Continuously loads and displays incoming DNS queries from NextDNS with timestamps, requesting device, domain, root domain, status, and block reasons.
- **Advanced Filtering**: Filter records on the fly by status (**Blocked only**, **Malicious only**, **Unusual TLD only**), or suppress specific block reasons.
- **Multi-Profile & Multi-Device Selector**: Inspect logs from a single profile/device or aggregate streams across multiple configured profiles simultaneously.
- **Search & Debounce**: Rapidly search through logs by domain name, root domain, or client device IP/hostname with built-in query debouncing.
- **Interactive Context Menu**: Right-click any log row to instantly:
  - Copy domain name or raw query payload.
  - Add domain directly to the **Denylist** (block).
  - Add domain to the **Allowlist** (bypass).
  - Run on-demand **Threat Intelligence** lookups (URLhaus & urlscan.io).
  - Add to **Alert Ignore List** to suppress repetitive notifications.
- **Auto-Refresh**: Toggle automatic background refreshing at configurable intervals.

</details>

<details>
<summary><strong>Denylist</strong>: Manage blocked domains, single additions, and bulk operations.</summary>

- **Domain Table**: View all active denylist entries across profiles with domain search, sorting, and source tagging.
- **Single Domain Addition**: Add individual domains via a prompt dialog with automatic normalization and syntax validation.
- **Bulk Import**: Import extensive domain lists from `.txt` files in seconds with automatic syntax validation, deduplication, and profile selection. *(See [Bulk Import Format](#bulk-import-format) below).*
- **Export Capabilities**: Export active denylists to CSV or TXT format for backups or external firewall rules.
- **Right-Click Context Actions**: Block domain, unblock domain, or copy domain directly from the table.

</details>

<details>
<summary><strong>TLDs</strong>: Restrict and manage blocked Top-Level Domains per profile.</summary>

- **TLD Inspector**: View and audit blocked TLDs (e.g. `zip`, `top`, `ru`, `cn`) across selected profiles.
- **Quick Toggle & Search**: Search through TLD rules and toggle restrictions per profile.
- **Bulk TLD Import & Export**: Import curated TLD lists from `.txt` files or export active rules to CSV.
- **Context Actions**: Quickly block, unblock, or copy selected TLDs.

</details>

<details>
<summary><strong>Alerts</strong>: Configure real-time background monitoring, Telegram alerts, and suppression rules.</summary>

- **Telegram Delivery Control**: Enable or pause automated Telegram notifications for blocked queries.
- **Reason Overrides**: Fine-tune alert triggers based on specific NextDNS block reasons (e.g., Security Blocklists, Parental Control, CNAME Cloaking, Afraid).
- **Ignore Patterns**: Define wildcard rules (e.g. `*.apple.com`, `telemetry.*`) or exact domains to suppress repetitive, benign alerts without disabling overall security monitoring.
- **Threat Intelligence Auto-Enrichment**: Automatically cross-reference newly blocked domains against URLhaus and urlscan.io, appending threat tags and scan links to Telegram alerts.

</details>

<details>
<summary><strong>APIs</strong>: Centralized credential manager and live connection testing.</summary>

- **Credential Management**: Safely view, update, and persist API keys for **NextDNS**, **Telegram Bot**, **URLhaus**, and **urlscan.io**.
- **Live Connectivity Testing**:
  - Test NextDNS API token validity and retrieve account profile counts.
  - Send a test message to your Telegram chat to verify bot tokens and Chat IDs.
  - Check connectivity and quota for URLhaus and urlscan.io APIs.
- **Local Persistence**: State and preferences are saved locally in straightforward JSON configuration files.

</details>

<details>
<summary><strong>Settings</strong>: General preferences, themes, and console behavior.</summary>

- **Appearance**: Built-in ttk styling and automatic window geometry restoration across restarts.
- **Polling Intervals**: Tune background query polling frequency to optimize between latency and NextDNS API rate limits.
- **Console Diagnostics**: Windows GUI console error trapping and debug logging for headless and GUI operations.

</details>

---

### 2. Running in Headless Mode (Daemon / Server)

For background monitoring on a server, VPS, home router, or Raspberry Pi without GUI dependencies:

```bash
python nextdns_manager_gui.py --headless
```

In headless mode:
- No GUI or display server (`DISPLAY` / `X11`) is required.
- Continuously polls NextDNS logs for blocked or suspicious queries.
- Sends actionable alerts directly to your Telegram chat.
- Processes Telegram inline buttons and commands asynchronously.

<details>
<summary><strong>Autostart with systemd (Linux / Raspberry Pi)</strong>: Keep the daemon running 24/7 as a background service.</summary>

1. Create a service file:
   ```bash
   sudo nano /etc/systemd/system/nextdns-manager.service
   ```

2. Add the following unit configuration (update the paths and user to match your system):
   ```ini
   [Unit]
   Description=NextDNS Telegram Manager Daemon
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=your_username
   WorkingDirectory=/path/to/NextDNS-telegram
   ExecStart=/usr/bin/python3 nextdns_manager_gui.py --headless
   Restart=always
   RestartSec=10
   EnvironmentFile=/path/to/NextDNS-telegram/.env

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now nextdns-manager.service
   ```

4. View service status and live logs:
   ```bash
   sudo systemctl status nextdns-manager.service
   journalctl -u nextdns-manager.service -f
   ```

</details>

---

## Bulk Import Format

The application supports bulk importing domains into the **Denylist** and TLDs into the **TLDs** tab via plain text files (`.txt`).

### File Specifications:
- **File Type**: Plain text file (`.txt`), UTF-8 encoded.
- **One Entry Per Line**: Each line must contain exactly one domain (or TLD).
- **Comments Supported**: Lines beginning with `#` or `;` are treated as comments and ignored.
- **Blank Lines Ignored**: Empty lines and whitespace-only lines are automatically skipped.
- **Auto-Sanitization**: Domains are automatically converted to lowercase, stripped of protocols (`http://`, `https://`), paths, and trailing dots.
- **Deduplication**: Duplicate entries within the file are automatically filtered out.

### Example `denylist.txt`:
```text
# --- Threat intelligence feed: Phishing & C2 ---
malicious-site.example.com
evil-tracker.org
c2-traffic-beacon.net

; Secondary campaign blocks
phishing-login-portal.info
payload-distribution.xyz
```

### Example `tlds.txt`:
```text
# Block high-risk Top-Level Domains
zip
top
mov
country
kim
```

### Smart Import Workflow:
1. Click **Bulk import** in either the **Denylist** or **TLDs** tab.
2. Select your `.txt` file from the file dialog.
3. A **Profile Picker Dialog** will appear, allowing you to choose whether to apply the import to one specific profile, multiple profiles, or all profiles simultaneously.
4. The importer checks each profile's current configuration and **automatically skips domains already present**, avoiding duplicate API requests and unnecessary NextDNS rate limit consumption.

---

## Telegram Bot Interface

Once running (in GUI mode with alerts enabled or in `--headless` mode), interact with your bot in Telegram.

<p align="center">
  <img src="https://github.com/user-attachments/assets/5cd4f308-28fb-41e9-8f21-cce4ef475b63" alt="Telegram Alert Notification" width="400">
  &nbsp;&nbsp;&nbsp;&nbsp;
  <img src="https://github.com/user-attachments/assets/561bf8f4-13a3-4f3d-bbf5-662bce391348" alt="Telegram Interactive Menu" width="380">
</p>

### Full Command Reference

| Command | Arguments | Description |
|---|---|---|
| `/start` | None | Open the main interactive navigation menu with inline buttons. |
| `/help` | None | Display help message and return to the main navigation menu. |
| `/menu` | None | Open the root interactive navigation menu. |
| `/status` | None | Show monitoring daemon status, active profile count, and poller statistics. |
| `/profiles` | None | List all NextDNS profiles, view profile IDs, and toggle active monitoring per profile. |
| `/filters` | None | Open profile picker to view and manage active NextDNS security blocklists and filters. |
| `/list` | None | View all active alert ignore patterns (rules that suppress notifications). |
| `/ignorelist` | None | Alias for `/list`. |
| `/ignore` | `[pattern]` | Without arguments: view active ignore patterns. With argument (e.g. `/ignore domain.com` or `/ignore *.domain.com`): prompts to add the pattern to a profile's ignore list. |
| `/denylist` | `[domain]` | Without arguments: pick a profile to view/manage its blocked domains. With argument (e.g. `/denylist evil.com`): prompts to add the domain to a profile's denylist. |
| `/tlds` | `[tld]` | Without arguments: pick a profile to view/manage blocked TLDs. With argument (e.g. `/tlds zip`): prompts to block or unblock the TLD on a selected profile. |
| `/logs` | None | Select a profile and browse the most recent DNS query logs directly in chat with pagination. |

### Actionable Alert Notifications
When NextDNS blocks a query, the bot immediately delivers an alert containing:
- **Query details**: Timestamp, profile name, domain, root domain, and client device name/IP.
- **Block Reason**: Why NextDNS blocked the request (e.g. specific blocklist name, parental control).
- **Threat Intel**: Automated enrichment summaries from URLhaus and urlscan.io if configured.

#### Inline Action Buttons:
Each alert notification message includes interactive buttons directly underneath:
- 🔍 **URLHaus**: Instant direct link to the domain's live threat report on abuse.ch URLhaus.
- 🔎 **URLScan**: Instant link to full sandbox scan results, HTTP requests, and visual page data on urlscan.io.
- 🚫 **Ignore**: Immediately adds the domain to your profile's alert ignore list with one click, suppressing future notifications for this pattern without affecting NextDNS blocking.

---

## Security & Privacy

- **No Middleman (Zero Telemetry)**: All network requests travel strictly and directly between your machine and official upstream APIs (`api.nextdns.io`, `api.telegram.org`, `urlhaus-api.abuse.ch`, and `urlscan.io`). No third-party servers, tracking, or proxy relays are ever used.
- **Strict Bot Access Control**: The bot validates incoming user IDs against your configured `TELEGRAM_USER_ID` on every message and callback. Unauthorized messages from strangers are completely rejected.
- **Token Masking & Redaction**: Bot tokens and API keys are automatically stripped and replaced with `***` in console output, error tracebacks, and log files to prevent accidental leakage when sharing logs.
- **Local Configuration**: Credentials and states are kept strictly on your local disk (`.env` and local state files) and never shared.

---

## Troubleshooting & FAQ

<details>
<summary><strong>Telegram Error 409 Conflict</strong></summary>

> `Telegram getUpdates failed (409). Another bot process or webhook may be active...`

- **Cause**: Two instances of the bot are running simultaneously with the same token (e.g. the desktop GUI is running with Telegram alerts enabled while the `--headless` daemon is also active in background).
- **Solution**: Ensure only one process uses your bot token at any given time. Stop any existing background daemon before launching a second instance.

</details>

<details>
<summary><strong>Missing Tkinter on Linux (ModuleNotFoundError: No module named '_tkinter')</strong></summary>

- **Cause**: Debian/Ubuntu and some other Linux distributions do not include Tkinter in the standard Python package.
- **Solution**: Install it via your package manager:
  ```bash
  sudo apt update && sudo apt install python3-tk
  ```
  *(Note: Tkinter is only needed for the desktop GUI. Headless mode `--headless` runs without any GUI libraries).*

</details>

<details>
<summary><strong>NextDNS API Key vs Profile ID</strong></summary>

- Make sure you enter the account-level API key from [NextDNS Account Settings](https://my.nextdns.io/account) (under Account details), not a profile identifier.
- If NextDNS returns `429 Too Many Requests`, increase the log poll interval in the **Alerts** or **Settings** tab.

</details>

<details>
<summary><strong>Where do I find my numeric Telegram User ID?</strong></summary>

Your numeric User ID is distinct from your `@username`. You can get your numeric ID in 5 seconds by sending `/start` to [@userinfobot](https://t.me/userinfobot) or [@raw_data_bot](https://t.me/raw_data_bot).

</details>

---

## License

This project is licensed under the MIT License — feel free to use, modify, and distribute.
