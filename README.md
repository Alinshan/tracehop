# Tracehop: Premium JS Recon & Secret Scanner

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![AsyncIO](https://img.shields.io/badge/execution-async-brightgreen)
![Rich UI](https://img.shields.io/badge/ui-rich-magenta)

**Tracehop** is a high-performance JavaScript reconnaissance engine designed for security researchers and bug hunters. It automates the process of discovery and secret extraction from web applications by concurrently scanning script files and inline code for hardcoded credentials, API keys, and sensitive tokens.

---

## ✨ Features

- 🚀 **Asynchronous Scanner**: Powered by `httpx` and `asyncio` for blindingly fast concurrent request handling.
- 💎 **Premium Console UI**: A high-fidelity interface using the `rich` library, featuring real-time spinners, color-coded tables, and clean status updates.
- 🕵️ **Deep Intelligence**:
    - Scans both external JS files (`<script src="...">`) and inline scripts.
    - Automatically handles URL joining and de-duplication.
    - Intelligent JS beautification for minified files to improve detection accuracy.
- 🔍 **Comprehensive Ruleset**: Robust regex patterns for detecting:
    - **Cloud Providers**: AWS, Google Cloud, Firebase.
    - **Payment Gateways**: Stripe (Live/Test).
    - **Communication**: Slack, Twilio, Mailchimp.
    - **Platforms**: GitHub Tokens, Heroku API Keys.
    - **Generic Secrets**: Identifies standard `api_key` and `auth_token` patterns.
- 📊 **Automatic Reporting**: Generates timestamped JSON reports after every scan for easy auditing and integration.

---

## 🏗️ Architecture

Tracehop is built with a modular asynchronous architecture that maximizes efficiency:

1. **Orchestrator (`tracehop.py`)**: Manages CLI arguments, UI rendering, and the main event loop.
2. **Scanning Engine (`scanner/engine.py`)**:
   - **Phase 1: Discovery**: Fetches the landing page and extracts all script sources.
   - **Phase 2: Extraction**: Isolates inline JS content and resolves remote absolute URLs.
   - **Phase 3: High-Concurrency Scan**: Uses a Semaphore-controlled async pool to fetch and scan dozens of JS files in parallel.
3. **Detection Core**: Executes a pre-compiled dictionary of regex rules (`scanner/rules.py`) against beautified JS content.
4. **Reporter**: Aggregates findings and performs automatic JSON serialization.

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/tracehop.git
cd tracehop

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic Scan
Perform a deep scan on a target domain:
```bash
python tracehop.py https://example.com
```

### Advanced Options
- **Specify Output**: Save results to a custom file.
  ```bash
  python tracehop.py https://example.com -o myscan.json
  ```
- **Silent Mode**: Suppress the banner and table for use in scripts.
  ```bash
  python tracehop.py https://example.com -s
  ```

---

## 🔒 Secrets Detected (Ruleset)

Tracehop currently includes signatures for:
*   AWS Access Keys & Secret Keys
*   Google API & Firebase Keys
*   Stripe Live & Test Secret Keys
*   Slack Webhook URLs
*   Twilio Account SIDs & Auth Tokens
*   Heroku & Mailchimp API Keys
*   GitHub Personal Access Tokens
*   Generic Sensitive Keys (`password`, `secret`, `access_token`, etc.)

---

## ⚖️ Disclaimer

Tracehop is intended for **legal security research and authorized testing only**. Usage against targets without prior written consent is illegal and the author is not responsible for any misuse.

---

#### Developed by Alinshan © 2026
