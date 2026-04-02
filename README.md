<div align="center">

# Tracēhop 🚀
**Premium JS Reconnaissance & Secret Scanning Engine — v2.0 (Pro)**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/downloads/)
[![AsyncIO Powered](https://img.shields.io/badge/execution-AsyncIO-brightgreen.svg?style=for-the-badge)](https://docs.python.org/3/library/asyncio.html)
[![Terminal UI](https://img.shields.io/badge/UI-Rich-magenta.svg?style=for-the-badge)](https://github.com/Textualize/rich)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)]()

*For security researchers, bug bounty hunters, and penetrations testers.*

---

</div>

<br>

**Tracehop** is an asynchronous, high-performance web reconnaissance tool. It completely automates the extraction and deep-scanning of JavaScript files and inline scripts across modern web applications to identify exposed secrets, hardcoded credentials, and critical API integrations.

With the release of **v2.0 (Pro)**, Tracehop now supports lightning-fast **passive subdomain enumeration** and boasts a comprehensive detection engine of **over 50 complex regex signatures**.

<br>

## ✨ Core Features

<details open>
<summary><b>🔥 High-Performance Asynchronous Engine</b></summary>
<br>
Powered by `httpx` and `asyncio`, Tracehop makes blindingly fast concurrent requests, allowing it to scan entire domains and hundreds of scripts in seconds without blocking.
</details>

<details open>
<summary><b>🌐 Subdomain Discovery (New in v2.0)</b></summary>
<br>
Passively query the `crt.sh` Certificate Transparency logs to discover all active subdomains linked to your target, automatically chaining the attack surface directly into the scanner.
</details>

<details open>
<summary><b>🧠 Deep JS Intelligence & Beautification</b></summary>
<br>
Automatically fetches both remote scripts (`<script src="...">`) and inline JavaScript. Utilizing heuristic-based pre-processing, Tracehop detects and natively beautifies minified (uglified) scripts prior to regex matching to guarantee high-fidelity detection and minimum false positives.
</details>

<details open>
<summary><b>💎 Premium Terminal Experience</b></summary>
<br>
Built on top of the `rich` library. Enjoy dynamic spinners, live elapsed time tracking, color-coded findings matrices, and summarized scanning contexts straight in your terminal. No more cluttered CLI outputs.
</details>

<details open>
<summary><b>📊 Automated JSON Telemetry</b></summary>
<br>
Security scans mean nothing without data. Tracehop automatically compiles and ejects structured, timestamped JSON reports detailing the targets, endpoints, signatures triggered, and exact contexts of the findings.
</details>

<br>

## 🔎 The Detection Matrix

Tracehop is bundled with **50+ battle-tested secret signatures**, spanning across numerous platforms:

*   **Cloud Providers:** AWS Access/Secret Keys, Google Cloud Platform (Tokens, OAuth IDs, Service Accounts), Azure Storage Keys, DigitalOcean Tokens.
*   **Infrastructure & DevOps:** GitHub (PAT, OAuth, App, Refresh Tokens), GitLab, Heroku, Datadog APIs.
*   **Comms & Socials:** Slack (Webhooks, User/Bot Tokens), Twitter/X OAuth, Discord Webhooks, Telegram Bots, LinkedIn, Facebook.
*   **Payments & Commerce:** Stripe (Live, Restricted, Test), Square Access & OAuth secrets.
*   **Cryptographics:** JWT Tokens, Base64 API Keys, Private Keys (RSA, OpenSSH, PGP, Google Cloud).
*   **Advanced Heuristics:** Generic fallback detection utilizing assignment entropy (`pwd`, `apikey`, `secret_key`, etc).

<br>

## 🛠️ Setup & Installation

**Prerequisites:** Python 3.8+ required.

```bash
# 1. Clone the repository
git clone https://github.com/Alinshan/tracehop.git
cd tracehop

# 2. Install the required dependencies
pip install -r requirements.txt
```

<br>

## 🚀 Execution & Usage

Tracehop is designed to be plug-and-play.

#### 1. Basic Domain Scan
Perform a deep script scan aggressively against a single domain.
```bash
python tracehop.py example.com
```

#### 2. Advanced: Subdomain Expansion (Pro Feature)
Utilize the `-s` or `--subdomains` flag to discover, resolve, and simultaneously scan all subdomains of a target. Highly recommended for bug bounty hunting.
```bash
python tracehop.py example.com --subdomains
```

#### 3. Output Management
Target specific filenames for your auto-generated JSON reports.
```bash
python tracehop.py hackerone.com --subdomains --output h1_recon_report.json
```

#### 4. Stealth / Minimal Output
Execute headlessly or suppress the rich banner aesthetics.
```bash
python tracehop.py target.com --silent
```

<br>

## 🛡️ Demonstration Output
*(JSON Output Extract)*

```json
{
    "target": "example.com",
    "timestamp": "20260402_150000",
    "subdomains_found": [
        "api.example.com",
        "dev.example.com",
        "example.com"
    ],
    "findings_count": 1,
    "findings": [
        {
            "rule": "Stripe API Key",
            "secret": "sk_live_51Jkh...2H",
            "source": "https://example.com/assets/js/payment-bundle.js",
            "context": "const STRIPE_KEY = 'sk_live_51Jkh..."
        }
    ]
}
```

<br>

## ⚖️ Legal Disclaimer

Tracehop is constructed strictly for **educational purposes, defensive auditing, and authorized security research**. The authors and contributors are absolutely not responsible for any misuse, damage, or illegal activities conducted with this tool. Ensure you have overwhelming legal consent to scan and profile any target prior to utilizing Tracehop.

---

<div align="center">
<b>By Alinshan</b>
</div>
