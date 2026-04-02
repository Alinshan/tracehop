<div align="center">

# Tracēhop 🚀
**Premium JS Reconnaissance & Pentest Orchestrator — v3.0 (Elite)**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/downloads/)
[![AsyncIO Powered](https://img.shields.io/badge/execution-AsyncIO-brightgreen.svg?style=for-the-badge)](https://docs.python.org/3/library/asyncio.html)
[![Terminal UI](https://img.shields.io/badge/UI-Rich-magenta.svg?style=for-the-badge)](https://github.com/Textualize/rich)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)]()

*For security researchers, bug bounty hunters, and penetrations testers.*

---

</div>

<br>

**Tracehop** is an asynchronous, high-performance web reconnaissance and pentesting tool. It completely automates the extraction and deep-scanning of JavaScript files and inline scripts across modern web applications to identify exposed secrets, hardcoded credentials, and critical API integrations.

With the release of **v3.0 (Elite)**, Tracehop now features a **Professional Desktop GUI**, automated **Pentest Orchestration** (IDOR/Source Maps), and an extensible **YAML-based rule engine**.

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
<summary><b>🖥️ Pro Desktop GUI (New in v3.0)</b></summary>
<br>
A full PySide6-based graphical interface for researchers who prefer a dashboard. Monitor scans in real-time, filter findings by severity, and browse logs with ease.
</details>

<details open>
<summary><b>📦 Extensible YAML Rules & UA Rotation</b></summary>
<br>
Inject your own custom scanning signatures via YAML files and evade WAFs by providing a list of User-Agents for randomized request headers.
</details>

<details open>
<summary><b>🛡️ Automated Pentest Orchestration</b></summary>
<br>
A four-phase workflow that hunts for more than just secrets: IDOR probing on API endpoints, source map disclosure verification, and 1-click integration with Nuclei/Ffuf.
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

Tracehop is designed to be plug-and-play and features both an interactive UI and command-line arguments.

#### 1. Professional Desktop GUI (New)
Launch the standalone dashboard for a visual experience:
```bash
python tracehop.py --gui
```

#### 2. Advanced: Pentest Suite (Automated Orchestration)
Run the automated vulnerability verification engine:
```bash
# Setup tools on Windows (Nuclei, Ffuf, etc)
./setup_env.ps1

# Launch the automated attack
python tracehop.py example.com --pentest
```

#### 3. Custom Rule Injection (YAML)
Provide your own signatures in a Yumi-compatible format:
```bash
python tracehop.py example.com --rules my_custom_rules.yml
```

#### 4. Stealth Mode (User-Agent Rotation)
Pass a text file of User-Agents to randomize each request:
```bash
python tracehop.py filter.com --user-agents uas.txt
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
<b>©Alinshan</b>
</div>
