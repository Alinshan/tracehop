# 🛡️ Tracehop Advanced Usage Guide

Tracehop v1.1 supports professional-grade configuration for custom secret detection, stealth scanning, and deep technical intelligence.

## 🔍 Phase 0: Technical Intelligence (Advanced Reconnaissance)
Tracehop now performs a comprehensive "Deep Recon" before starting the JS scan. This includes:
-   **DNS Records**: A, MX, NS, and TXT resolution.
-   **SSL Certificate**: Expiry, Issuer, and SAN inspection.
-   **WHOIS**: Domain registration age and ownership.
-   **Geo-Location**: Mapping targets to their physical infrastructure and ISP.
-   **Port Scanning**: Checking top 20 most common service ports.

## 📝 Custom Rules (YAML)
You can inject your own proprietary regex signatures without modifying the core engine. This is ideal for internal tokens or platform-specific secrets.

### 1. Create a `custom_rules.yml`
Tracehop supports two formats for custom rules:
-   **Simple Dict**: `Rule Name: "REGEX"`
-   **Structured List**: (Tracehop/Nuclei format)

```yaml
# Simple Dict
My-Internal-Token: "MY-TOKEN-[0-9]{8}"

# Structured List
- name: "S3-Bucket"
  regex: "[a-z0-9.-]+\.s3\.amazonaws\.com"
```

### 2. Execute with Rules
**CLI Mode:**
```bash
python tracehop.py dev.example.com --rules custom_rules.yml
```
**GUI Mode:**
- Use the **"Custom Rules (YAML)"** browse button in the sidebar to select your file.

---

## 🕵️ User-Agent Rotation (WAF Evasion)
To avoid being fingerprinted or blocked by Web Application Firewalls (WAFs), Tracehop can rotate its identity for every single request.

### 1. Create a `user_agents.txt`
Simply list one full User-Agent string per line.

```text
Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...
```

### 2. Execute with Rotation
**CLI Mode:**
```bash
python tracehop.py dev.example.com --user-agents user_agents.txt
```
**GUI Mode:**
- Use the **"User-Agents (TXT)"** browse button in the sidebar to select your list.

---

## 🚀 Pro Tip: Combined Stealth Mode
For a professional recon session, combine both features with subdomains:
```bash
python tracehop.py example.com --subdomains --rules custom_rules.yml --user-agents user_agents.txt
```

> [!TIP]
> Use the **Engine Logs** tab in the GUI to see real-time rotation and rule matching in action!
