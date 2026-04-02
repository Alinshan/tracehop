import re
import math
import yaml
import os

# ─────────────────────────────────────────────
#  ADVANCED SECRET DETECTION RULESET v3.0
#  100+ signatures across all major platforms
# ─────────────────────────────────────────────

RULES = {
    # ── AWS ──────────────────────────────────
    "AWS Access Key ID":            r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
    "AWS Secret Access Key":        r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
    "AWS MWS Auth Token":           r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS Session Token":            r"FQoGZXIvYXdzE[a-zA-Z0-9\/+]{100,}",

    # ── Google / GCP ─────────────────────────
    "Google API Key":               r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Client ID":       r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com",
    "Google OAuth Client Secret":   r"GOCSPX-[a-zA-Z0-9\-_]{28}",
    "Google Private Key":           r"\"private_key\":\s*\"-----BEGIN PRIVATE KEY-----",
    "Google Service Account":       r"\"type\":\s*\"service_account\"",
    "Firebase API Key":             r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":                 r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase Database Rule":       r"\"\.read\":\s*\"?true\"?",

    # ── Azure ────────────────────────────────
    # Require "AccountKey=" prefix so we don't match random base64 strings (e.g. PNG images)
    "Azure Storage Account Key":    r"AccountKey=[a-zA-Z0-9\/+]{86}==",
    "Azure Connection String":      r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9\/+=]{86,88}",
    "Azure SAS Token":              r"sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&s[a-z]=&[a-z]+=[a-zA-Z0-9%]+",
    "Azure Client Secret":          r"(?i)(client.?secret|clientsecret)(.{0,20})?['\"][a-zA-Z0-9~._\-]{30,50}['\"]",

    # ── GitHub ───────────────────────────────
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub Fine-Grained Token":   r"github_pat_[a-zA-Z0-9_]{82}",
    "GitHub OAuth Access Token":    r"gho_[a-zA-Z0-9]{36}",
    "GitHub App Token":             r"ghs_[a-zA-Z0-9]{36}",
    "GitHub Refresh Token":         r"ghr_[a-zA-Z0-9]{36}",
    "GitHub Actions Token":         r"GITHUB_TOKEN\s*=\s*['\"][a-zA-Z0-9_]{4,}['\"]",

    # ── GitLab ───────────────────────────────
    "GitLab Personal Access Token": r"glpat-[0-9a-zA-Z\-]{20}",
    "GitLab Runner Token":          r"GR1348941[0-9a-zA-Z\-_]{20}",

    # ── Stripe ───────────────────────────────
    "Stripe Live Secret Key":       r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Restricted Key":        r"rk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Secret Key":       r"sk_test_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key":       r"pk_live_[0-9a-zA-Z]{24,}",
    "Stripe Webhook Secret":        r"whsec_[0-9a-zA-Z]{32,}",

    # ── Slack ────────────────────────────────
    "Slack Webhook":                r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Slack User Token":             r"xoxp-[0-9]{10,12}-[0-9]{10,12}-[0-9]{10,12}-[a-f0-9]{32}",
    "Slack Bot Token":              r"xoxb-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}",
    "Slack App-Level Token":        r"xapp-[0-9]-[A-Z0-9]{10}-[0-9]+-[a-f0-9]{64}",

    # ── Twilio ───────────────────────────────
    "Twilio Account SID":           r"AC[a-f0-9]{32}",
    "Twilio Auth Token":            r"(?i)twilio(.{0,20})?['\"][a-f0-9]{32}['\"]",

    # ── SendGrid / Mailchimp / Mailgun ───────
    "SendGrid API Key":             r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}",
    "Mailchimp API Key":            r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key":              r"key-[0-9a-zA-Z]{32}",
    "NPM Access Token":             r"npm_[0-9a-f]{36}",
    "Postmark Server Token":        r"(?i)postmark(.{0,20})?['\"][a-zA-Z0-9\-]{36}['\"]",
    "SparkPost API Key":            r"(?i)sparkpost(.{0,20})?['\"][a-zA-Z0-9]{48}['\"]",

    # ── Payments ─────────────────────────────
    "Square Access Token":          r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret":          r"sq0csp-[0-9A-Za-z\-_]{44}",
    "PayPal Braintree Key":         r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Shopify Access Token":         r"shpat_[a-fA-F0-9]{32}",
    "Shopify Shared Secret":        r"shpss_[a-fA-F0-9]{32}",
    "Shopify Custom App Key":       r"shpca_[a-fA-F0-9]{32}",
    "Adyen API Key":                r"AQE[a-zA-Z0-9\/+]{36,}==",

    # ── Social / Comms ───────────────────────
    "Telegram Bot Token":           r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
    "Discord Bot Token":            r"[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]{27}",
    "Discord Webhook":              r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+",
    "Twitter Bearer Token":         r"AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]{37}",
    "Twitter API Key":              r"(?i)twitter(.{0,20})?['\"][0-9a-zA-Z]{35,44}['\"]",
    "LinkedIn Client ID":           r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{14}['\"]",
    "Facebook Access Token":        r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook App Secret":          r"(?i)facebook(.{0,20})?['\"][0-9a-f]{32}['\"]",
    "Instagram Access Token":       r"IGQVJ[a-zA-Z0-9\-_=]{80,}",

    # ── Monitoring & DevOps ──────────────────
    "Datadog API Key":              r"(?i)datadog(.{0,20})?['\"][a-f0-9]{32}['\"]",
    "Datadog App Key":              r"(?i)datadog(.{0,20})?['\"][a-f0-9]{40}['\"]",
    "New Relic License Key":        r"NRAK-[A-Z0-9]{27}",
    "New Relic API Key":            r"NRAA-[a-z0-9]{52}",
    "Sentry DSN":                   r"https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+",
    "Dynatrace Access Token":       r"dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}",
    "Splunk Auth Token":            r"(?i)splunk(.{0,20})?['\"][a-zA-Z0-9\-]{40,100}['\"]",
    "PagerDuty Integration Key":    r"(?i)pagerduty(.{0,20})?['\"][a-z0-9+]{32}['\"]",

    # ── Database / Cloud ─────────────────────
    "MongoDB Connection String":    r"mongodb(\+srv)?://[^:\"'\s]+:[^@\"'\s]+@[^\"'\s]+",
    "PostgreSQL Connection String": r"postgres(?:ql)?://[^:\"'\s]+:[^@\"'\s]+@[^\"'\s]+",
    "MySQL Connection String":      r"mysql://[^:\"'\s]+:[^@\"'\s]+@[^\"'\s]+",
    "Redis URL":                    r"redis://:[^\@\"'\s]+@[^\"'\s]+",
    "ElasticSearch Credentials":    r"https://[^:]+:[^@]+@[a-z0-9-]+\.es\.io",
    "Supabase Service Key":         r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "PlanetScale Token":            r"pscale_tkn_[a-zA-Z0-9_\-]{43}",

    # ── Infrastructure ───────────────────────
    "Heroku API Key":               r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "DigitalOcean Token":           r"dop_v1_[a-f0-9]{64}",
    # Must be exactly 18 chars after "DO" and NOT followed by more letters (to avoid matching DOM, DOCTYPE, etc.)
    "DigitalOcean Spaces Key":      r"\bDO[A-Z0-9]{16}\b",
    "Cloudflare API Key":           r"(?i)cloudflare(.{0,20})?['\"][a-f0-9]{37}['\"]",
    "Cloudflare Global API Key":    r"\b[a-f0-9]{37}\b",
    "Netlify Access Token":         r"(?i)netlify(.{0,20})?['\"][a-zA-Z0-9\-_]{40,50}['\"]",
    "Vercel Token":                 r"(?i)vercel(.{0,20})?['\"][a-zA-Z0-9]{24}['\"]",
    "Terraform Cloud Token":        r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{60,}",

    # ── Auth / SSO ───────────────────────────
    "JWT Token":                    r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "Auth0 Client Secret":          r"(?i)auth0(.{0,20})?['\"][a-zA-Z0-9_\-]{40,60}['\"]",
    "Okta API Token":               r"00[a-zA-Z0-9\-_]{40}",
    "Firebase Auth Token":          r"(?:ya29\.[a-zA-Z0-9\-_]+)",

    # ── Crypto / Keys ────────────────────────
    "RSA Private Key":              r"-----BEGIN RSA PRIVATE KEY-----",
    "DSA Private Key":              r"-----BEGIN DSA PRIVATE KEY-----",
    "OpenSSH Private Key":          r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key Block":        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "EC Private Key":               r"-----BEGIN EC PRIVATE KEY-----",
    "PKCS8 Private Key":            r"-----BEGIN PRIVATE KEY-----",

    # ── Analytics & Marketing ────────────────
    "Mixpanel Token":               r"(?i)mixpanel(.{0,20})?['\"][a-f0-9]{32}['\"]",
    "Amplitude API Key":            r"(?i)amplitude(.{0,20})?['\"][a-f0-9]{32}['\"]",
    "Segment Write Key":            r"(?i)segment(.{0,20})?['\"][a-zA-Z0-9]{40}['\"]",
    "HubSpot API Key":              r"(?i)hubspot(.{0,20})?['\"][a-f0-9\-]{36}['\"]",
    "Salesforce OAuth Token":       r"00D[a-zA-Z0-9]{15}![a-zA-Z0-9_.]{60,}",
    "Intercom API Token":           r"(?i)intercom(.{0,20})?['\"][a-zA-Z0-9_]{52}['\"]",

    # ── CI/CD ────────────────────────────────
    "CircleCI Personal Token":      r"(?i)circleci(.{0,20})?['\"][a-f0-9]{40}['\"]",
    "Travis CI Token":              r"(?i)travis(.{0,20})?['\"][a-zA-Z0-9\-_]{22}['\"]",
    "Jenkins API Token":            r"(?i)jenkins(.{0,20})?['\"][a-zA-Z0-9]{34}['\"]",

    # ── Misc ─────────────────────────────────
    "Figma Access Token":           r"figd_[a-zA-Z0-9]{20,40}",
    "Cloudinary URL":               r"cloudinary://[0-9]{15}:[0-9a-zA-Z_-]{27}@[a-z0-9]+",
    "Algolia API Key":              r"(?i)algolia(.{0,20})?['\"][a-f0-9]{32}['\"]",
    "Mapbox Access Token":          r"pk\.eyJ1IjoiWa-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Ipstack API Key":              r"(?i)ipstack(.{0,20})?['\"][a-f0-9]{32}['\"]",
    "OpenAI API Key":               r"sk-[a-zA-Z0-9]{48}",
    "Anthropic API Key":            r"sk-ant-[a-zA-Z0-9\-_]{93,}",
    "Cohere API Key":               r"(?i)cohere(.{0,20})?['\"][a-zA-Z0-9]{40}['\"]",
    "Hugging Face Token":           r"hf_[a-zA-Z0-9]{37}",
    "Pinecone API Key":             r"(?i)pinecone(.{0,20})?['\"][a-f0-9\-]{36}['\"]",

    # ── Generic High-Entropy Heuristics ──────
    "Generic API Key":              r"(?i)(api[_\-]?key|apikey|api[_\-]?token|access[_\-]?key)(\s*[=:]\s*|\s*['\"]?\s*:\s*['\"]?)(['\"]?)([a-zA-Z0-9\/+_\-]{32,128})\3",
    "Generic Secret":               r"(?i)(secret|client[_\-]?secret|app[_\-]?secret|auth[_\-]?secret)(\s*[=:]\s*|\s*['\"]?\s*:\s*['\"]?)(['\"]?)([a-zA-Z0-9\/+_\-]{20,128})\3",
    "Generic Password":             r"(?i)(password|passwd|pwd|pass)(\s*[=:]\s*|\s*['\"]?\s*:\s*['\"]?)(['\"]?)([a-zA-Z0-9!@#$%^&*()_+\-=]{8,64})\3",
    "Private Token Assignment":     r"(?i)(private[_\-]?token|priv[_\-]?key|encryption[_\-]?key)(\s*[=:]\s*|\s*['\"]?\s*:\s*['\"]?)(['\"]?)([a-zA-Z0-9\/+_\-]{20,128})\3",
    "Bearer Token":                 r"(?i)bearer\s+[a-zA-Z0-9\-_=.]{20,}",
    "Basic Auth (Base64)":          r"Basic\s+[a-zA-Z0-9+\/=]{20,}",

    # ── Advanced Pentesting ──────────────────
    # LinkFinder regex to extract API paths, routes, and URLs from JS files
    "API Endpoint":                 r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')"""
}


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to filter low-entropy false positives."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((f / len(data)) * math.log2(f / len(data)) for f in freq.values())
    return entropy


# Patterns that are known dummy/placeholder values — skip them
DUMMY_PATTERNS = [
    r"^(0123456789|abcdefghij|aaaaaaaaaa|xxxxxxxxxx|1234567890|test|demo|example|placeholder|your.key.here|insert.key|changeme|xxx+|sample).*",
    r"^[a-z]{32}$",   # pure sequential lowercase (like "abcdefghijklmnopqrstuvwxyzabcdef")
]

# Quick check against embedded image/binary data URIs
DATA_URI_SKIP_RE = re.compile(r"^data:image/[a-z]+;base64,", re.IGNORECASE)
_DUMMY_RE = [re.compile(p, re.IGNORECASE) for p in DUMMY_PATTERNS]


def is_likely_dummy(value: str) -> bool:
    """Return True if the matched value looks like a placeholder."""
    # Never report embedded images as secrets
    if DATA_URI_SKIP_RE.match(value.strip()):
        return True

    for pattern in _DUMMY_RE:
        if pattern.match(value.strip()):
            return True
    
    # Also check: very low entropy = likely sequential/dummy
    if len(value) >= 16 and shannon_entropy(value) < 2.5:
        return True
    return False


def get_compiled_rules(custom_rules_path=None):
    """Compile built-in rules and merge with optional YAML rules file."""
    base_rules = RULES.copy()
    
    if custom_rules_path and os.path.exists(custom_rules_path):
        try:
            with open(custom_rules_path, "r") as f:
                external = yaml.safe_load(f)
                if isinstance(external, list):
                    # Format: [{"id": "name", "regex": "..."}] (Tracehop format)
                    for r in external:
                        name = r.get("name") or r.get("id")
                        regex = r.get("regex")
                        if name and regex:
                            base_rules[name] = regex
                elif isinstance(external, dict):
                    # Format: {"rule_name": "regex"}
                    base_rules.update(external)
        except Exception:
            pass

    compiled = {}
    for name, pattern in base_rules.items():
        try:
            # Strip anchors for global matching if loading from YAML
            p = pattern.strip()
            compiled[name] = re.compile(p)
        except re.error:
            pass
    return compiled
