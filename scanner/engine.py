import asyncio
import httpx
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import jsbeautifier
import random
from .rules import get_compiled_rules, is_likely_dummy

# Regex to extract JS file references from webpack chunks, source maps, etc.
_WEBPACK_CHUNK_RE = re.compile(r'["\']((?:https?://|/)[^"\']+\.js)["\']')
_SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL=(.+\.map)')


class TracehopEngine:
    def __init__(self, target_url, semaphore_limit=30, custom_rules_path=None, user_agents=None):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc or target_url
        self.compiled_rules = get_compiled_rules(custom_rules_path)
        self.semaphore = asyncio.Semaphore(semaphore_limit)
        self.results = []
        self.scanned_urls = set()
        self.historical_urls = []
        self.endpoints = set()
        self._seen_findings = set()   # deduplicate findings
        self.user_agents = user_agents or []

    # ─────────────────────────────────────────
    #  SUBDOMAIN DISCOVERY
    # ─────────────────────────────────────────

    async def find_subdomains(self):
        """Multi-source subdomain enumeration: crt.sh + HackerTarget."""
        subdomains = set()
        base = self.domain.lstrip("www.")

        # Source 1: crt.sh (Certificate Transparency logs)
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(f"https://crt.sh/?q=%25.{base}&output=json")
                if r.status_code == 200:
                    for entry in r.json():
                        for sub in entry.get("name_value", "").split("\n"):
                            sub = sub.strip().lower().lstrip("*.")
                            if sub and sub.endswith(base):
                                subdomains.add(sub)
        except Exception:
            pass

        # Source 2: HackerTarget
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={base}")
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        parts = line.split(",")
                        if parts:
                            sub = parts[0].strip().lower()
                            if sub.endswith(base):
                                subdomains.add(sub)
        except Exception:
            pass

        result = sorted(subdomains) if subdomains else [self.domain]
        return result

    async def find_historical_js(self):
        """Fetch historical .js URLs from AlienVault OTX and Wayback Machine."""
        urls = set()
        # Source 1: AlienVault OTX
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/url_list?limit=100")
                if r.status_code == 200:
                    for entry in r.json().get("url_list", []):
                        url = entry.get("url")
                        if url and url.endswith(".js"):
                            urls.add(url)
        except Exception:
            pass

        # Source 2: Wayback Machine
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&filter=mimetype:application/javascript&collapse=urlkey&fl=original&limit=100")
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        if line.startswith("http") and line.endswith(".js"):
                            urls.add(line)
        except Exception:
            pass
        return list(urls)

    # ─────────────────────────────────────────
    #  ROBOTS.TXT / SITEMAP CRAWL
    # ─────────────────────────────────────────

    async def crawl_robots(self, client, base_url):
        """Parse robots.txt to discover extra paths & sitemaps."""
        extra_urls = []
        try:
            r = await client.get(f"{base_url}/robots.txt", timeout=8)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        extra_urls.append(sitemap_url)
                    elif line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            extra_urls.append(urljoin(base_url, path))
        except Exception:
            pass
        return extra_urls

    # ─────────────────────────────────────────
    #  FETCHING
    # ─────────────────────────────────────────

    async def fetch_content(self, client, url):
        async with self.semaphore:
            try:
                # Rotate User-Agent if list is provided
                headers = {}
                if self.user_agents:
                    headers["User-Agent"] = random.choice(self.user_agents)
                
                r = await client.get(url, follow_redirects=True, timeout=12, headers=headers)
                if r.status_code == 200:
                    return r.text
            except Exception:
                pass
            return None

    # ─────────────────────────────────────────
    #  SCRIPT EXTRACTION
    # ─────────────────────────────────────────

    def extract_scripts(self, html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        script_urls = []
        inline_scripts = []

        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                full = urljoin(base_url, src)
                if full not in self.scanned_urls:
                    script_urls.append(full)
                    self.scanned_urls.add(full)
            elif tag.string:
                inline_scripts.append(tag.string)

        # Also pick up webpack chunk references embedded in the HTML itself
        for m in _WEBPACK_CHUNK_RE.finditer(html):
            url = urljoin(base_url, m.group(1))
            if url not in self.scanned_urls and url.endswith(".js"):
                script_urls.append(url)
                self.scanned_urls.add(url)

        return script_urls, inline_scripts

    def extract_webpack_chunks(self, js_content, base_url):
        """Try to pull additional chunk JS URLs referenced inside a bundle."""
        urls = []
        for m in _WEBPACK_CHUNK_RE.finditer(js_content):
            url = urljoin(base_url, m.group(1))
            if url not in self.scanned_urls:
                urls.append(url)
                self.scanned_urls.add(url)
        return urls

    # ─────────────────────────────────────────
    #  SECRET SCANNING
    # ─────────────────────────────────────────

    def scan_text(self, content, source_url="inline"):
        findings = []
        # Beautify minified code for better regex matching
        if len(content) > 500 and "\n" not in content[:200]:
            try:
                content = jsbeautifier.beautify(content)
            except Exception:
                pass

        for name, regex in self.compiled_rules.items():
            for match in regex.finditer(content):
                raw = match.group()

                if name == "API Endpoint":
                    ep = raw.strip("\"' ")
                    # Filter junk endpoints
                    if len(ep) > 3 and not is_likely_dummy(ep):
                        self.endpoints.add(ep)
                    continue

                # Filter out dummy/placeholder values
                if is_likely_dummy(raw):
                    continue

                # Deduplicate: same rule + same secret value
                dedup_key = f"{name}::{raw}"
                if dedup_key in self._seen_findings:
                    continue
                self._seen_findings.add(dedup_key)

                # Grab surrounding context (±60 chars)
                start = max(0, match.start() - 60)
                end = min(len(content), match.end() + 60)
                ctx = content[start:end].strip().replace("\n", " ")

                findings.append({
                    "rule":    name,
                    "secret":  raw,
                    "source":  source_url,
                    "context": ctx,
                })

        return findings

    # ─────────────────────────────────────────
    #  PER-TARGET SCAN
    # ─────────────────────────────────────────

    async def scan_target(self, client, target, progress_callback=None):
        base_url = f"https://{target}"
        if progress_callback:
            progress_callback(f"Scanning {target}...")

        # Fetch main page
        html = await self.fetch_content(client, base_url)
        if not html:
            # Try HTTP fallback
            html = await self.fetch_content(client, f"http://{target}")
        if not html:
            return

        script_urls, inline_scripts = self.extract_scripts(html, base_url)

        # Scan inline scripts immediately
        for inline in inline_scripts:
            self.results.extend(self.scan_text(inline, f"{target} (inline)"))

        # Gather extra paths from robots.txt
        extra_paths = await self.crawl_robots(client, base_url)
        for path in extra_paths:
            if path not in self.scanned_urls and not path.endswith(".js"):
                self.scanned_urls.add(path)
                path_html = await self.fetch_content(client, path)
                if path_html:
                    s_urls, s_inline = self.extract_scripts(path_html, base_url)
                    script_urls.extend(s_urls)
                    for si in s_inline:
                        self.results.extend(self.scan_text(si, f"{path} (inline)"))

        # Fetch and scan all JS files concurrently
        tasks = [self.fetch_and_scan(client, url, base_url) for url in script_urls]
        if tasks:
            await asyncio.gather(*tasks)

    async def fetch_and_scan(self, client, url, base_url=None):
        content = await self.fetch_content(client, url)
        if not content:
            return

        findings = self.scan_text(content, url)
        self.results.extend(findings)

        # Dig one level deeper into webpack chunks found inside this bundle
        if base_url:
            chunk_urls = self.extract_webpack_chunks(content, base_url)
            if chunk_urls:
                chunk_tasks = [self.fetch_and_scan(client, cu, base_url) for cu in chunk_urls[:30]]
                await asyncio.gather(*chunk_tasks)

        # ✨ New Feature: Source Map Probing
        # If this is a minified JS file, see if a sourcemap was left behind
        if url.endswith(".js"):
            map_url = url + ".map"
            if map_url not in self.scanned_urls:
                self.scanned_urls.add(map_url)
                map_content = await self.fetch_content(client, map_url)
                if map_content and "sourcesContent" in map_content:
                    # Scan sourcemap for hardcoded values left inside the unminified original source
                    map_findings = self.scan_text(map_content, map_url)
                    self.results.extend(map_findings)

    # ─────────────────────────────────────────
    #  ENTRY POINT
    # ─────────────────────────────────────────

    async def run(self, enumerate_subdomains=False, progress_callback=None):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }

        if enumerate_subdomains:
            if progress_callback:
                progress_callback("Enumerating subdomains (crt.sh + HackerTarget)...")
            self.targets = await self.find_subdomains()
        else:
            self.targets = [self.domain]

        if progress_callback:
            progress_callback("Hunting for hidden historical JS (Wayback + AlienVault)...")
        self.historical_urls = await self.find_historical_js()

        if progress_callback:
            progress_callback(f"Found {len(self.targets)} target(s) and {len(self.historical_urls)} historical JS files. Initiating scan matrix...")

        async with httpx.AsyncClient(headers=headers, verify=False, http2=True) as client:
            tasks = [self.scan_target(client, t, progress_callback) for t in self.targets]
            # Also fetch and scan all historical URLs
            for h_url in self.historical_urls:
                if h_url not in self.scanned_urls:
                    self.scanned_urls.add(h_url)
                    tasks.append(self.fetch_and_scan(client, h_url))
            
            await asyncio.gather(*tasks)

        return self.results
