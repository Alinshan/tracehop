import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import jsbeautifier
from .rules import get_compiled_rules

class TracehopEngine:
    def __init__(self, target_url, semaphore_limit=20):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc or target_url
        self.compiled_rules = get_compiled_rules()
        self.semaphore = asyncio.Semaphore(semaphore_limit)
        self.results = []
        self.scanned_urls = set()
        self.targets = []

    async def find_subdomains(self):
        """Fetches subdomains from crt.sh JSON API."""
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    subdomains = set()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub and '*' not in sub and sub.endswith(self.domain):
                                subdomains.add(sub)
                    return sorted(list(subdomains))
        except Exception:
            pass
        return [self.domain]

    async def fetch_content(self, client, url):
        async with self.semaphore:
            try:
                response = await client.get(url, follow_redirects=True, timeout=10)
                if response.status_code == 200:
                    return response.text
            except Exception:
                pass
            return None

    def extract_scripts(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        script_urls = []
        inline_scripts = []

        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                full_url = urljoin(base_url, src)
                if full_url not in self.scanned_urls:
                    script_urls.append(full_url)
                    self.scanned_urls.add(full_url)
            else:
                if script.string:
                    inline_scripts.append(script.string)

        return script_urls, inline_scripts

    def scan_text(self, content, source_url="inline"):
        findings = []
        # Pre-beautify if content looks minified
        if len(content) > 1000 and '\n' not in content[:100]:
            try:
                content = jsbeautifier.beautify(content)
            except:
                pass

        for name, regex in self.compiled_rules.items():
            matches = regex.finditer(content)
            for match in matches:
                findings.append({
                    "rule": name,
                    "secret": match.group(),
                    "source": source_url,
                    "context": content[max(0, match.start()-20):min(len(content), match.end()+20)].strip()
                })
        return findings

    async def scan_target(self, client, target, progress_callback=None):
        """Scans a single target (domain or subdomain)."""
        url = f"https://{target}"
        if progress_callback:
            progress_callback(f"Scanning {target}...")
            
        html = await self.fetch_content(client, url)
        if not html:
            return

        script_urls, inline_scripts = self.extract_scripts(html, url)
        
        # Scan inline
        for inline in inline_scripts:
            self.results.extend(self.scan_text(inline, f"{target} (inline)"))

        # Scan remote scripts
        tasks = [self.fetch_and_scan(client, s_url) for s_url in script_urls]
        if tasks:
            await asyncio.gather(*tasks)

    async def fetch_and_scan(self, client, url):
        content = await self.fetch_content(client, url)
        if content:
            findings = self.scan_text(content, url)
            self.results.extend(findings)

    async def run(self, enumerate_subdomains=False, progress_callback=None):
        if enumerate_subdomains:
            if progress_callback:
                progress_callback("Enumerating subdomains...")
            self.targets = await self.find_subdomains()
        else:
            self.targets = [self.domain]

        async with httpx.AsyncClient(headers={"User-Agent": "Tracehop/1.0"}, verify=False) as client:
            tasks = [self.scan_target(client, target, progress_callback) for target in self.targets]
            await asyncio.gather(*tasks)

        return self.results
