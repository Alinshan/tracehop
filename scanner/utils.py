import re
import hashlib
from bs4 import BeautifulSoup

def calculate_content_signature(html_text):
    """
    Creates a semi-stable fingerprint of a page by stripping 
    boilerplate like timestamps, CSRF tokens, and script tags.
    """
    if not html_text:
        return ""
    
    # Strip common dynamic noise patterns
    html_text = re.sub(r'<script.*?>.*?</script>', '', html_text, flags=re.DOTALL)
    html_text = re.sub(r'csrf[-_]token\s*[:=]\s*["\']\w+["\']', '', html_text, flags=re.IGNORECASE)
    html_text = re.sub(r'nonce\s*=\s*["\']\w+["\']', '', html_text, flags=re.IGNORECASE)
    
    # Simple normalization: remove whitespace and special characters
    normalized = re.sub(r'\s+', '', html_text)
    
    # Use MD5 for a quick, readable signature (good enough for diffing)
    return hashlib.md5(normalized.encode('utf-8')).hexdigest()

def extract_identifiers(html_text):
    """
    Tries to find a 'Name' or 'Title' for the page to use as evidence.
    """
    soup = BeautifulSoup(html_text, 'html.parser')
    
    # Try finding common identity markers
    # 1. Page Title
    title = soup.title.string.strip() if soup.title else ""
    
    # 2. H1 (often the name on a profile page)
    h1 = soup.find('h1').get_text(strip=True) if soup.find('h1') else ""
    
    # 3. Meta Data / OG Tags
    og_title = ""
    og_tag = soup.find('meta', property='og:title')
    if og_tag:
        og_title = og_tag.get('content', '').strip()
        
    # Pick the best candidate
    candidates = [h1, og_title, title]
    for c in candidates:
        if c and len(c) > 3 and "error" not in c.lower() and "404" not in c:
            return c
            
    return "Unknown Profile"
