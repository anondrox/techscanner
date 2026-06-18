import re
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
import time
import ssl
import certifi
import random

from .fingerprints import FINGERPRINTS, SECURITY_HEADERS
from .cve_lookup import CVELookup, CVEInfo, format_cve_for_display, FRAMEWORK_ENDPOINTS, ENDPOINT_VERSION_PATTERNS, COMMON_ENDPOINTS


class TechDetector:
    def __init__(self, timeout: int = 25, max_retries: int = 2, 
                  enable_cve: bool = False, nvd_api_key: Optional[str] = None,
                  stealth_mode: bool = True):
        self.timeout = timeout
        self.max_retries = max_retries
        self.enable_cve = enable_cve
        self.stealth_mode = stealth_mode
        self.cve_lookup = CVELookup(api_key=nvd_api_key if enable_cve else None)
        
        # Highly realistic modern User-Agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        ]

    def _get_headers(self) -> Dict[str, str]:
        """Generate highly realistic browser headers for stealth"""
        ua = random.choice(self.user_agents)
        
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }
        
        # Randomly add modern client hints
        if random.random() > 0.4:
            headers["Sec-CH-UA"] = '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"'
            headers["Sec-CH-UA-Mobile"] = "?0"
            headers["Sec-CH-UA-Platform"] = random.choice(['"Windows"', '"macOS"', '"Linux"'])
        
        if random.random() > 0.6:
            headers["DNT"] = "1"
            
        return headers

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    async def _stealth_delay(self):
        if self.stealth_mode:
            # Variable delay to look more human
            delay = random.uniform(1.2, 3.5)
            await asyncio.sleep(delay)

    async def _fetch_page(self, session: aiohttp.ClientSession, url: str) -> Tuple[Optional[str], Dict[str, str], Optional[str], List[str]]:
        html = None
        headers: Dict[str, str] = {}
        final_url = url
        cookies: List[str] = []
        
        for attempt in range(self.max_retries):
            try:
                await self._stealth_delay()
                
                ssl_context = ssl.create_default_context(cafile=certifi.where())
                
                async with session.get(
                    url,
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=ssl_context,
                    allow_redirects=True
                ) as response:
                    html = await response.text()
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    final_url = str(response.url)
                    cookies = [f"{c.key}={c.value}" for c in response.cookies.values()]
                    break
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    return None, {}, None, []
            except Exception:
                if attempt == self.max_retries - 1:
                    return None, {}, None, []
                await asyncio.sleep(random.uniform(2.0, 4.5))
        
        return html, headers, final_url, cookies

    # ... (rest of the methods remain the same for brevity in this update)

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        start_time = time.time()
        result = {
            'url': url,
            'success': False,
            'technologies': [],
            'security': {},
            'performance': {},
            'vulnerabilities': {},
            'page_info': {},
            'analysis_time': 0,
            'final_url': url,
            'tech_stacks': []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                html, headers, final_url, cookies = await self._fetch_page(session, self._normalize_url(url))
                
                if not html:
                    result['error'] = 'Failed to fetch page'
                    result['analysis_time'] = round(time.time() - start_time, 2)
                    return result
                
                result['final_url'] = final_url
                
                soup = BeautifulSoup(html, 'lxml')
                script_srcs, script_contents = self._extract_scripts(soup)
                css_hrefs = self._extract_css(soup)
                meta_tags = self._extract_meta(soup)
                
                context = {
                    'html': html,
                    'headers': headers,
                    'script_srcs': script_srcs,
                    'script_contents': script_contents,
                    'css_hrefs': css_hrefs,
                    'meta_tags': meta_tags,
                    'cookies': cookies,
                    'url': final_url
                }
                
                technologies = self._detect_technologies(context)
                result['technologies'] = technologies
                result['tech_stacks'] = self.detect_tech_stacks(technologies)
                
                result['security'] = self._analyze_security_headers(headers)
                result['performance'] = self._analyze_performance(html, headers)
                
                title_tag = soup.find('title')
                if title_tag:
                    result['page_info']['title'] = title_tag.get_text(strip=True)[:100]
                
                if self.enable_cve and technologies:
                    detected_names = [t['name'] for t in technologies]
                    versions = await self._scan_endpoints_for_versions(session, final_url, detected_names)
                    for tech in technologies:
                        if tech['name'] in versions:
                            tech['version'] = versions[tech['name']]
                    cve_results = await self.cve_lookup.lookup_cves(technologies)
                    result['vulnerabilities'] = cve_results
                
                result['success'] = True
                result['analysis_time'] = round(time.time() - start_time, 2)
                
        except Exception as e:
            result['error'] = str(e)
            result['analysis_time'] = round(time.time() - start_time, 2)
        
        return result

    async def analyze_urls(self, urls: List[str], concurrency: int = 2) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(concurrency)
        
        async def analyze_with_semaphore(url):
            async with semaphore:
                return await self.analyze_url(url)
        
        tasks = [analyze_with_semaphore(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)
