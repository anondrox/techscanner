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
import json

from .fingerprints import FINGERPRINTS, SECURITY_HEADERS
from .cve_lookup import CVELookup, CVEInfo, format_cve_for_display, FRAMEWORK_ENDPOINTS, ENDPOINT_VERSION_PATTERNS, COMMON_ENDPOINTS


class TechDetector:
    def __init__(self, timeout: int = 25, max_retries: int = 2, 
                  enable_cve: bool = False, nvd_api_key: Optional[str] = None,
                  stealth_mode: bool = True,
                  min_confidence: float = 0.70,
                  enable_graphql_recon: bool = False):
        self.timeout = timeout
        self.max_retries = max_retries
        self.enable_cve = enable_cve
        self.stealth_mode = stealth_mode
        self.min_confidence = min_confidence
        self.enable_graphql_recon = enable_graphql_recon
        self.cve_lookup = CVELookup(api_key=nvd_api_key if enable_cve else None)
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        ]

        # Common GraphQL field/type wordlist for light schema inference (Clairvoyance-style)
        self.graphql_common_fields = [
            "id", "_id", "uuid", "name", "email", "username", "password", "token", "accessToken",
            "user", "users", "me", "profile", "account", "admin", "role", "roles",
            "query", "mutation", "subscription", "__schema", "__type", "__typename",
            "createdAt", "updatedAt", "deletedAt", "status", "active", "enabled",
            "data", "input", "output", "result", "error", "message",
            "page", "limit", "offset", "total", "count", "edges", "node", "nodes",
            "login", "logout", "register", "resetPassword", "verifyEmail",
            "product", "products", "order", "orders", "cart", "payment",
            "file", "files", "upload", "download"
        ]

    def _get_headers(self) -> Dict[str, str]:
        ua = random.choice(self.user_agents)
        headers = {
            "User-Agent": ua,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
        }
        return headers

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    async def _stealth_delay(self):
        if self.stealth_mode:
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

    async def _post_graphql(self, session: aiohttp.ClientSession, endpoint: str, query: str) -> Optional[Dict]:
        """Send GraphQL query with stealth"""
        try:
            await self._stealth_delay()
            headers = self._get_headers()
            headers["Content-Type"] = "application/json"
            
            payload = {"query": query}
            
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            async with session.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=ssl_context
            ) as response:
                if response.status == 200:
                    return await response.json()
                return None
        except:
            return None

    async def detect_graphql_introspection(self, session: aiohttp.ClientSession, base_url: str, graphql_endpoints: List[str]) -> Dict[str, Any]:
        """Check if GraphQL introspection is enabled (Clairvoyance-style recon)"""
        result = {
            "detected": False,
            "introspection_enabled": False,
            "endpoints": [],
            "schema_hints": [],
            "risk_level": "Low"
        }

        if not graphql_endpoints:
            return result

        result["detected"] = True
        result["endpoints"] = graphql_endpoints

        introspection_query = """
        {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              name
              kind
            }
          }
        }
        """

        for endpoint in graphql_endpoints[:3]:  # Limit to first 3 endpoints
            full_url = urljoin(base_url, endpoint) if endpoint.startswith('/') else endpoint
            
            data = await self._post_graphql(session, full_url, introspection_query)
            
            if data and "data" in data and data["data"]:
                result["introspection_enabled"] = True
                schema = data["data"].get("__schema", {})
                
                types = schema.get("types", [])
                if types:
                    type_names = [t.get("name") for t in types if t.get("name") and not t.get("name").startswith("__")]
                    result["schema_hints"] = type_names[:15]  # Limit output
                
                result["risk_level"] = "High" if result["introspection_enabled"] else "Medium"
                break
            
            # If introspection disabled, try light field inference (mini Clairvoyance)
            if self.enable_graphql_recon:
                inferred = await self._light_graphql_field_inference(session, full_url)
                if inferred:
                    result["schema_hints"].extend(inferred)
                    result["risk_level"] = "Medium"

        return result

    async def _light_graphql_field_inference(self, session: aiohttp.ClientSession, endpoint: str) -> List[str]:
        """Lightweight schema inference when introspection is disabled (inspired by Clairvoyance)"""
        discovered = []
        
        # Test common root types
        test_queries = [
            "{ __typename }",
            "{ me { id } }",
            "{ user { id email } }",
            "{ users { id } }",
            "mutation { login(input: {email: \"test@test.com\"}) { token } }"
        ]

        for query in test_queries[:4]:
            data = await self._post_graphql(session, endpoint, query)
            if data:
                if "errors" in data:
                    # Look for useful error messages that reveal field names
                    for err in data.get("errors", []):
                        msg = str(err.get("message", "")).lower()
                        for field in self.graphql_common_fields:
                            if field in msg and field not in discovered:
                                discovered.append(field)
                elif "data" in data:
                    discovered.append("__typename")

        return discovered[:10]

    async def _scan_endpoints_for_versions(self, session: aiohttp.ClientSession, base_url: str, detected_techs: List[str]) -> Dict[str, str]:
        versions: Dict[str, str] = {}
        if not detected_techs:
            return versions

        framework_endpoints = set()
        for tech in detected_techs:
            if tech in FRAMEWORK_ENDPOINTS:
                framework_endpoints.update(FRAMEWORK_ENDPOINTS[tech])

        endpoints_to_scan = list(framework_endpoints)[:10] + list(COMMON_ENDPOINTS)[:8]

        for endpoint in endpoints_to_scan:
            try:
                endpoint_url = urljoin(base_url, endpoint) if endpoint.startswith('/') else endpoint
                if endpoint_url.startswith('http'):
                    html, _, _, _ = await self._fetch_page(session, endpoint_url)
                    if html and len(html) < 50000:
                        for pattern, _ in ENDPOINT_VERSION_PATTERNS:
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            if matches:
                                for tech in detected_techs:
                                    if tech not in versions:
                                        versions[tech] = matches[0]
                                        break
            except:
                pass
        return versions

    def _extract_scripts(self, soup: BeautifulSoup) -> Tuple[List[str], List[str]]:
        script_srcs: List[str] = []
        script_contents: List[str] = []
        
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                script_srcs.append(str(src))
            if script.string:
                script_contents.append(str(script.string))
        
        return script_srcs, script_contents

    def _extract_css(self, soup: BeautifulSoup) -> List[str]:
        css_hrefs: List[str] = []
        for link in soup.find_all('link', rel='stylesheet'):
            href = link.get('href')
            if href:
                css_hrefs.append(str(href))
        for style in soup.find_all('style'):
            if style.string:
                css_hrefs.append(str(style.string))
        return css_hrefs

    def _extract_meta(self, soup: BeautifulSoup) -> Dict[str, str]:
        meta_tags: Dict[str, str] = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property') or meta.get('http-equiv') or ''
            content = meta.get('content') or ''
            if name and content:
                meta_tags[str(name).lower()] = str(content)
        return meta_tags

    def _check_pattern(self, pattern_info: Dict[str, Any], context: Dict[str, Any]) -> Tuple[bool, float]:
        pattern_type = pattern_info.get('type', '')
        pattern = pattern_info.get('pattern', '')
        value_pattern = pattern_info.get('value', '')
        
        if not pattern:
            return False, 0.0
        
        try:
            if pattern_type == 'script':
                for src in context.get('script_srcs', []):
                    if re.search(pattern, str(src), re.IGNORECASE):
                        return True, 0.90
            elif pattern_type == 'script_content':
                for content in context.get('script_contents', []):
                    if re.search(pattern, str(content), re.IGNORECASE):
                        return True, 0.85
            elif pattern_type == 'css':
                for css in context.get('css_hrefs', []):
                    if re.search(pattern, str(css), re.IGNORECASE):
                        return True, 0.88
            elif pattern_type == 'html':
                html = context.get('html', '')
                if re.search(pattern, str(html), re.IGNORECASE):
                    return True, 0.75
            elif pattern_type == 'meta':
                meta_tags = context.get('meta_tags', {})
                if pattern in meta_tags:
                    if value_pattern:
                        if re.search(value_pattern, str(meta_tags[pattern]), re.IGNORECASE):
                            return True, 0.95
                    else:
                        return True, 0.88
            elif pattern_type == 'header':
                headers = context.get('headers', {})
                header_name = str(pattern).lower()
                if header_name in headers:
                    if value_pattern:
                        if re.search(value_pattern, str(headers[header_name]), re.IGNORECASE):
                            return True, 0.95
                    else:
                        return True, 0.82
            elif pattern_type == 'cookie':
                cookies = context.get('cookies', [])
                for cookie in cookies:
                    if re.search(pattern, str(cookie), re.IGNORECASE):
                        return True, 0.80
            elif pattern_type == 'url':
                url = context.get('url', '')
                if re.search(pattern, str(url), re.IGNORECASE):
                    return True, 0.65
        except re.error:
            pass
        return False, 0.0

    def _detect_technologies(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        detected: List[Dict[str, Any]] = []
        
        for category, technologies in FINGERPRINTS.items():
            for tech_name, tech_info in technologies.items():
                patterns = tech_info.get('patterns', [])
                matches = 0
                total_confidence = 0.0
                
                for pattern_info in patterns:
                    matched, confidence = self._check_pattern(pattern_info, context)
                    if matched:
                        matches += 1
                        total_confidence += confidence
                
                if matches > 0:
                    avg_confidence = total_confidence / matches
                    
                    if matches >= 2 or avg_confidence >= 0.90:
                        if matches > 1:
                            avg_confidence = min(0.99, avg_confidence + (matches - 1) * 0.04)
                        
                        if avg_confidence >= self.min_confidence:
                            version = self.cve_lookup.extract_version(tech_name, context)
                            detected.append({
                                'name': tech_name,
                                'category': tech_info.get('category', category),
                                'confidence': round(avg_confidence, 2),
                                'website': tech_info.get('website', ''),
                                'matches': matches,
                                'version': version,
                            })
        
        detected.sort(key=lambda x: (-x['confidence'], x['name']))
        return detected

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
            'tech_stacks': [],
            'graphql': {}
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

                # === GraphQL Detection + Clairvoyance-style Recon ===
                graphql_endpoints = []
                for tech in technologies:
                    if 'graphql' in tech['category'].lower() or 'graphql' in tech['name'].lower():
                        if '/graphql' in tech.get('name', '').lower() or any(p in str(context.get('html', '')).lower() for p in ['/graphql', 'graphql']):
                            graphql_endpoints.append('/graphql')

                if graphql_endpoints or any('graphql' in t['category'].lower() for t in technologies):
                    graphql_info = await self.detect_graphql_introspection(session, final_url, ['/graphql'])
                    result['graphql'] = graphql_info

                # CVE Checking
                if self.enable_cve and technologies:
                    detected_names = [t['name'] for t in technologies]
                    for tech in technologies:
                        if not tech.get('version'):
                            version = self.cve_lookup.extract_version(tech['name'], context)
                            if version:
                                tech['version'] = version
                    
                    versions = await self._scan_endpoints_for_versions(session, final_url, detected_names)
                    for tech in technologies:
                        if tech['name'] in versions and not tech.get('version'):
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
