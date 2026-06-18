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


# Common Tech Stack Definitions
TECH_STACKS = {
    "Next.js Stack": {
        "core": ["Next.js", "React"],
        "recommended": ["Tailwind CSS", "shadcn/ui", "Vercel", "tRPC"],
        "description": "Modern full-stack React framework"
    },
    "T3 Stack": {
        "core": ["Next.js", "React", "Tailwind CSS"],
        "recommended": ["tRPC", "Prisma", "Drizzle"],
        "description": "Popular type-safe full-stack stack"
    },
    "Nuxt Stack": {
        "core": ["Nuxt.js", "Vue.js"],
        "recommended": ["Tailwind CSS", "Vercel"],
        "description": "Vue.js meta-framework"
    },
    "SvelteKit Stack": {
        "core": ["SvelteKit", "Svelte"],
        "recommended": ["Tailwind CSS"],
        "description": "Fast, lightweight Svelte framework"
    },
    "MERN Stack": {
        "core": ["MongoDB", "Express.js", "React", "Node.js"],
        "recommended": ["Tailwind CSS", "Redux"],
        "description": "Classic JavaScript full-stack"
    },
    "Laravel Stack": {
        "core": ["Laravel", "PHP"],
        "recommended": ["Tailwind CSS", "Livewire"],
        "description": "Elegant PHP framework"
    },
    "Django Stack": {
        "core": ["Django", "Python"],
        "recommended": ["Tailwind CSS", "Celery"],
        "description": "Batteries-included Python framework"
    },
    "FastAPI Stack": {
        "core": ["FastAPI", "Python"],
        "recommended": ["SQLAlchemy", "Pydantic"],
        "description": "High-performance Python API framework"
    },
    "Spring Boot Stack": {
        "core": ["Spring", "Java"],
        "recommended": ["Spring Boot"],
        "description": "Enterprise Java framework"
    },
    "Ruby on Rails Stack": {
        "core": ["Ruby on Rails", "Ruby"],
        "recommended": ["Tailwind CSS"],
        "description": "Convention over configuration"
    },
    "WordPress Stack": {
        "core": ["WordPress", "PHP"],
        "recommended": ["WooCommerce", "Elementor"],
        "description": "Most popular CMS in the world"
    },
    "Shopify Stack": {
        "core": ["Shopify"],
        "recommended": ["Hydrogen", "Remix", "Storefront API"],
        "description": "Modern e-commerce platform"
    },
    "Astro Stack": {
        "core": ["Astro"],
        "recommended": ["React", "Vue.js", "Tailwind CSS", "MDX"],
        "description": "Content-focused static site generator"
    },
    "Jamstack": {
        "core": ["Next.js", "Gatsby", "Astro"],
        "recommended": ["Netlify", "Vercel", "Cloudflare"],
        "description": "Modern web architecture"
    },
}


class TechDetector:
    def __init__(self, timeout: int = 20, max_retries: int = 2, 
                  enable_cve: bool = False, nvd_api_key: Optional[str] = None,
                  stealth_mode: bool = True):
        self.timeout = timeout
        self.max_retries = max_retries
        self.enable_cve = enable_cve
        self.stealth_mode = stealth_mode
        self.cve_lookup = CVELookup(api_key=nvd_api_key if enable_cve else None)
        
        # Realistic & Recent User-Agents (Stealth)
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        ]

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=0",
        }
        
        # Add more stealth headers randomly
        if random.random() > 0.5:
            headers["DNT"] = "1"
        if random.random() > 0.7:
            headers["Sec-CH-UA-Platform"] = random.choice(['"Windows"', '"macOS"', '"Linux"'])
            
        return headers

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    async def _stealth_delay(self):
        """Add random delay for stealth"""
        if self.stealth_mode:
            await asyncio.sleep(random.uniform(0.8, 2.5))

    async def _fetch_page(self, session: aiohttp.ClientSession, url: str) -> Tuple[Optional[str], Dict[str, str], Optional[str], List[str]]:
        html = None
        headers: Dict[str, str] = {}
        final_url = url
        cookies: List[str] = []
        
        for attempt in range(self.max_retries):
            try:
                await self._stealth_delay()  # Stealth delay before request
                
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
                await asyncio.sleep(random.uniform(1.0, 3.0))
        
        return html, headers, final_url, cookies

    async def _scan_endpoints_for_versions(self, session: aiohttp.ClientSession, base_url: str, detected_techs: List[str]) -> Dict[str, str]:
        """Scan framework-specific, common, and discovered endpoints for version information"""
        versions: Dict[str, str] = {}
        
        if not detected_techs:
            return versions
        
        framework_endpoints = set()
        common_endpoints_set = set(COMMON_ENDPOINTS)
        robots_endpoints = set()
        sitemap_endpoints = set()
        
        for tech in detected_techs:
            if tech in FRAMEWORK_ENDPOINTS:
                framework_endpoints.update(FRAMEWORK_ENDPOINTS[tech])
        
        # Fetch robots.txt
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            robots_response = await self._fetch_page(session, robots_url)
            if robots_response[0]:
                robots_content = robots_response[0]
                sitemap_urls = re.findall(r'Sitemap:\s*(\S+)', robots_content, re.IGNORECASE)
                sitemap_endpoints.update(sitemap_urls)
                
                disallow_paths = re.findall(r'Disallow:\s*/([^\s]*)', robots_content, re.IGNORECASE)
                for path in disallow_paths:
                    if path:
                        robots_endpoints.add(f"/{path}")
        except:
            pass
        
        # Parse sitemap.xml
        try:
            sitemap_url = urljoin(base_url, '/sitemap.xml')
            sitemap_response = await self._fetch_page(session, sitemap_url)
            if sitemap_response[0]:
                sitemap_urls = re.findall(r'<loc>([^<]+)</loc>', sitemap_response[0])
                for url in sitemap_urls:
                    try:
                        path = urlparse(url).path
                        if path:
                            sitemap_endpoints.add(path)
                    except:
                        pass
        except:
            pass
        
        endpoints_to_scan = list(robots_endpoints)[:25]
        endpoints_to_scan.extend(list(framework_endpoints)[:8])
        endpoints_to_scan.extend(list(common_endpoints_set)[:8])
        endpoints_to_scan.extend(list(sitemap_endpoints)[:8])
        
        for endpoint in endpoints_to_scan:
            try:
                endpoint_url = urljoin(base_url, endpoint) if endpoint.startswith('/') else endpoint
                if endpoint_url.startswith('http'):
                    html, _, _, _ = await self._fetch_page(session, endpoint_url)
                    if html and len(html) < 50000:
                        for pattern, desc in ENDPOINT_VERSION_PATTERNS:
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            if matches:
                                for tech in detected_techs:
                                    if tech.lower() in endpoint.lower():
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
                name_str = str(name) if not isinstance(name, str) else name
                content_str = str(content) if not isinstance(content, str) else content
                meta_tags[name_str.lower()] = content_str
        
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
                        return True, 0.9
            
            elif pattern_type == 'script_content':
                for content in context.get('script_contents', []):
                    if re.search(pattern, str(content), re.IGNORECASE):
                        return True, 0.85
            
            elif pattern_type == 'css':
                for css in context.get('css_hrefs', []):
                    if re.search(pattern, str(css), re.IGNORECASE):
                        return True, 0.9
            
            elif pattern_type == 'html':
                html = context.get('html', '')
                if re.search(pattern, str(html), re.IGNORECASE):
                    return True, 0.8
            
            elif pattern_type == 'meta':
                meta_tags = context.get('meta_tags', {})
                if pattern in meta_tags:
                    if value_pattern:
                        if re.search(value_pattern, str(meta_tags[pattern]), re.IGNORECASE):
                            return True, 0.95
                    else:
                        return True, 0.9
            
            elif pattern_type == 'header':
                headers = context.get('headers', {})
                header_name = str(pattern).lower()
                if header_name in headers:
                    if value_pattern:
                        if re.search(value_pattern, str(headers[header_name]), re.IGNORECASE):
                            return True, 0.95
                    else:
                        return True, 0.85
            
            elif pattern_type == 'cookie':
                cookies = context.get('cookies', [])
                for cookie in cookies:
                    if re.search(pattern, str(cookie), re.IGNORECASE):
                        return True, 0.85
            
            elif pattern_type == 'url':
                url = context.get('url', '')
                if re.search(pattern, str(url), re.IGNORECASE):
                    return True, 0.7
                    
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
                    if matches > 1:
                        avg_confidence = min(0.99, avg_confidence + (matches - 1) * 0.05)
                    
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

    def detect_tech_stacks(self, technologies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect common technology stacks from detected technologies"""
        if not technologies:
            return []
        
        tech_names = {t['name'] for t in technologies}
        detected_stacks = []
        
        for stack_name, stack_info in TECH_STACKS.items():
            core_techs = set(stack_info["core"])
            
            if core_techs.issubset(tech_names):
                matched_recommended = [tech for tech in stack_info.get("recommended", []) if tech in tech_names]
                
                detected_stacks.append({
                    "name": stack_name,
                    "description": stack_info.get("description", ""),
                    "core_technologies": list(core_techs),
                    "matched_recommended": matched_recommended,
                    "confidence": 0.95 if len(matched_recommended) > 0 else 0.85
                })
        
        detected_stacks.sort(key=lambda x: -x["confidence"])
        return detected_stacks

    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            'present': [],
            'missing': [],
            'score': 0,
            'max_score': 0,
        }
        
        importance_weights = {'high': 3, 'medium': 2, 'low': 1}
        
        for header_key, header_info in SECURITY_HEADERS.items():
            results['max_score'] += importance_weights.get(header_info['importance'], 1)
            
            if header_key in headers:
                results['present'].append({
                    'header': header_key,
                    'value': headers[header_key][:100] if len(headers[header_key]) > 100 else headers[header_key]
                })
                results['score'] += importance_weights.get(header_info['importance'], 1)
            else:
                results['missing'].append({
                    'header': header_key,
                    'importance': header_info['importance'],
                    'description': header_info['description']
                })
        
        if results['max_score'] > 0:
            percentage = (results['score'] / results['max_score']) * 100
            if percentage >= 90:
                results['grade'] = 'A+'
            elif percentage >= 80:
                results['grade'] = 'A'
            elif percentage >= 70:
                results['grade'] = 'B'
            elif percentage >= 60:
                results['grade'] = 'C'
            elif percentage >= 50:
                results['grade'] = 'D'
            else:
                results['grade'] = 'F'
        else:
            results['grade'] = 'N/A'
        
        return results

    def _analyze_performance(self, html: str, headers: Dict[str, str]) -> Dict[str, Any]:
        performance = {}
        
        if 'content-encoding' in headers:
            performance['compression'] = headers['content-encoding']
        
        cache_headers = {}
        for h in ['cache-control', 'expires', 'etag', 'last-modified']:
            if h in headers:
                cache_headers[h] = headers[h][:80]
        if cache_headers:
            performance['caching'] = cache_headers
        
        if 'loading="lazy"' in html.lower() or 'lazy' in html.lower():
            performance['lazy_loading'] = True
        
        preload = re.findall(r'rel=["\']preload["\']', html, re.IGNORECASE)
        if preload:
            performance['preload'] = len(preload)
        
        return performance

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
                
                # Parse page
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

    async def analyze_urls(self, urls: List[str], concurrency: int = 3) -> List[Dict[str, Any]]:
        """Lower default concurrency for stealth"""
        semaphore = asyncio.Semaphore(concurrency)
        
        async def analyze_with_semaphore(url):
            async with semaphore:
                return await self.analyze_url(url)
        
        tasks = [analyze_with_semaphore(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)
