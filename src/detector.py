import re
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import time
import ssl
import certifi

from .fingerprints import FINGERPRINTS, SECURITY_HEADERS
from .cve_lookup import CVELookup, CVEInfo, format_cve_for_display, FRAMEWORK_ENDPOINTS, ENDPOINT_VERSION_PATTERNS, COMMON_ENDPOINTS


class TechDetector:
    def __init__(self, timeout: int = 15, max_retries: int = 2, 
                 enable_cve: bool = False, nvd_api_key: Optional[str] = None):
        self.timeout = timeout
        self.max_retries = max_retries
        self.enable_cve = enable_cve
        self.cve_lookup = CVELookup(api_key=nvd_api_key if enable_cve else None)
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]

    def _get_headers(self) -> Dict[str, str]:
        import random
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "no-cache",
        }

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    async def _fetch_page(self, session: aiohttp.ClientSession, url: str) -> Tuple[Optional[str], Dict[str, str], Optional[str], List[str]]:
        html = None
        headers: Dict[str, str] = {}
        final_url = url
        cookies: List[str] = []
        
        for attempt in range(self.max_retries):
            try:
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
                await asyncio.sleep(0.5)
        
        return html, headers, final_url, cookies

    async def _scan_endpoints_for_versions(self, session: aiohttp.ClientSession, base_url: str, detected_techs: List[str]) -> Dict[str, str]:
        """Scan framework-specific, common, and discovered endpoints for version information"""
        versions: Dict[str, str] = {}
        
        if not detected_techs:
            return versions
        
        # Collect endpoints to scan from multiple sources
        framework_endpoints = set()
        common_endpoints_set = set(COMMON_ENDPOINTS)
        robots_endpoints = set()
        sitemap_endpoints = set()
        
        # 1. Add framework-specific endpoints
        for tech in detected_techs:
            if tech in FRAMEWORK_ENDPOINTS:
                framework_endpoints.update(FRAMEWORK_ENDPOINTS[tech])
        
        # 2. Fetch robots.txt for Disallow paths and sitemap URLs
        robots_content = None
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            robots_response = await self._fetch_page(session, robots_url)
            if robots_response[0]:
                robots_content = robots_response[0]
                # Extract sitemap URLs
                sitemap_urls = re.findall(r'Sitemap:\s*(\S+)', robots_content, re.IGNORECASE)
                sitemap_endpoints.update(sitemap_urls)
                
                # Extract ALL Disallow paths (prioritize robots.txt endpoints)
                disallow_paths = re.findall(r'Disallow:\s*/([^\s]*)', robots_content, re.IGNORECASE)
                for path in disallow_paths:
                    if path:
                        robots_endpoints.add(f"/{path}")
        except:
            pass
        
        # 3. Parse sitemap.xml if found
        try:
            sitemap_url = urljoin(base_url, '/sitemap.xml')
            sitemap_response = await self._fetch_page(session, sitemap_url)
            if sitemap_response[0]:
                # Extract URLs from sitemap
                sitemap_urls = re.findall(r'<loc>([^<]+)</loc>', sitemap_response[0])
                # Add all paths from sitemap as endpoints
                for url in sitemap_urls:
                    try:
                        path = urlparse(url).path
                        if path:
                            sitemap_endpoints.add(path)
                    except:
                        pass
        except:
            pass
        
        # 4. Prioritize endpoint scanning: robots.txt first, then framework/common, then sitemap
        # Scan all robots.txt endpoints + selected others
        endpoints_to_scan = list(robots_endpoints)[:30]  # Scan up to 30 robots.txt endpoints
        endpoints_to_scan.extend(list(framework_endpoints)[:10])  # Add framework endpoints
        endpoints_to_scan.extend(list(common_endpoints_set)[:10])  # Add common endpoints
        endpoints_to_scan.extend(list(sitemap_endpoints)[:10])  # Add sitemap endpoints
        
        # 5. Scan endpoints for version clues
        for endpoint in endpoints_to_scan:
            try:
                endpoint_url = urljoin(base_url, endpoint) if endpoint.startswith('/') else endpoint
                if endpoint_url.startswith('http'):
                    html, _, _, _ = await self._fetch_page(session, endpoint_url)
                    if html and len(html) < 50000:  # Only process reasonable-sized responses
                        for pattern, desc in ENDPOINT_VERSION_PATTERNS:
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            if matches:
                                # Try to find framework-specific version
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

    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            'present': [],
            'missing': [],
            'score': 0,
            'max_score': 0,
        }
        
        importance_weights = {'high': 3, 'medium': 2, 'low': 1}
        
        for header_key, header_info in SECURITY_HEADERS.items():
            weight = importance_weights.get(header_info['importance'], 1)
            results['max_score'] += weight
            
            if header_key in headers:
                header_value = headers.get(header_key, '') or ''
                results['present'].append({
                    'header': header_info['name'],
                    'value': header_value[:100] + ('...' if len(header_value) > 100 else ''),
                    'importance': header_info['importance'],
                    'description': header_info['description'],
                })
                results['score'] += weight
            else:
                results['missing'].append({
                    'header': header_info['name'],
                    'importance': header_info['importance'],
                    'description': header_info['description'],
                    'reference': header_info['reference'],
                })
        
        if results['max_score'] > 0:
            results['grade'] = self._calculate_grade(results['score'] / results['max_score'])
        else:
            results['grade'] = 'N/A'
        
        return results

    def _calculate_grade(self, ratio: float) -> str:
        if ratio >= 0.9:
            return 'A+'
        elif ratio >= 0.8:
            return 'A'
        elif ratio >= 0.7:
            return 'B'
        elif ratio >= 0.6:
            return 'C'
        elif ratio >= 0.5:
            return 'D'
        else:
            return 'F'

    def _analyze_performance(self, headers: Dict[str, str], html: str, soup: BeautifulSoup) -> Dict[str, Any]:
        performance: Dict[str, Any] = {
            'caching': {},
            'compression': None,
            'cdn': None,
            'http2': None,
            'preload': [],
            'lazy_loading': False,
        }
        
        cache_control = headers.get('cache-control', '')
        if cache_control:
            performance['caching']['cache-control'] = cache_control
        
        if 'etag' in headers:
            performance['caching']['etag'] = True
        
        if 'last-modified' in headers:
            performance['caching']['last-modified'] = headers['last-modified']
        
        content_encoding = headers.get('content-encoding', '')
        if content_encoding:
            performance['compression'] = content_encoding
        
        for link in soup.find_all('link', rel='preload'):
            href = link.get('href')
            as_type = link.get('as', '')
            if href:
                performance['preload'].append({'href': str(href), 'as': str(as_type)})
        
        if soup.find_all(attrs={'loading': 'lazy'}):
            performance['lazy_loading'] = True
        
        return performance

    def _get_page_info(self, soup: BeautifulSoup, url: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            'title': '',
            'description': '',
            'language': '',
            'canonical': '',
            'favicon': '',
        }
        
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            info['title'] = str(title_tag.string).strip()
        
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            content = meta_desc.get('content')
            if content:
                info['description'] = str(content)[:200]
        
        html_tag = soup.find('html')
        if html_tag:
            lang = html_tag.get('lang')
            if lang:
                info['language'] = str(lang)
        
        canonical = soup.find('link', rel='canonical')
        if canonical:
            href = canonical.get('href')
            if href:
                info['canonical'] = str(href)
        
        for link in soup.find_all('link'):
            rel = link.get('rel')
            if rel is None:
                rel_str = ''
            elif isinstance(rel, list):
                rel_str = ' '.join(str(r) for r in rel)
            else:
                rel_str = str(rel)
            if 'icon' in rel_str.lower():
                href = link.get('href')
                if href:
                    info['favicon'] = urljoin(url, str(href))
                    break
        
        return info

    async def analyze_url(self, url: str, fetch_cves: bool = True) -> Dict[str, Any]:
        start_time = time.time()
        url = self._normalize_url(url)
        
        result: Dict[str, Any] = {
            'url': url,
            'final_url': None,
            'success': False,
            'error': None,
            'technologies': [],
            'vulnerabilities': {},
            'security': {},
            'performance': {},
            'page_info': {},
            'analysis_time': 0,
        }
        
        connector = aiohttp.TCPConnector(limit=10, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            html, headers, final_url, cookies = await self._fetch_page(session, url)
            
            if html is None:
                result['error'] = 'Failed to fetch page'
                result['analysis_time'] = round(time.time() - start_time, 2)
                return result
            
            result['final_url'] = final_url
            result['success'] = True
            
            soup = BeautifulSoup(html, 'lxml')
            
            script_srcs, script_contents = self._extract_scripts(soup)
            css_hrefs = self._extract_css(soup)
            meta_tags = self._extract_meta(soup)
            
            context: Dict[str, Any] = {
                'html': html,
                'headers': headers,
                'cookies': cookies,
                'url': final_url if final_url else url,
                'script_srcs': script_srcs,
                'script_contents': script_contents,
                'css_hrefs': css_hrefs,
                'meta_tags': meta_tags,
            }
            
            result['technologies'] = self._detect_technologies(context)
            result['security'] = self._analyze_security_headers(headers)
            result['performance'] = self._analyze_performance(headers, html, soup)
            result['page_info'] = self._get_page_info(soup, final_url if final_url else url)
            
            # Scan endpoints for additional version info
            detected_tech_names = [t['name'] for t in result['technologies']]
            endpoint_versions = await self._scan_endpoints_for_versions(session, final_url if final_url else url, detected_tech_names)
            for i, tech in enumerate(result['technologies']):
                if tech['name'] in endpoint_versions and not tech['version']:
                    result['technologies'][i]['version'] = endpoint_versions[tech['name']]
            
            # Always fetch CVE IDs for technologies and add to each tech
            if self.cve_lookup and fetch_cves:
                cve_ids_by_tech = self._fetch_cve_ids_for_techs(result['technologies'], context)
                for i, tech in enumerate(result['technologies']):
                    tech_name = tech.get('name', '')
                    if tech_name in cve_ids_by_tech:
                        result['technologies'][i]['cves'] = cve_ids_by_tech[tech_name]
                    else:
                        result['technologies'][i]['cves'] = []
            
            if self.enable_cve and self.cve_lookup and fetch_cves:
                result['vulnerabilities'] = self._fetch_cves(result['technologies'], context)
        
        result['analysis_time'] = round(time.time() - start_time, 2)
        return result

    def _fetch_cve_ids_for_techs(self, technologies: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, List[str]]:
        """Fetch just CVE IDs for each technology (lightweight, always runs)"""
        if not self.cve_lookup:
            return {}
        
        cve_ids: Dict[str, List[str]] = {}
        
        for tech in technologies:
            tech_name = tech.get('name', '')
            if not tech_name:
                continue
            
            version = self.cve_lookup.extract_version(tech_name, context)
            cves = self.cve_lookup.search_cves(tech_name, version, max_results=3)
            
            if cves:
                cve_ids[tech_name] = [cve.cve_id for cve in cves]
            else:
                cve_ids[tech_name] = []
        
        return cve_ids

    def _fetch_cves(self, technologies: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
        if not self.cve_lookup:
            return {}
        
        vulnerabilities: Dict[str, Any] = {
            'total_cves': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_technology': {},
        }
        
        for tech in technologies:
            tech_name = tech.get('name', '')
            if not tech_name:
                continue
            
            version = self.cve_lookup.extract_version(tech_name, context)
            
            cves = self.cve_lookup.search_cves(tech_name, version, max_results=5)
            
            if cves:
                tech_cves = []
                for cve in cves:
                    tech_cves.append(format_cve_for_display(cve))
                    vulnerabilities['total_cves'] += 1
                    
                    severity = cve.severity.upper()
                    if severity == 'CRITICAL':
                        vulnerabilities['critical'] += 1
                    elif severity == 'HIGH':
                        vulnerabilities['high'] += 1
                    elif severity == 'MEDIUM':
                        vulnerabilities['medium'] += 1
                    elif severity == 'LOW':
                        vulnerabilities['low'] += 1
                
                vulnerabilities['by_technology'][tech_name] = {
                    'version': version,
                    'cves': tech_cves,
                }
        
        return vulnerabilities

    async def analyze_urls(self, urls: List[str], concurrency: int = 5) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(concurrency)
        
        async def limited_analyze(url: str) -> Dict[str, Any]:
            async with semaphore:
                return await self.analyze_url(url)
        
        tasks = [limited_analyze(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed_results: List[Dict[str, Any]] = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                processed_results.append({
                    'url': urls[i],
                    'success': False,
                    'error': str(res),
                    'technologies': [],
                    'security': {},
                    'performance': {},
                    'page_info': {},
                    'analysis_time': 0,
                })
            elif isinstance(res, dict):
                processed_results.append(res)
        
        return processed_results
