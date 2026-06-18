import os
import re
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import nvdlib
import time


@dataclass
class CVEInfo:
    cve_id: str
    severity: str
    score: float
    description: str
    published: str
    references: List[str]


# Framework-specific endpoints that might reveal version information
FRAMEWORK_ENDPOINTS = {
    "WordPress": [
        r"/wp-json/",
        r"/wp-includes/version.php",
        r"/wp-content/",
        r"/readme.html",
        r"/wp-admin/",
    ],
    "Drupal": [
        r"/admin/",
        r"/modules/",
        r"/sites/",
        r"/profiles/",
        r"/CHANGELOG",
        r"/web/sites/",
    ],
    "Joomla": [
        r"/administrator/",
        r"/components/",
        r"/modules/",
        r"/plugins/",
        r"/templates/",
        r"/CHANGELOG",
    ],
    "Magento": [
        r"/pub/static/",
        r"/pub/media/",
        r"/app/",
        r"/var/",
        r"/lib/",
        r"/setup/",
        r"/admin/",
    ],
    "Laravel": [
        r"/storage/",
        r"/public/",
        r"/app/",
        r"/config/",
        r"/routes/",
        r"/artisan",
    ],
    "Django": [
        r"/admin/",
        r"/static/",
        r"/media/",
        r"/api/",
        r"/__pycache__/",
    ],
    "Flask": [
        r"/static/",
        r"/api/",
        r"/admin/",
        r"/templates/",
    ],
    "Symfony": [
        r"/web/",
        r"/app/",
        r"/src/",
        r"/vendor/",
        r"/bundles/",
    ],
    "ASP.NET": [
        r"/bin/",
        r"/obj/",
        r"/Content/",
        r"/Scripts/",
        r"/Fonts/",
        r"/.well-known/",
    ],
    "Ruby on Rails": [
        r"/app/",
        r"/public/",
        r"/config/",
        r"/Gemfile",
        r"/vendor/",
    ],
    "Ghost": [
        r"/ghost/",
        r"/api/v2/",
        r"/api/v3/",
        r"/content/",
        r"/members/",
    ],
    "WooCommerce": [
        r"/wp-json/wc/",
        r"/wp-content/plugins/woocommerce/",
        r"/shop/",
        r"/product/",
    ],
}

# Version patterns that work across endpoints/responses
ENDPOINT_VERSION_PATTERNS = [
    (r'"version"?\s*:\s*"(\d+\.\d+\.\d+(?:-[a-zA-Z]*\d*)?)"', "version in JSON with patch"),
    (r'"version"?\s*:\s*"([\d.]+)"', "version in JSON"),
    (r'<version>(\d+\.\d+\.\d+(?:-[a-zA-Z]*\d*)?)</version>', "version in XML with patch"),
    (r'<version>([\d.]+)</version>', "version in XML"),
    (r'Version:\s*(\d+\.\d+\.\d+(?:-[a-zA-Z]*\d*)?)', "version in text with patch"),
    (r'Version:\s*([\d.]+)', "version in text"),
    (r'v(\d+\.\d+\.\d+(?:-[a-zA-Z]*\d*)?)', "v-prefixed version with patch"),
    (r'v([\d.]+)', "v-prefixed version"),
    (r'"(\d+\.\d+\.\d+(?:-p\d+)?)"', "quoted version with patch"),
    (r'"(\d+\.\d+(?:\.\d+)?)"', "quoted version string"),
    (r'(\d+\.\d+\.\d+-p\d+)', "semantic version with patch"),
    (r'(\d+\.\d+\.\d+)', "semantic version"),
]

COMMON_ENDPOINTS = [
    "/.well-known/",
    "/admin/",
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/config/",
    "/version",
    "/about",
    "/info",
    "/health",
    "/status",
    "/.git/config",
    "/composer.json",
    "/package.json",
    "/Gemfile",
    "/requirements.txt",
    "/sitemap.xml",
    "/robots.txt",
]

CPE_MAPPING = {
    "jQuery": {"vendor": "jquery", "product": "jquery", "keywords": ["jquery"]},
    "React": {"vendor": "facebook", "product": "react", "keywords": ["react", "reactjs"]},
    "Vue.js": {"vendor": "vuejs", "product": "vue.js", "keywords": ["vue.js", "vuejs"]},
    "Angular": {"vendor": "angular", "product": "angular", "keywords": ["angular", "angularjs"]},
    "Next.js": {"vendor": "vercel", "product": "next.js", "keywords": ["next.js", "nextjs"]},
    "Nuxt.js": {"vendor": "nuxt", "product": "nuxt.js", "keywords": ["nuxt.js", "nuxtjs"]},
    "Express.js": {"vendor": "expressjs", "product": "express", "keywords": ["express", "expressjs"]},
    "Django": {"vendor": "djangoproject", "product": "django", "keywords": ["django"]},
    "Flask": {"vendor": "palletsprojects", "product": "flask", "keywords": ["flask", "pallets"]},
    "Laravel": {"vendor": "laravel", "product": "laravel", "keywords": ["laravel"]},
    "Ruby on Rails": {"vendor": "rubyonrails", "product": "rails", "keywords": ["rails", "ruby on rails"]},
    "WordPress": {"vendor": "wordpress", "product": "wordpress", "keywords": ["wordpress"]},
    "Drupal": {"vendor": "drupal", "product": "drupal", "keywords": ["drupal"]},
    "Joomla": {"vendor": "joomla", "product": "joomla\\!", "keywords": ["joomla"]},
    "Magento": {"vendor": "magento", "product": "magento", "keywords": ["magento"]},
    "Shopify": {"vendor": "shopify", "product": "shopify", "keywords": ["shopify"]},
}

VERSION_PATTERNS = {
    "jQuery": [
        r"ajax\.googleapis\.com/ajax/libs/jquery/(\d+\.\d+\.\d+)",
        r"cdnjs\.cloudflare\.com/ajax/libs/jquery/(\d+\.\d+\.\d+)",
        r"code\.jquery\.com/jquery-(\d+\.\d+\.\d+)",
        r"jquery[/-](\d+\.\d+(?:\.\d+)?)",
        r"jquery\.min\.js\?v=(\d+\.\d+(?:\.\d+)?)",
        r"jQuery\s+v?(\d+\.\d+(?:\.\d+)?)",
    ],
    "Apache": [
        r"[Aa]pache/(\d+\.\d+(?:\.\d+)?)",
        r"Apache HTTP Server[/\s]+(\d+\.\d+(?:\.\d+)?)",
        r"httpd[/-](\d+\.\d+(?:\.\d+)?)",
        r"mod_ssl/(\d+\.\d+(?:\.\d+)?)",
        r"Server:\s*Apache/(\d+\.\d+(?:\.\d+)?)",
    ],
    "Apache Tomcat": [
        r"Apache Tomcat/(\d+\.\d+(?:\.\d+)?)",
        r"[Tt]omcat[/-](\d+\.\d+(?:\.\d+)?)",
        r"Tomcat/(\d+\.\d+(?:\.\d+)?)",
        r"catalina[/-](\d+\.\d+(?:\.\d+)?)",
        r"Server:\s*Apache Tomcat/(\d+\.\d+(?:\.\d+)?)",
    ],
    "Microsoft IIS": [
        r"Microsoft-IIS/(\d+\.\d+)",
        r"IIS[/-](\d+\.\d+)",
        r"Server:\s*Microsoft-IIS/(\d+\.\d+)",
    ],
    "PHP": [
        r"PHP/(\d+\.\d+(?:\.\d+)?)",
        r"[Pp]hp[\s/-](\d+\.\d+(?:\.\d+)?)",
    ],
    "Nginx": [
        r"nginx/(\d+\.\d+(?:\.\d+)?)",
        r"[Nn]ginx[\s/-](\d+\.\d+(?:\.\d+)?)",
    ],
    "Node.js": [
        r"node[/-]v?(\d+\.\d+(?:\.\d+)?)",
        r"Node\.js[/-]v?(\d+\.\d+(?:\.\d+)?)",
    ],
    "React": [
        r"react[/-](\d+\.\d+(?:\.\d+)?)",
        r"React\.version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]",
    ],
    "Next.js": [
        r"next[/-](\d+\.\d+(?:\.\d+)?)",
        r'"next":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
    ],
    "WordPress": [
        r"WordPress\s+(\d+\.\d+(?:\.\d+)?)",
        r"wp-includes.*?ver=(\d+\.\d+(?:\.\d+)?)",
    ],
}


class CVELookup:
    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 3600):
        self.api_key = api_key or os.environ.get('NVD_API_KEY')
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_request = 0.0
        self._rate_limit_delay = 6.0 if not self.api_key else 0.6
        self._executor = ThreadPoolExecutor(max_workers=2)

    def _get_cache_key(self, tech: str, version: Optional[str]) -> str:
        return f"{tech}:{version or 'all'}"

    def _is_cache_valid(self, cache_key: str) -> bool:
        if cache_key not in self._cache:
            return False
        entry = self._cache[cache_key]
        return time.time() - entry['timestamp'] < self.cache_ttl

    def extract_version(self, tech_name: str, context: Dict[str, Any]) -> Optional[str]:
        if tech_name not in VERSION_PATTERNS:
            return None
        
        patterns = VERSION_PATTERNS[tech_name]
        search_content: List[str] = []
        search_content.extend(str(s) for s in context.get('script_srcs', []))
        search_content.extend(str(s) for s in context.get('script_contents', []))
        search_content.extend(str(s) for s in context.get('css_hrefs', []))
        search_content.append(str(context.get('html', '')))
        
        headers = context.get('headers', {})
        for header_value in headers.values():
            search_content.append(str(header_value))
        
        full_content = ' '.join(search_content)
        
        for pattern in patterns:
            match = re.search(pattern, full_content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

    def _is_relevant_cve(self, cve: Any, tech_name: str, cpe_info: Optional[Dict[str, Any]]) -> bool:
        if not cpe_info:
            return True
        
        keywords = cpe_info.get('keywords', [])
        vendor = cpe_info.get('vendor', '').lower()
        product = cpe_info.get('product', '').lower().replace('\\!', '')
        
        description = ""
        if hasattr(cve, 'descriptions') and cve.descriptions:
            for desc in cve.descriptions:
                if hasattr(desc, 'lang') and desc.lang == 'en':
                    description = desc.value.lower()
                    break
            if not description and cve.descriptions:
                description = cve.descriptions[0].value.lower()
        
        if hasattr(cve, 'cpe') and cve.cpe:
            for cpe_match in cve.cpe:
                if hasattr(cpe_match, 'criteria'):
                    criteria = cpe_match.criteria.lower()
                    if vendor in criteria or product in criteria:
                        return True
        
        for keyword in keywords:
            if keyword.lower() in description:
                return True
        
        if vendor in description or product in description:
            return True
        
        return False

    def _search_cves_sync(self, tech_name: str, version: Optional[str] = None, 
                          max_results: int = 5) -> List[CVEInfo]:
        cache_key = self._get_cache_key(tech_name, version)
        
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]['data']
        
        cves: List[CVEInfo] = []
        cpe_info = CPE_MAPPING.get(tech_name)
        
        if not cpe_info:
            self._cache[cache_key] = {'data': [], 'timestamp': time.time()}
            return []
        
        try:
            # Rate limiting
            elapsed = time.time() - self._last_request
            if elapsed < self._rate_limit_delay:
                time.sleep(self._rate_limit_delay - elapsed)
            self._last_request = time.time()
            
            cpe_string = f"cpe:2.3:a:{cpe_info['vendor']}:{cpe_info['product']}"
            if version:
                cpe_string += f":{version}"
            else:
                cpe_string += ":*"
            cpe_string += ":*:*:*:*:*:*:*"
            
            results = []
            try:
                if self.api_key:
                    results = list(nvdlib.searchCVE(
                        cpeName=cpe_string,
                        limit=max_results * 2,
                        key=self.api_key
                    ))
                else:
                    results = list(nvdlib.searchCVE(
                        cpeName=cpe_string,
                        limit=max_results * 2
                    ))
            except Exception as e:
                # Fallback: try keyword search if CPE fails
                try:
                    keyword = f"{tech_name} {version or ''}".strip()
                    if self.api_key:
                        results = list(nvdlib.searchCVE(
                            keywordSearch=keyword,
                            limit=max_results,
                            key=self.api_key
                        ))
                    else:
                        results = list(nvdlib.searchCVE(
                            keywordSearch=keyword,
                            limit=max_results
                        ))
                except:
                    pass
            
            for cve in results:
                if len(cves) >= max_results:
                    break
                if not self._is_relevant_cve(cve, tech_name, cpe_info):
                    continue
                
                try:
                    severity = "UNKNOWN"
                    score = 0.0
                    
                    if hasattr(cve, 'v31severity') and cve.v31severity:
                        severity = cve.v31severity
                        score = float(cve.v31score) if hasattr(cve, 'v31score') and cve.v31score else 0.0
                    elif hasattr(cve, 'v30severity') and cve.v30severity:
                        severity = cve.v30severity
                        score = float(cve.v30score) if hasattr(cve, 'v30score') and cve.v30score else 0.0
                    elif hasattr(cve, 'v2severity') and cve.v2severity:
                        severity = cve.v2severity
                        score = float(cve.v2score) if hasattr(cve, 'v2score') and cve.v2score else 0.0
                    
                    description = ""
                    if hasattr(cve, 'descriptions') and cve.descriptions:
                        for desc in cve.descriptions:
                            if hasattr(desc, 'lang') and desc.lang == 'en':
                                description = desc.value
                                break
                        if not description and cve.descriptions:
                            description = cve.descriptions[0].value
                    
                    refs: List[str] = []
                    if hasattr(cve, 'references') and cve.references:
                        refs = [ref.url for ref in cve.references[:3] if hasattr(ref, 'url')]
                    
                    published = ""
                    if hasattr(cve, 'published'):
                        published = str(cve.published)[:10]
                    
                    cves.append(CVEInfo(
                        cve_id=cve.id,
                        severity=severity,
                        score=score,
                        description=description[:300] + "..." if len(description) > 300 else description,
                        published=published,
                        references=refs
                    ))
                except:
                    continue
            
            cves.sort(key=lambda x: (-x.score, x.cve_id))
            self._cache[cache_key] = {'data': cves, 'timestamp': time.time()}
            
        except Exception:
            self._cache[cache_key] = {'data': [], 'timestamp': time.time()}
        
        return cves

    def search_cves(self, tech_name: str, version: Optional[str] = None, 
                    max_results: int = 5) -> List[CVEInfo]:
        return self._search_cves_sync(tech_name, version, max_results)

    async def search_cves_async(self, tech_name: str, version: Optional[str] = None,
                                max_results: int = 5) -> List[CVEInfo]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._search_cves_sync,
            tech_name,
            version,
            max_results
        )


def get_severity_color(severity: str) -> str:
    severity_colors = {
        'CRITICAL': 'red',
        'HIGH': 'red',
        'MEDIUM': 'yellow',
        'LOW': 'green',
        'UNKNOWN': 'dim',
    }
    return severity_colors.get(severity.upper(), 'white')


def format_cve_for_display(cve: CVEInfo) -> Dict[str, Any]:
    return {
        'id': cve.cve_id,
        'severity': cve.severity,
        'score': cve.score,
        'description': cve.description,
        'published': cve.published,
        'references': cve.references,
    }
