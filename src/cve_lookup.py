import os
import re
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import nvdlib
import requests
import time


@dataclass
class CVEInfo:
    cve_id: str
    severity: str
    score: float
    description: str
    published: str
    references: List[str]


FRAMEWORK_ENDPOINTS = {
    "WordPress": [r"/wp-json/", r"/wp-includes/version.php", r"/readme.html"],
    "Drupal": [r"/CHANGELOG", r"/admin/"],
    "Joomla": [r"/administrator/", r"/CHANGELOG"],
    "Magento": [r"/pub/static/", r"/app/etc/"],
    "Laravel": [r"/composer.json"],
}

ENDPOINT_VERSION_PATTERNS = [
    (r'"version"?\s*:\s*"(\d+\.\d+\.\d+(?:-[a-zA-Z]*\d*)?)"', "version"),
    (r'Version:\s*(\d+\.\d+\.\d+(?:-[a-zA-Z]*\d*)?)', "version"),
    (r'v(\d+\.\d+\.\d+(?:-[a-zA-Z]*\d*)?)', "version"),
    (r'(\d+\.\d+\.\d+)', "version"),
]

COMMON_ENDPOINTS = ["/version", "/about", "/api/", "/robots.txt"]

CPE_MAPPING = {
    "jQuery": {"vendor": "jquery", "product": "jquery"},
    "React": {"vendor": "facebook", "product": "react"},
    "Next.js": {"vendor": "vercel", "product": "next.js"},
    "Vue.js": {"vendor": "vuejs", "product": "vue.js"},
    "Angular": {"vendor": "angular", "product": "angular"},
    "Express.js": {"vendor": "expressjs", "product": "express"},
    "Django": {"vendor": "djangoproject", "product": "django"},
    "Laravel": {"vendor": "laravel", "product": "laravel"},
    "WordPress": {"vendor": "wordpress", "product": "wordpress"},
    "Nginx": {"vendor": "f5", "product": "nginx"},
    "Apache": {"vendor": "apache", "product": "http_server"},
    "PHP": {"vendor": "php", "product": "php"},
}

VERSION_PATTERNS = {
    "jQuery": [r"jquery[/-](\d+\.\d+(?:\.\d+)?)"],
    "React": [r"react[/-](\d+\.\d+(?:\.\d+)?)"],
    "Next.js": [r"next[/-](\d+\.\d+(?:\.\d+)?)"],
    "Vue.js": [r"vue[/-](\d+\.\d+(?:\.\d+)?)"],
    "Angular": [r"angular[/-](\d+\.\d+(?:\.\d+)?)"],
    "Express.js": [r"express[/-](\d+\.\d+(?:\.\d+)?)"],
    "Django": [r"django[/-](\d+\.\d+(?:\.\d+)?)"],
    "Laravel": [r"laravel[/-](\d+\.\d+(?:\.\d+)?)"],
    "WordPress": [r"WordPress\s+(\d+\.\d+(?:\.\d+)?)"],
    "Nginx": [r"nginx/(\d+\.\d+(?:\.\d+)?)"],
    "Apache": [r"Apache/(\d+\.\d+(?:\.\d+)?)"],
    "PHP": [r"PHP/(\d+\.\d+(?:\.\d+)?)"],
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
        return time.time() - self._cache[cache_key]['timestamp'] < self.cache_ttl

    def extract_version(self, tech_name: str, context: Dict[str, Any]) -> Optional[str]:
        if tech_name not in VERSION_PATTERNS:
            return None
        patterns = VERSION_PATTERNS[tech_name]
        search_content = []
        search_content.extend(str(s) for s in context.get('script_srcs', []))
        search_content.extend(str(s) for s in context.get('script_contents', []))
        search_content.append(str(context.get('html', '')))
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
        if hasattr(cve, 'cpe') and cve.cpe:
            for cpe_match in cve.cpe:
                if hasattr(cpe_match, 'criteria'):
                    if vendor in cpe_match.criteria.lower() or product in cpe_match.criteria.lower():
                        return True
        for keyword in keywords:
            if keyword.lower() in description:
                return True
        return False

    # ==================== OSV.dev Integration ====================
    def _query_osv(self, package_name: str, version: str, ecosystem: str = "npm") -> List[Dict]:
        try:
            url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {"name": package_name, "ecosystem": ecosystem},
                "version": version
            }
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                return response.json().get("vulns", [])
        except:
            pass
        return []

    def _get_osv_severity(self, osv_vuln: Dict) -> tuple:
        """Extract severity and score from OSV response"""
        severity = "UNKNOWN"
        score = 0.0

        if "severity" in osv_vuln and isinstance(osv_vuln["severity"], list):
            for sev in osv_vuln["severity"]:
                if isinstance(sev, dict):
                    sev_type = sev.get("type", "")
                    score_str = sev.get("score", "")

                    # Try to extract numeric score from CVSS vector
                    if "CVSS" in sev_type and score_str:
                        # OSV often returns full CVSS vector. Try to parse base score if present.
                        # For simplicity, we map common high-impact vectors
                        if "AV:N" in score_str and ("C:H" in score_str or "I:H" in score_str):
                            severity = "CRITICAL"
                            score = 9.0
                        elif "AV:N" in score_str:
                            severity = "HIGH"
                            score = 7.5
                        elif "AV:L" in score_str or "AV:A" in score_str:
                            severity = "MEDIUM"
                            score = 5.0
                        else:
                            severity = "MEDIUM"
                            score = 5.0
                        break
        return severity, score

    def _convert_osv_to_cve(self, osv_vuln: Dict) -> Optional[CVEInfo]:
        try:
            cve_id = osv_vuln.get("id", "OSV-?")
            summary = osv_vuln.get("summary", "") or ""
            details = osv_vuln.get("details", "") or ""
            description = (summary + ". " + details)[:300]

            severity, score = self._get_osv_severity(osv_vuln)

            published = osv_vuln.get("published", "")[:10] if osv_vuln.get("published") else ""

            refs = []
            for ref in osv_vuln.get("references", [])[:3]:
                if isinstance(ref, dict):
                    refs.append(ref.get("url", ""))

            return CVEInfo(
                cve_id=cve_id,
                severity=severity,
                score=score,
                description=description,
                published=published,
                references=refs
            )
        except:
            return None

    def _search_cves_sync(self, tech_name: str, version: Optional[str] = None, 
                          max_results: int = 5) -> List[CVEInfo]:
        cache_key = self._get_cache_key(tech_name, version)
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]['data']
        
        cves: List[CVEInfo] = []
        cpe_info = CPE_MAPPING.get(tech_name)
        
        # NVD
        if cpe_info:
            try:
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
                        results = list(nvdlib.searchCVE(cpeName=cpe_string, limit=max_results*2, key=self.api_key))
                    else:
                        results = list(nvdlib.searchCVE(cpeName=cpe_string, limit=max_results*2))
                except:
                    pass
                
                for cve in results:
                    if len(cves) >= max_results: break
                    if not self._is_relevant_cve(cve, tech_name, cpe_info): continue
                    try:
                        severity = "UNKNOWN"
                        score = 0.0
                        if hasattr(cve, 'v31severity') and cve.v31severity:
                            severity = cve.v31severity
                            score = float(cve.v31score) if hasattr(cve, 'v31score') else 0.0
                        elif hasattr(cve, 'v30severity') and cve.v30severity:
                            severity = cve.v30severity
                            score = float(cve.v30score) if hasattr(cve, 'v30score') else 0.0
                        
                        description = ""
                        if hasattr(cve, 'descriptions') and cve.descriptions:
                            for desc in cve.descriptions:
                                if hasattr(desc, 'lang') and desc.lang == 'en':
                                    description = desc.value
                                    break
                        refs = []
                        if hasattr(cve, 'references') and cve.references:
                            refs = [ref.url for ref in cve.references[:3] if hasattr(ref, 'url')]
                        published = str(getattr(cve, 'published', ''))[:10]
                        
                        cves.append(CVEInfo(cve_id=cve.id, severity=severity, score=score,
                                            description=description[:300], published=published, references=refs))
                    except:
                        continue
            except:
                pass
        
        # OSV.dev
        if version and len(cves) < max_results:
            try:
                ecosystem_map = {
                    "React": ("react", "npm"),
                    "Vue.js": ("vue", "npm"),
                    "Angular": ("angular", "npm"),
                    "Next.js": ("next", "npm"),
                    "Express.js": ("express", "npm"),
                    "Lodash": ("lodash", "npm"),
                    "Django": ("django", "PyPI"),
                    "Flask": ("flask", "PyPI"),
                }
                if tech_name in ecosystem_map:
                    pkg_name, ecosystem = ecosystem_map[tech_name]
                    osv_results = self._query_osv(pkg_name, version, ecosystem)
                    for osv_vuln in osv_results:
                        if len(cves) >= max_results: break
                        cve_info = self._convert_osv_to_cve(osv_vuln)
                        if cve_info:
                            cves.append(cve_info)
            except:
                pass
        
        cves.sort(key=lambda x: (-x.score, x.cve_id))
        self._cache[cache_key] = {'data': cves, 'timestamp': time.time()}
        return cves

    def search_cves(self, tech_name: str, version: Optional[str] = None, max_results: int = 5) -> List[CVEInfo]:
        return self._search_cves_sync(tech_name, version, max_results)

    async def search_cves_async(self, tech_name: str, version: Optional[str] = None, max_results: int = 5) -> List[CVEInfo]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._search_cves_sync, tech_name, version, max_results)


def get_severity_color(severity: str) -> str:
    return {'CRITICAL': 'red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green'}.get(severity.upper(), 'dim')


def format_cve_for_display(cve: CVEInfo) -> Dict[str, Any]:
    return {
        'id': cve.cve_id,
        'severity': cve.severity,
        'score': cve.score,
        'description': cve.description,
        'published': cve.published,
        'references': cve.references,
    }
