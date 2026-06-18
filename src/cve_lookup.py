import os
import re
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import nvdlib
import requests
import time
import math


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

    # ==================== CVSS v3.1 + v4.0 Support ====================
    def _parse_cvss_vector(self, vector: str) -> Dict[str, str]:
        metrics = {}
        if not vector or not vector.startswith("CVSS:"):
            return metrics
        try:
            parts = vector.split("/")
            for part in parts[1:]:
                if ":" in part:
                    key, value = part.split(":", 1)
                    metrics[key.upper()] = value.upper()
        except:
            pass
        return metrics

    def _calculate_cvss_base_score(self, metrics: Dict[str, str]) -> tuple:
        """CVSS v3.1 Base Score calculation"""
        if not metrics:
            return 0.0, "UNKNOWN"

        AV = metrics.get('AV', 'N')
        AC = metrics.get('AC', 'L')
        PR = metrics.get('PR', 'N')
        UI = metrics.get('UI', 'N')
        S  = metrics.get('S', 'U')
        C  = metrics.get('C', 'N')
        I  = metrics.get('I', 'N')
        A  = metrics.get('A', 'N')

        av_values = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        ac_values = {'L': 0.77, 'H': 0.44}
        ui_values = {'N': 0.85, 'R': 0.62}
        pr_values = {'N': {'U': 0.85, 'C': 0.68}, 'L': {'U': 0.62, 'C': 0.68}, 'H': {'U': 0.27, 'C': 0.50}}

        exploitability = 8.22 * av_values.get(AV, 0.85) * ac_values.get(AC, 0.77) * \
                         pr_values.get(PR, pr_values['N']).get(S, 0.85) * ui_values.get(UI, 0.85)

        cia_values = {'N': 0.0, 'L': 0.22, 'H': 0.56}
        iss = 1 - ((1 - cia_values.get(C, 0)) * (1 - cia_values.get(I, 0)) * (1 - cia_values.get(A, 0)))

        if S == 'U':
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

        if impact <= 0:
            base_score = 0.0
        else:
            if S == 'U':
                base_score = min(math.ceil(min(impact + exploitability, 10) * 10) / 10, 10)
            else:
                base_score = min(math.ceil(min(1.08 * (impact + exploitability), 10) * 10) / 10, 10)

        if base_score >= 9.0: severity = "CRITICAL"
        elif base_score >= 7.0: severity = "HIGH"
        elif base_score >= 4.0: severity = "MEDIUM"
        elif base_score > 0: severity = "LOW"
        else: severity = "NONE"

        return round(base_score, 1), severity

    def _calculate_cvss_v4_score(self, metrics: Dict[str, str]) -> tuple:
        """Simplified but practical CVSS v4.0 scoring"""
        if not metrics:
            return 0.0, "UNKNOWN"

        # Key v4.0 metrics
        AV = metrics.get('AV', 'N')
        AC = metrics.get('AC', 'L')
        AT = metrics.get('AT', 'N')      # Attack Requirements (new in v4)
        PR = metrics.get('PR', 'N')
        UI = metrics.get('UI', 'N')
        VC = metrics.get('VC', 'N')      # Vulnerable System Confidentiality
        VI = metrics.get('VI', 'N')
        VA = metrics.get('VA', 'N')
        SC = metrics.get('SC', 'N')      # Subsequent System Confidentiality
        SI = metrics.get('SI', 'N')
        SA = metrics.get('SA', 'N')

        # Base scoring logic for v4.0 (simplified but effective)
        score = 0.0

        # Attack Vector weight
        if AV == 'N': score += 3.5
        elif AV == 'A': score += 2.8
        elif AV == 'L': score += 2.0
        else: score += 1.0

        # Attack Complexity + Requirements
        if AC == 'L' and AT == 'N': score += 2.5
        elif AC == 'H' or AT == 'P': score += 1.5

        # Privileges Required
        if PR == 'N': score += 2.0
        elif PR == 'L': score += 1.3
        else: score += 0.7

        # User Interaction
        if UI == 'N': score += 1.5
        elif UI == 'P': score += 0.8

        # Impact (Vulnerable + Subsequent systems)
        impact = 0
        for val in [VC, VI, VA, SC, SI, SA]:
            if val == 'H': impact += 1.8
            elif val == 'L': impact += 1.0

        score += impact

        # Normalize to 0-10 scale
        base_score = min(max(score, 0), 10)

        # Severity mapping (aligned with v4.0 guidance)
        if base_score >= 9.0: severity = "CRITICAL"
        elif base_score >= 7.0: severity = "HIGH"
        elif base_score >= 4.0: severity = "MEDIUM"
        else: severity = "LOW"

        return round(base_score, 1), severity

    def _get_osv_severity(self, osv_vuln: Dict) -> tuple:
        """Detect CVSS version and calculate score accordingly"""
        severity = "UNKNOWN"
        score = 0.0

        if "severity" not in osv_vuln or not isinstance(osv_vuln["severity"], list):
            return severity, score

        for sev in osv_vuln["severity"]:
            if not isinstance(sev, dict): continue

            sev_type = sev.get("type", "")
            score_str = sev.get("score", "")

            if "CVSS" not in sev_type or not score_str: continue

            metrics = self._parse_cvss_vector(score_str)
            if not metrics: continue

            if "4.0" in sev_type:
                score, severity = self._calculate_cvss_v4_score(metrics)
            else:
                score, severity = self._calculate_cvss_base_score(metrics)

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
