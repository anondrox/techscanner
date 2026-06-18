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
from .cve_lookup import CVELookup


class TechDetector:
    def __init__(self, timeout: int = 25, max_retries: int = 2, 
                  enable_cve: bool = False, nvd_api_key: Optional[str] = None,
                  stealth_mode: bool = True,
                  min_confidence: float = 0.70,
                  enable_graphql_recon: bool = True):
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
        ]

        # Common GraphQL types/fields for light Clairvoyance-style inference
        self.graphql_common_fields = [
            "id", "_id", "uuid", "name", "email", "username", "password", "token",
            "user", "users", "me", "profile", "account", "admin", "role",
            "query", "mutation", "subscription",
            "createdAt", "updatedAt", "status", "active",
            "product", "products", "order", "orders", "cart",
            "login", "logout", "register"
        ]

    def _get_headers(self) -> Dict[str, str]:
        ua = random.choice(self.user_agents)
        return {
            "User-Agent": ua,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    async def _stealth_delay(self):
        if self.stealth_mode:
            await asyncio.sleep(random.uniform(1.2, 3.5))

    async def _fetch_page(self, session: aiohttp.ClientSession, url: str):
        for attempt in range(self.max_retries):
            try:
                await self._stealth_delay()
                ssl_context = ssl.create_default_context(cafile=certifi.where())
                async with session.get(url, headers=self._get_headers(), timeout=aiohttp.ClientTimeout(total=self.timeout), ssl=ssl_context) as response:
                    return await response.text(), {k.lower(): v for k, v in response.headers.items()}, str(response.url), []
            except:
                if attempt == self.max_retries - 1:
                    return None, {}, None, []
                await asyncio.sleep(2)
        return None, {}, None, []

    async def _post_graphql(self, session: aiohttp.ClientSession, endpoint: str, query: str):
        try:
            await self._stealth_delay()
            headers = self._get_headers()
            headers["Content-Type"] = "application/json"
            async with session.post(endpoint, json={"query": query}, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
        except:
            pass
        return None

    async def detect_graphql_introspection(self, session: aiohttp.ClientSession, base_url: str) -> Dict[str, Any]:
        """GraphQL detection + Clairvoyance-lite (introspection + field inference)"""
        result = {
            "detected": False,
            "introspection_enabled": False,
            "endpoint": None,
            "schema_hints": [],
            "risk_level": "Low"
        }

        common_endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query']

        # Step 1: Try standard introspection
        introspection_query = """{ __schema { queryType { name } mutationType { name } types { name kind } } }"""

        for endpoint in common_endpoints:
            full_url = urljoin(base_url, endpoint)
            data = await self._post_graphql(session, full_url, introspection_query)

            if data and "data" in data and data.get("data"):
                result.update({
                    "detected": True,
                    "introspection_enabled": True,
                    "endpoint": endpoint,
                    "risk_level": "High"
                })
                schema = data["data"].get("__schema", {})
                types = [t["name"] for t in schema.get("types", []) if t.get("name") and not t["name"].startswith("__")]
                result["schema_hints"] = types[:12]
                return result

        # Step 2: If introspection disabled → Light Clairvoyance (field inference)
        if self.enable_graphql_recon:
            for endpoint in common_endpoints:
                full_url = urljoin(base_url, endpoint)
                inferred = await self._light_graphql_field_inference(session, full_url)
                if inferred:
                    result.update({
                        "detected": True,
                        "endpoint": endpoint,
                        "schema_hints": inferred,
                        "risk_level": "Medium"
                    })
                    break

        return result

    async def _light_graphql_field_inference(self, session: aiohttp.ClientSession, endpoint: str) -> List[str]:
        """Lightweight schema inference when introspection is disabled"""
        discovered = set()

        # Test common root queries
        test_queries = [
            "{ __typename }",
            "{ me { id name email } }",
            "{ user(id: \"1\") { id email } }",
            "{ users { id } }",
            "{ products { id name } }"
        ]

        for query in test_queries:
            data = await self._post_graphql(session, endpoint, query)
            if not data:
                continue

            if "errors" in data:
                for err in data.get("errors", []):
                    msg = str(err.get("message", "")).lower()
                    for field in self.graphql_common_fields:
                        if field in msg:
                            discovered.add(field)

            elif "data" in data and data["data"]:
                discovered.add("__typename")

        return list(discovered)[:10]

    def _detect_technologies(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        detected = []
        for category, technologies in FINGERPRINTS.items():
            for tech_name, tech_info in technologies.items():
                matches = 0
                total_confidence = 0.0
                for pattern_info in tech_info.get("patterns", []):
                    matched, confidence = self._check_pattern(pattern_info, context)
                    if matched:
                        matches += 1
                        total_confidence += confidence

                if matches > 0:
                    avg = total_confidence / matches
                    if matches >= 2 or avg >= 0.90:
                        if avg >= self.min_confidence:
                            detected.append({
                                "name": tech_name,
                                "category": tech_info.get("category", category),
                                "confidence": round(avg, 2),
                                "matches": matches
                            })
        return sorted(detected, key=lambda x: -x["confidence"])

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        start_time = time.time()
        result = {
            "url": url,
            "success": False,
            "technologies": [],
            "graphql": {},
            "analysis_time": 0
        }

        try:
            async with aiohttp.ClientSession() as session:
                html, headers, final_url, _ = await self._fetch_page(session, self._normalize_url(url))
                if not html:
                    result["error"] = "Failed to fetch"
                    return result

                soup = BeautifulSoup(html, "lxml")
                context = {
                    "html": html,
                    "headers": headers,
                    "script_srcs": [s.get("src") for s in soup.find_all("script") if s.get("src")],
                    "script_contents": [s.string for s in soup.find_all("script") if s.string],
                    "url": final_url
                }

                technologies = self._detect_technologies(context)
                result["technologies"] = technologies

                # GraphQL + Clairvoyance
                has_graphql = any("graphql" in t["category"].lower() for t in technologies)
                if has_graphql or any(p in html.lower() for p in ["/graphql", "graphql"]):
                    result["graphql"] = await self.detect_graphql_introspection(session, final_url)

                result["success"] = True
                result["analysis_time"] = round(time.time() - start_time, 2)

        except Exception as e:
            result["error"] = str(e)

        return result

    async def analyze_urls(self, urls: List[str], concurrency: int = 2):
        sem = asyncio.Semaphore(concurrency)
        async def task(u):
            async with sem:
                return await self.analyze_url(u)
        return await asyncio.gather(*[task(u) for u in urls])
