import os
import re
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import nvdlib


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
# Enhanced to capture patch versions like 2.4.5-p10, 1.0.0-alpha1, etc.
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

# Common top-level endpoints to check (framework-agnostic)
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
    "Bootstrap": {"vendor": "getbootstrap", "product": "bootstrap", "keywords": ["bootstrap", "getbootstrap", "twbs"]},
    "Tailwind CSS": {"vendor": "tailwindcss", "product": "tailwindcss", "keywords": ["tailwind", "tailwindcss"]},
    "Nginx": {"vendor": "f5", "product": "nginx", "keywords": ["nginx"]},
    "Apache": {"vendor": "apache", "product": "http_server", "keywords": ["apache http", "httpd", "apache server"]},
    "Apache Tomcat": {"vendor": "apache", "product": "tomcat", "keywords": ["tomcat", "apache tomcat", "catalina"]},
    "Microsoft IIS": {"vendor": "microsoft", "product": "internet_information_services", "keywords": ["iis", "internet information services"]},
    "Java": {"vendor": "oracle", "product": "jdk", "keywords": ["java", "jdk", "jre"]},
    "JSP": {"vendor": "oracle", "product": "javaserver_pages", "keywords": ["jsp", "javaserver pages"]},
    "JBoss": {"vendor": "redhat", "product": "jboss_enterprise_application_platform", "keywords": ["jboss", "jboss eap"]},
    "WebLogic": {"vendor": "oracle", "product": "weblogic_server", "keywords": ["weblogic", "oracle weblogic"]},
    "WebSphere": {"vendor": "ibm", "product": "websphere_application_server", "keywords": ["websphere"]},
    "GlassFish": {"vendor": "oracle", "product": "glassfish", "keywords": ["glassfish"]},
    "Jetty": {"vendor": "eclipse", "product": "jetty", "keywords": ["jetty", "eclipse jetty"]},
    "PHP": {"vendor": "php", "product": "php", "keywords": ["php"]},
    "ASP.NET": {"vendor": "microsoft", "product": ".net_framework", "keywords": ["asp.net", "aspnet", ".net"]},
    "ASP Classic": {"vendor": "microsoft", "product": "active_server_pages", "keywords": ["asp", "active server pages"]},
    "ColdFusion": {"vendor": "adobe", "product": "coldfusion", "keywords": ["coldfusion", "cfml"]},
    "Perl": {"vendor": "perl", "product": "perl", "keywords": ["perl"]},
    "Python": {"vendor": "python", "product": "python", "keywords": ["python"]},
    "Node.js": {"vendor": "nodejs", "product": "node.js", "keywords": ["node.js", "nodejs"]},
    "OpenSSL": {"vendor": "openssl", "product": "openssl", "keywords": ["openssl", "ssl"]},
    "mod_ssl": {"vendor": "apache", "product": "mod_ssl", "keywords": ["mod_ssl"]},
    "LiteSpeed": {"vendor": "litespeedtech", "product": "litespeed_web_server", "keywords": ["litespeed"]},
    "HAProxy": {"vendor": "haproxy", "product": "haproxy", "keywords": ["haproxy"]},
    "Caddy": {"vendor": "caddyserver", "product": "caddy", "keywords": ["caddy", "caddyserver"]},
    "Spring": {"vendor": "vmware", "product": "spring_framework", "keywords": ["spring framework", "springframework"]},
    "Lodash": {"vendor": "lodash", "product": "lodash", "keywords": ["lodash"]},
    "Moment.js": {"vendor": "momentjs", "product": "moment", "keywords": ["moment.js", "momentjs"]},
    "Axios": {"vendor": "axios", "product": "axios", "keywords": ["axios"]},
    "Socket.io": {"vendor": "socket", "product": "socket.io", "keywords": ["socket.io"]},
    "Sentry": {"vendor": "sentry", "product": "sentry", "keywords": ["sentry"]},
    "Stripe": {"vendor": "stripe", "product": "stripe.js", "keywords": ["stripe"]},
    "D3.js": {"vendor": "d3", "product": "d3.js", "keywords": ["d3.js", "d3js"]},
    "Three.js": {"vendor": "threejs", "product": "three.js", "keywords": ["three.js", "threejs"]},
    "Chart.js": {"vendor": "chartjs", "product": "chart.js", "keywords": ["chart.js", "chartjs"]},
    "Backbone.js": {"vendor": "backbonejs", "product": "backbone.js", "keywords": ["backbone.js", "backbonejs"]},
    "Ember.js": {"vendor": "emberjs", "product": "ember.js", "keywords": ["ember.js", "emberjs"]},
    "Svelte": {"vendor": "svelte", "product": "svelte", "keywords": ["svelte"]},
    "Preact": {"vendor": "preactjs", "product": "preact", "keywords": ["preact"]},
    "Alpine.js": {"vendor": "alpinejs", "product": "alpine.js", "keywords": ["alpine.js", "alpinejs"]},
    "Bulma": {"vendor": "jgthms", "product": "bulma", "keywords": ["bulma css"]},
    "Foundation": {"vendor": "zurb", "product": "foundation", "keywords": ["foundation", "zurb"]},
    "Semantic UI": {"vendor": "semantic-ui", "product": "semantic-ui", "keywords": ["semantic-ui", "semantic ui"]},
    "UIKit": {"vendor": "yootheme", "product": "uikit", "keywords": ["uikit", "yootheme"]},
    "Materialize": {"vendor": "materializecss", "product": "materialize", "keywords": ["materialize", "materializecss"]},
    "Ghost": {"vendor": "ghost", "product": "ghost", "keywords": ["ghost cms"]},
    "Hugo": {"vendor": "gohugoio", "product": "hugo", "keywords": ["hugo", "gohugo"]},
    "Jekyll": {"vendor": "jekyllrb", "product": "jekyll", "keywords": ["jekyll"]},
    "Gatsby": {"vendor": "gatsbyjs", "product": "gatsby", "keywords": ["gatsby", "gatsbyjs"]},
    "WooCommerce": {"vendor": "woocommerce", "product": "woocommerce", "keywords": ["woocommerce"]},
    "Handlebars.js": {"vendor": "handlebarsjs", "product": "handlebars", "keywords": ["handlebars", "handlebarsjs"]},
    "CryptoJS": {"vendor": "cryptojs", "product": "crypto-js", "keywords": ["crypto-js", "cryptojs"]},
}

VERSION_PATTERNS = {
    "jQuery": [
        r"ajax\.googleapis\.com/ajax/libs/jquery/(\d+\.\d+\.\d+)",
        r"cdnjs\.cloudflare\.com/ajax/libs/jquery/(\d+\.\d+\.\d+)",
        r"code\.jquery\.com/jquery-(\d+\.\d+\.\d+)",
        r"jquery[/-](\d+\.\d+(?:\.\d+)?)",
        r"jquery\.min\.js\?v=(\d+\.\d+(?:\.\d+)?)",
        r"jQuery\s+v?(\d+\.\d+(?:\.\d+)?)",
        r"jQuery,\s*(\d+\.\d+(?:\.\d+)?)",
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
    "Java": [
        r"Java/(\d+\.\d+(?:\.\d+)?(?:_\d+)?)",
        r"JDK[/-](\d+\.\d+(?:\.\d+)?)",
        r"Java\s+SE\s+(\d+(?:\.\d+)?)",
        r"OpenJDK[/-](\d+\.\d+(?:\.\d+)?)",
        r"java\.version.*?(\d+\.\d+(?:\.\d+)?)",
    ],
    "JBoss": [
        r"JBoss[/-](\d+\.\d+(?:\.\d+)?)",
        r"JBoss EAP[/-](\d+\.\d+(?:\.\d+)?)",
        r"WildFly/(\d+\.\d+(?:\.\d+)?)",
    ],
    "WebLogic": [
        r"WebLogic[/-](\d+\.\d+(?:\.\d+)?)",
        r"WebLogic Server\s+(\d+\.\d+(?:\.\d+)?)",
    ],
    "WebSphere": [
        r"WebSphere[/-](\d+\.\d+(?:\.\d+)?)",
        r"WebSphere Application Server\s+(\d+\.\d+(?:\.\d+)?)",
    ],
    "GlassFish": [
        r"GlassFish[/-](\d+\.\d+(?:\.\d+)?)",
        r"GlassFish Server\s+(\d+\.\d+(?:\.\d+)?)",
    ],
    "Jetty": [
        r"Jetty[/\(](\d+\.\d+(?:\.\d+)?)",
        r"Eclipse Jetty[/-](\d+\.\d+(?:\.\d+)?)",
    ],
    "ASP.NET": [
        r"X-AspNet-Version:\s*(\d+\.\d+(?:\.\d+)?)",
        r"X-AspNetMvc-Version:\s*(\d+\.\d+(?:\.\d+)?)",
        r"\.NET Framework[/-](\d+\.\d+(?:\.\d+)?)",
        r"ASP\.NET[/-](\d+\.\d+(?:\.\d+)?)",
        r"\.NET[/-](\d+\.\d+(?:\.\d+)?)",
    ],
    "ColdFusion": [
        r"ColdFusion[/-](\d+(?:\.\d+)?)",
        r"Adobe ColdFusion\s+(\d+(?:\.\d+)?)",
    ],
    "OpenSSL": [
        r"OpenSSL/(\d+\.\d+\.\d+[a-z]?)",
        r"OpenSSL[/-](\d+\.\d+\.\d+)",
    ],
    "LiteSpeed": [
        r"LiteSpeed/(\d+\.\d+(?:\.\d+)?)",
    ],
    "HAProxy": [
        r"HAProxy[/-](\d+\.\d+(?:\.\d+)?)",
    ],
    "Caddy": [
        r"Caddy[/-](\d+\.\d+(?:\.\d+)?)",
        r"Server:\s*Caddy[/-](\d+\.\d+(?:\.\d+)?)",
    ],
    "Python": [
        r"Python/(\d+\.\d+(?:\.\d+)?)",
        r"python[/-](\d+\.\d+(?:\.\d+)?)",
    ],
    "Perl": [
        r"Perl/v?(\d+\.\d+(?:\.\d+)?)",
        r"mod_perl/(\d+\.\d+(?:\.\d+)?)",
    ],
    "Node.js": [
        r"node[/-]v?(\d+\.\d+(?:\.\d+)?)",
        r"Node\.js[/-]v?(\d+\.\d+(?:\.\d+)?)",
    ],
    "React": [
        r"react[/-](\d+\.\d+(?:\.\d+)?)",
        r"react\.production\.min\.js.*?(\d+\.\d+\.\d+)",
        r'"react":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
        r"React\.version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]",
    ],
    "Vue.js": [
        r"vue[/-](\d+\.\d+(?:\.\d+)?)",
        r"Vue\.version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]",
        r'"vue":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
        r"vue@(\d+\.\d+(?:\.\d+)?)",
    ],
    "Angular": [
        r"angular[/-](\d+\.\d+(?:\.\d+)?)",
        r"ng-version=['\"](\d+\.\d+(?:\.\d+)?)['\"]",
        r'"@angular/core":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
    ],
    "Bootstrap": [
        r"bootstrap[/-](\d+\.\d+(?:\.\d+)?)",
        r"Bootstrap\s+v?(\d+\.\d+(?:\.\d+)?)",
        r'"bootstrap":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
        r"bootstrap@(\d+\.\d+(?:\.\d+)?)",
    ],
    "Tailwind CSS": [
        r"tailwindcss[/-](\d+\.\d+(?:\.\d+)?)",
        r'"tailwindcss":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
    ],
    "WordPress": [
        r"WordPress\s+(\d+\.\d+(?:\.\d+)?)",
        r"wp-includes.*?ver=(\d+\.\d+(?:\.\d+)?)",
        r"wp-content.*?v=(\d+\.\d+(?:\.\d+)?)",
    ],
    "Drupal": [
        r"Drupal\s+(\d+(?:\.\d+)?)",
        r"drupal[/-](\d+(?:\.\d+)?)",
    ],
    "Nginx": [
        r"nginx/(\d+\.\d+(?:\.\d+)?)",
        r"[Nn]ginx[\s/-](\d+\.\d+(?:\.\d+)?)",
    ],
    "PHP": [
        r"PHP/(\d+\.\d+(?:\.\d+)?)",
        r"[Pp]hp[\s/-](\d+\.\d+(?:\.\d+)?)",
    ],
    "Express.js": [
        r"express[/-](\d+\.\d+(?:\.\d+)?)",
        r'"express":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
    ],
    "Next.js": [
        r"next[/-](\d+\.\d+(?:\.\d+)?)",
        r'"next":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
        r"__NEXT_DATA__.*?ssg.*?(\d+\.\d+(?:\.\d+)?)",
    ],
    "Nuxt.js": [
        r"nuxt[/-](\d+\.\d+(?:\.\d+)?)",
        r'"nuxt":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
    ],
    "Lodash": [
        r"lodash[/-](\d+\.\d+(?:\.\d+)?)",
        r'"lodash":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
    ],
    "Moment.js": [
        r"moment\.js/(\d+\.\d+\.\d+)",
        r"moment[/-](\d+\.\d+(?:\.\d+)?)",
        r'"moment":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
        r"cdnjs\.cloudflare\.com/ajax/libs/moment\.js/(\d+\.\d+\.\d+)",
    ],
    "Handlebars.js": [
        r"handlebars\.js/(\d+\.\d+\.\d+)",
        r"handlebars[/-](\d+\.\d+(?:\.\d+)?)",
        r'"handlebars":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
        r"cdnjs\.cloudflare\.com/ajax/libs/handlebars\.js/(\d+\.\d+\.\d+)",
    ],
    "CryptoJS": [
        r"crypto-js/(\d+\.\d+\.\d+)",
        r"crypto-js[/-](\d+\.\d+(?:\.\d+)?)",
        r'"crypto-js":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
        r"cdnjs\.cloudflare\.com/ajax/libs/crypto-js/(\d+\.\d+\.\d+)",
    ],
    "D3.js": [
        r"d3[/-]v?(\d+\.\d+(?:\.\d+)?)",
        r'"d3":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
    ],
    "Shopify": [
        r"Shopify\.version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]",
        r"Shopify\s+v?(\d+\.\d+(?:\.\d+)?)",
    ],
    "Magento": [
        r"Magento[/-](\d+\.\d+\.\d+-p\d+)",
        r"Magento[/-](\d+\.\d+(?:\.\d+)?)",
        r"magento[/-](\d+\.\d+\.\d+-p\d+)",
        r"magento[/-](\d+\.\d+(?:\.\d+)?)",
        r'"version":\s*"(\d+\.\d+\.\d+-p\d+)"',
        r'"version":\s*"(\d+\.\d+\.\d+)"',
        r"Mage\.version\s*=\s*['\"](\d+\.\d+\.\d+-p\d+)['\"]",
        r"Mage\.version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]",
        r"MAGENTO_VERSION\s*[=:]\s*['\"]?(\d+\.\d+\.\d+-p\d+)",
        r"MAGENTO_VERSION\s*[=:]\s*['\"]?(\d+\.\d+(?:\.\d+)?)",
        r"Magento\s+v?(\d+\.\d+\.\d+-p\d+)",
        r"Magento\s+v?(\d+\.\d+(?:\.\d+)?)",
        r"<!-- Magento (\d+\.\d+\.\d+-p\d+)",
        r"<!-- Magento ([0-9.]+)",
        r'"magento/product-community-edition":\s*"(\d+\.\d+\.\d+-p\d+)"',
        r'"magento/product-community-edition":\s*"(\d+\.\d+\.\d+)"',
        r'"magento/product-enterprise-edition":\s*"(\d+\.\d+\.\d+-p\d+)"',
        r'"magento/product-enterprise-edition":\s*"(\d+\.\d+\.\d+)"',
        r"window\.Magento\s*=.*?version[\"'\s:]*(\d+\.\d+\.\d+-p\d+)",
        r"window\.Magento\s*=.*?version[\"'\s:]*(\d+\.\d+(?:\.\d+)?)",
        r"/pub/static/version(\d+\.\d+\.\d+-p\d+)/",
        r"/pub/static/version([\d.]+)/",
        r"frontend/[^/]+/[^/]+/en_[A-Z]+/v(\d+\.\d+\.\d+-p\d+)",
        r"frontend/[^/]+/[^/]+/en_[A-Z]+/v([\d.]+)",
        r"master_magento_v(\d+\.\d+\.\d+-p\d+)",
        r"master_magento_v([\d.]+)",
        r"mageuat\..*?[vV](\d+\.\d+\.\d+-p\d+)",
        r"mageuat\..*?[vV](\d+\.\d+(?:\.\d+)?)",
    ],
    "Axios": [
        r"axios[/-](\d+\.\d+(?:\.\d+)?)",
        r'"axios":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
    ],
    "Svelte": [
        r"svelte[/-](\d+\.\d+(?:\.\d+)?)",
        r'"svelte":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
    ],
    "Ember.js": [
        r"ember[/-](\d+\.\d+(?:\.\d+)?)",
        r'"ember-source":\s*"[\^~]?(\d+\.\d+(?:\.\d+)?)"',
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
        self._lock = asyncio.Lock() if hasattr(asyncio, 'Lock') else None

    async def _async_rate_limit(self):
        import time
        elapsed = time.time() - self._last_request
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)
        self._last_request = time.time()

    def _sync_rate_limit(self):
        import time
        elapsed = time.time() - self._last_request
        if elapsed < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - elapsed)
        self._last_request = time.time()

    def _get_cache_key(self, tech: str, version: Optional[str]) -> str:
        return f"{tech}:{version or 'all'}"

    def _is_cache_valid(self, cache_key: str) -> bool:
        import time
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
        import time
        
        cache_key = self._get_cache_key(tech_name, version)
        
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]['data']
        
        cves: List[CVEInfo] = []
        cpe_info = CPE_MAPPING.get(tech_name)
        
        if not cpe_info:
            self._cache[cache_key] = {'data': [], 'timestamp': time.time()}
            return []
        
        try:
            self._sync_rate_limit()
            
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
            except Exception:
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
                except Exception:
                    continue
            
            cves.sort(key=lambda x: (-x.score, x.cve_id))
            
            self._cache[cache_key] = {
                'data': cves,
                'timestamp': time.time()
            }
            
        except Exception:
            self._cache[cache_key] = {'data': [], 'timestamp': time.time()}
        
        return cves

    def search_cves(self, tech_name: str, version: Optional[str] = None, 
                    max_results: int = 5, severity_filter: Optional[str] = None) -> List[CVEInfo]:
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
