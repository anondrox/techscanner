FINGERPRINTS = {
    "javascript_frameworks": {
        # === Legacy ===
        "jQuery": {
            "patterns": [ {"type": "script", "pattern": r"jquery(?:\.min)?\.js"} ],
            "category": "JavaScript Library (Legacy)", "website": "https://jquery.com"
        },
        "Backbone.js": {
            "patterns": [ {"type": "script", "pattern": r"backbone(?:\.min)?\.js"} ],
            "category": "JavaScript Framework (Legacy)", "website": "https://backbonejs.org"
        },
        "Ember.js": {
            "patterns": [ {"type": "script", "pattern": r"ember(?:\.min)?\.js"} ],
            "category": "JavaScript Framework (Legacy)", "website": "https://emberjs.com"
        },
        # === Modern ===
        "React": {
            "patterns": [ {"type": "script", "pattern": r"react(?:\.min)?\.js"} ],
            "category": "JavaScript Framework", "website": "https://reactjs.org"
        },
        "Vue.js": {
            "patterns": [ {"type": "script", "pattern": r"vue(?:\.min)?\.js"} ],
            "category": "JavaScript Framework", "website": "https://vuejs.org"
        },
        "Angular": {
            "patterns": [ {"type": "script", "pattern": r"angular(?:\.min)?\.js"} ],
            "category": "JavaScript Framework", "website": "https://angular.io"
        },
        "Next.js": {
            "patterns": [ {"type": "html", "pattern": r"__NEXT_DATA__"} ],
            "category": "JavaScript Framework", "website": "https://nextjs.org"
        },
        "SvelteKit": {
            "patterns": [ {"type": "html", "pattern": r"__SVELTEKIT__"} ],
            "category": "JavaScript Framework", "website": "https://kit.svelte.dev"
        },
        "Astro": {
            "patterns": [ {"type": "meta", "pattern": r"generator", "value": r"Astro"} ],
            "category": "Static Site Generator", "website": "https://astro.build"
        },
        "Alpine.js": {
            "patterns": [ {"type": "html", "pattern": r"x-data"} ],
            "category": "JavaScript Framework", "website": "https://alpinejs.dev"
        },
        "HTMX": {
            "patterns": [ {"type": "script", "pattern": r"htmx(?:\.min)?\.js"} ],
            "category": "JavaScript Library", "website": "https://htmx.org"
        },
        "Redux": {
            "patterns": [ {"type": "script_content", "pattern": r"redux|createStore"} ],
            "category": "State Management", "website": "https://redux.js.org"
        },
        "Zustand": {
            "patterns": [ {"type": "script_content", "pattern": r"zustand"} ],
            "category": "State Management", "website": "https://zustand-demo.pmnd.rs"
        },
        "TanStack Query": {
            "patterns": [ {"type": "script_content", "pattern": r"@tanstack/react-query|useQuery"} ],
            "category": "Data Fetching", "website": "https://tanstack.com/query"
        },
    },
    "cms": {
        "WordPress": {
            "patterns": [ {"type": "meta", "pattern": r"generator", "value": r"WordPress"} ],
            "category": "CMS", "website": "https://wordpress.org"
        },
        "Drupal": {
            "patterns": [ {"type": "meta", "pattern": r"generator", "value": r"Drupal"} ],
            "category": "CMS", "website": "https://www.drupal.org"
        },
        "Joomla": {
            "patterns": [ {"type": "meta", "pattern": r"generator", "value": r"Joomla"} ],
            "category": "CMS", "website": "https://www.joomla.org"
        },
        "Magento": {
            "patterns": [ {"type": "script", "pattern": r"mage/|Magento"} ],
            "category": "E-commerce CMS", "website": "https://magento.com"
        },
    },
    "backend": {
        "Express.js": {
            "patterns": [ {"type": "script_content", "pattern": r"express|app\.listen"} ],
            "category": "Backend Framework", "website": "https://expressjs.com"
        },
        "NestJS": {
            "patterns": [ {"type": "script_content", "pattern": r"@nestjs|NestFactory"} ],
            "category": "Backend Framework", "website": "https://nestjs.com"
        },
        "Fastify": {
            "patterns": [ {"type": "script_content", "pattern": r"fastify"} ],
            "category": "Backend Framework", "website": "https://www.fastify.io"
        },
    },
    "ai_ml": {
        "OpenAI": {
            "patterns": [ {"type": "script_content", "pattern": r"openai|gpt-"} ],
            "category": "AI / ML", "website": "https://openai.com"
        },
        "Anthropic Claude": {
            "patterns": [ {"type": "script_content", "pattern": r"anthropic|claude"} ],
            "category": "AI / ML", "website": "https://www.anthropic.com"
        },
    },
}

SECURITY_HEADERS = {
    "content-security-policy": {
        "name": "Content Security Policy (CSP)",
        "description": "Controls resources the browser is allowed to load",
        "importance": "high"
    },
    "strict-transport-security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "description": "Forces HTTPS connections",
        "importance": "high"
    },
}
