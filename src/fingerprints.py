FINGERPRINTS = {
    "javascript_frameworks": {
        "React": {
            "patterns": [
                {"type": "script", "pattern": r"react(?:\.min)?\.js"},
                {"type": "script", "pattern": r"react-dom(?:\.min)?\.js"},
                {"type": "html", "pattern": r"data-reactroot"},
                {"type": "html", "pattern": r"data-reactid"},
                {"type": "html", "pattern": r"__NEXT_DATA__"},
                {"type": "script_content", "pattern": r"React\.createElement"},
                {"type": "script_content", "pattern": r"_react\.default\.createElement"},
                {"type": "script_content", "pattern": r"ReactDOM\.render|createRoot"},
            ],
            "category": "JavaScript Framework",
            "website": "https://reactjs.org"
        },
        "Vue.js": {
            "patterns": [
                {"type": "script", "pattern": r"vue(?:\.min)?\.js"},
                {"type": "script", "pattern": r"vue\.runtime(?:\.min)?\.js"},
                {"type": "html", "pattern": r"data-v-[a-f0-9]+"},
                {"type": "html", "pattern": r"v-cloak"},
                {"type": "html", "pattern": r"v-if|v-for|v-bind|v-model"},
                {"type": "script_content", "pattern": r"Vue\.component"},
                {"type": "script_content", "pattern": r"new Vue\("},
                {"type": "script_content", "pattern": r"createApp|Vue\.createApp"},
            ],
            "category": "JavaScript Framework",
            "website": "https://vuejs.org"
        },
        "Angular": {
            "patterns": [
                {"type": "script", "pattern": r"angular(?:\.min)?\.js"},
                {"type": "html", "pattern": r"ng-app"},
                {"type": "html", "pattern": r"ng-controller"},
                {"type": "html", "pattern": r"ng-model"},
                {"type": "html", "pattern": r"\[ngClass\]|\[ngStyle\]"},
                {"type": "html", "pattern": r"_ngcontent-"},
                {"type": "html", "pattern": r"ng-version"},
            ],
            "category": "JavaScript Framework",
            "website": "https://angular.io"
        },
        "jQuery": {
            "patterns": [
                {"type": "script", "pattern": r"jquery(?:\.min)?\.js"},
                {"type": "script", "pattern": r"jquery-\d+\.\d+(?:\.\d+)?(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"\$\(document\)\.ready"},
                {"type": "script_content", "pattern": r"jQuery\.fn\."],
            ],
            "category": "JavaScript Library",
            "website": "https://jquery.com"
        },
        "Next.js": {
            "patterns": [
                {"type": "html", "pattern": r"__NEXT_DATA__"},
                {"type": "script", "pattern": r"_next/static"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"Next\.js"},
                {"type": "script_content", "pattern": r"next/router|next/navigation"},
            ],
            "category": "JavaScript Framework",
            "website": "https://nextjs.org"
        },
        "Nuxt.js": {
            "patterns": [
                {"type": "html", "pattern": r"__NUXT__"},
                {"type": "script", "pattern": r"_nuxt/"},
                {"type": "html", "pattern": r"data-n-head"],
            ],
            "category": "JavaScript Framework",
            "website": "https://nuxtjs.org"
        },
        "Svelte": {
            "patterns": [
                {"type": "html", "pattern": r"svelte-"},
                {"type": "script", "pattern": r"svelte(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"SvelteComponent"],
            ],
            "category": "JavaScript Framework",
            "website": "https://svelte.dev"
        },
        "SvelteKit": {
            "patterns": [
                {"type": "html", "pattern": r"__SVELTEKIT__"},
                {"type": "script", "pattern": r"_app/immutable|\.svelte-kit"},
                {"type": "html", "pattern": r"data-sveltekit-"],
            ],
            "category": "JavaScript Framework",
            "website": "https://kit.svelte.dev"
        },
        "Solid.js": {
            "patterns": [
                {"type": "script", "pattern": r"solid(?:\.min)?\.js"},
                {"type": "html", "pattern": r"solid-js"},
                {"type": "script_content", "pattern": r"createSignal|createEffect|createResource"],
            ],
            "category": "JavaScript Framework",
            "website": "https://www.solidjs.com"
        },
        "Qwik": {
            "patterns": [
                {"type": "html", "pattern": r"qwik"},
                {"type": "script", "pattern": r"qwik(?:\.min)?\.js|build/q-"},
                {"type": "script_content", "pattern": r"useSignal|useStore|qwikCity"],
            ],
            "category": "JavaScript Framework",
            "website": "https://qwik.dev"
        },
        "Remix": {
            "patterns": [
                {"type": "html", "pattern": r"__remixManifest|remix-"},
                {"type": "script", "pattern": r"@remix-run|remix/router"],
            ],
            "category": "JavaScript Framework",
            "website": "https://remix.run"
        },
        "Ember.js": {
            "patterns": [
                {"type": "script", "pattern": r"ember(?:\.min)?\.js"],
                {"type": "html", "pattern": r"data-ember-action"},
                {"type": "html", "pattern": r"ember-view"],
            ],
            "category": "JavaScript Framework",
            "website": "https://emberjs.com"
        },
        "Backbone.js": {
            "patterns": [
                {"type": "script", "pattern": r"backbone(?:\.min)?\.js"],
                {"type": "script_content", "pattern": r"Backbone\.Model"],
            ],
            "category": "JavaScript Framework",
            "website": "https://backbonejs.org"
        },
        "Alpine.js": {
            "patterns": [
                {"type": "script", "pattern": r"alpine(?:\.min)?\.js"],
                {"type": "html", "pattern": r"x-data"],
                {"type": "html", "pattern": r"x-show|x-bind|x-on"],
            ],
            "category": "JavaScript Framework",
            "website": "https://alpinejs.dev"
        },
        "Preact": {
            "patterns": [
                {"type": "script", "pattern": r"preact(?:\.min)?\.js"],
                {"type": "script_content", "pattern": r"preact\.h\("},
            ],
            "category": "JavaScript Framework",
            "website": "https://preactjs.com"
        },
        "Stimulus": {
            "patterns": [
                {"type": "html", "pattern": r"data-controller"],
                {"type": "html", "pattern": r"data-action"],
                {"type": "script", "pattern": r"stimulus(?:\.min)?\.js"],
            ],
            "category": "JavaScript Framework",
            "website": "https://stimulus.hotwired.dev"
        },
        "HTMX": {
            "patterns": [
                {"type": "script", "pattern": r"htmx(?:\.min)?\.js"],
                {"type": "html", "pattern": r"hx-get|hx-post|hx-put|hx-delete"],
                {"type": "html", "pattern": r"hx-trigger|hx-swap"],
            ],
            "category": "JavaScript Library",
            "website": "https://htmx.org"
        },
        "Lodash": {
            "patterns": [
                {"type": "script", "pattern": r"lodash(?:\.min)?\.js"],
                {"type": "script_content", "pattern": r"_\.map\(|_\.filter\(|_\.reduce\("},
            ],
            "category": "JavaScript Library",
            "website": "https://lodash.com"
        },
        "Redux": {
            "patterns": [
                {"type": "script_content", "pattern": r"redux|createStore|configureStore"],
                {"type": "script", "pattern": r"redux"],
            ],
            "category": "State Management",
            "website": "https://redux.js.org"
        },
        "Jotai": {
            "patterns": [
                {"type": "script_content", "pattern": r"jotai|useAtom"],
            ],
            "category": "State Management",
            "website": "https://jotai.org"
        },
    },
    "css_frameworks": {
        "Tailwind CSS": {
            "patterns": [
                {"type": "css", "pattern": r"tailwind(?:\.min)?\.css"],
                {"type": "html", "pattern": r"class=\"[^\"]*(?:flex|grid|p-\d+|m-\d+|text-(?:xs|sm|base|lg|xl)|bg-(?:gray|red|blue|green)-\d{2,3})"],
                {"type": "html", "pattern": r"class=\"[^\"]*(?:hover:|focus:|dark:|sm:|md:|lg:|xl:)"],
            ],
            "category": "CSS Framework",
            "website": "https://tailwindcss.com"
        },
        "shadcn/ui": {
            "patterns": [
                {"type": "html", "pattern": r"shadcn|cn\(\)"],
                {"type": "script_content", "pattern": r"@radix-ui|tailwindcss"],
            ],
            "category": "CSS Framework",
            "website": "https://ui.shadcn.com"
        },
    },
    "cms": {
        "Medusa": {
            "patterns": [
                {"type": "html", "pattern": r"medusa|medusajs"],
                {"type": "script_content", "pattern": r"@medusajs"],
            ],
            "category": "E-commerce",
            "website": "https://medusajs.com"
        },
        "BigCommerce": {
            "patterns": [
                {"type": "html", "pattern": r"bigcommerce|bigcommerce\.com"],
            ],
            "category": "E-commerce",
            "website": "https://www.bigcommerce.com"
        },
    },
    "ai_ml": {
        "OpenAI": {
            "patterns": [
                {"type": "script_content", "pattern": r"openai|gpt-|chatgpt"],
                {"type": "script", "pattern": r"openai\.com|api\.openai\.com"],
            ],
            "category": "AI / ML",
            "website": "https://openai.com"
        },
        "LangChain": {
            "patterns": [
                {"type": "script_content", "pattern": r"langchain|LangChain"],
                {"type": "script", "pattern": r"langchain\.js"],
            ],
            "category": "AI / ML",
            "website": "https://www.langchain.com"
        },
        "Hugging Face": {
            "patterns": [
                {"type": "script_content", "pattern": r"huggingface|transformers"],
                {"type": "script", "pattern": r"huggingface\.co"],
            ],
            "category": "AI / ML",
            "website": "https://huggingface.co"
        },
    },
    "security": {
        "Firebase Auth": {
            "patterns": [
                {"type": "script", "pattern": r"firebase\.com|firebase-app"],
                {"type": "script_content", "pattern": r"firebase\.auth"],
            ],
            "category": "Authentication",
            "website": "https://firebase.google.com"
        },
    },
}

SECURITY_HEADERS = {
    "content-security-policy": {
        "name": "Content Security Policy (CSP)",
        "description": "Controls resources the browser is allowed to load",
        "importance": "high",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    "strict-transport-security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "description": "Forces HTTPS connections",
        "importance": "high",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Prevents clickjacking attacks",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME type sniffing",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "description": "Enables browser XSS filtering (legacy)",
        "importance": "low",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls referrer information sent with requests",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Controls browser feature permissions",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy (COEP)",
        "description": "Prevents loading cross-origin resources without permission",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "description": "Isolates browsing context from cross-origin documents",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy (CORP)",
        "description": "Prevents other domains from reading resource responses",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
    },
}
