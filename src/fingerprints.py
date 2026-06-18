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
                {"type": "script_content", "pattern": r"createApp|Vue\.createApp"],
            ],
            "category": "JavaScript Framework",
            "website": "https://vuejs.org"
        },
        "Angular": {
            "patterns": [
                {"type": "script", "pattern": r"angular(?:\.min)?\.js"],
                {"type": "html", "pattern": r"ng-app"],
                {"type": "html", "pattern": r"ng-controller"],
                {"type": "html", "pattern": r"ng-model"],
                {"type": "html", "pattern": r"\[ngClass\]|\[ngStyle\]"],
                {"type": "html", "pattern": r"_ngcontent-"],
                {"type": "html", "pattern": r"ng-version"],
            ],
            "category": "JavaScript Framework",
            "website": "https://angular.io"
        },
        "Next.js": {
            "patterns": [
                {"type": "html", "pattern": r"__NEXT_DATA__"],
                {"type": "script", "pattern": r"_next/static"],
                {"type": "header", "pattern": r"x-powered-by", "value": r"Next\.js"],
                {"type": "script_content", "pattern": r"next/router|next/navigation"],
            ],
            "category": "JavaScript Framework",
            "website": "https://nextjs.org"
        },
        "SvelteKit": {
            "patterns": [
                {"type": "html", "pattern": r"__SVELTEKIT__"],
                {"type": "script", "pattern": r"_app/immutable|\.svelte-kit"],
                {"type": "html", "pattern": r"data-sveltekit-"],
            ],
            "category": "JavaScript Framework",
            "website": "https://kit.svelte.dev"
        },
        "Astro": {
            "patterns": [
                {"type": "meta", "pattern": r"generator", "value": r"Astro"],
                {"type": "html", "pattern": r"astro-"],
            ],
            "category": "Static Site Generator",
            "website": "https://astro.build"
        },
        "tRPC": {
            "patterns": [
                {"type": "script_content", "pattern": r"@trpc|trpc"],
                {"type": "script", "pattern": r"@trpc"],
            ],
            "category": "API Layer",
            "website": "https://trpc.io"
        },
        "Prisma": {
            "patterns": [
                {"type": "script_content", "pattern": r"@prisma|prisma"],
            ],
            "category": "Database ORM",
            "website": "https://www.prisma.io"
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
        "Anthropic Claude": {
            "patterns": [
                {"type": "script_content", "pattern": r"anthropic|claude"],
            ],
            "category": "AI / ML",
            "website": "https://www.anthropic.com"
        },
        "LangChain": {
            "patterns": [
                {"type": "script_content", "pattern": r"langchain|LangChain"],
            ],
            "category": "AI / ML",
            "website": "https://www.langchain.com"
        },
        "LlamaIndex": {
            "patterns": [
                {"type": "script_content", "pattern": r"llamaindex|LlamaIndex"],
            ],
            "category": "AI / ML",
            "website": "https://www.llamaindex.ai"
        },
    },
    "auth": {
        "NextAuth.js / Auth.js": {
            "patterns": [
                {"type": "script_content", "pattern": r"next-auth|auth\.js"],
                {"type": "script", "pattern": r"next-auth"],
            ],
            "category": "Authentication",
            "website": "https://authjs.dev"
        },
        "Clerk": {
            "patterns": [
                {"type": "script", "pattern": r"clerk\.com|clerkjs"],
            ],
            "category": "Authentication",
            "website": "https://clerk.com"
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
}
