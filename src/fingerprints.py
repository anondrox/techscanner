FINGERPRINTS = {
    "javascript_frameworks": {
        "jQuery": {"patterns": [{"type": "script", "pattern": r"jquery(?:\.min)?\.js"}], "category": "JavaScript Library (Legacy)", "website": "https://jquery.com"},
        "React": {"patterns": [{"type": "script", "pattern": r"react(?:\.min)?\.js"}], "category": "JavaScript Framework", "website": "https://reactjs.org"},
        "Vue.js": {"patterns": [{"type": "script", "pattern": r"vue(?:\.min)?\.js"}], "category": "JavaScript Framework", "website": "https://vuejs.org"},
        "Angular": {"patterns": [{"type": "script", "pattern": r"angular(?:\.min)?\.js"}], "category": "JavaScript Framework", "website": "https://angular.io"},
        "Next.js": {"patterns": [{"type": "html", "pattern": r"__NEXT_DATA__"}], "category": "JavaScript Framework", "website": "https://nextjs.org"},
        "SvelteKit": {"patterns": [{"type": "html", "pattern": r"__SVELTEKIT__"}], "category": "JavaScript Framework", "website": "https://kit.svelte.dev"},
        "Astro": {"patterns": [{"type": "meta", "pattern": r"generator", "value": r"Astro"}], "category": "Static Site Generator", "website": "https://astro.build"},
        "Alpine.js": {"patterns": [{"type": "html", "pattern": r"x-data"}], "category": "JavaScript Framework", "website": "https://alpinejs.dev"},
        "HTMX": {"patterns": [{"type": "script", "pattern": r"htmx(?:\.min)?\.js"}], "category": "JavaScript Library", "website": "https://htmx.org"},
        "Redux": {"patterns": [{"type": "script_content", "pattern": r"redux|createStore"}], "category": "State Management", "website": "https://redux.js.org"},
        "Zustand": {"patterns": [{"type": "script_content", "pattern": r"zustand"}], "category": "State Management", "website": "https://zustand-demo.pmnd.rs"},
        "TanStack Query": {"patterns": [{"type": "script_content", "pattern": r"@tanstack/react-query|useQuery"}], "category": "Data Fetching", "website": "https://tanstack.com/query"},
    },
    "cms": {
        "WordPress": {"patterns": [{"type": "meta", "pattern": r"generator", "value": r"WordPress"}], "category": "CMS", "website": "https://wordpress.org"},
        "Drupal": {"patterns": [{"type": "meta", "pattern": r"generator", "value": r"Drupal"}], "category": "CMS", "website": "https://www.drupal.org"},
        "Joomla": {"patterns": [{"type": "meta", "pattern": r"generator", "value": r"Joomla"}], "category": "CMS", "website": "https://www.joomla.org"},
        "Magento": {"patterns": [{"type": "script", "pattern": r"mage/|Magento"}], "category": "E-commerce CMS", "website": "https://magento.com"},
    },
    "backend": {
        "Express.js": {"patterns": [{"type": "script_content", "pattern": r"express|app\.listen"}], "category": "Backend Framework", "website": "https://expressjs.com"},
        "NestJS": {"patterns": [{"type": "script_content", "pattern": r"@nestjs|NestFactory"}], "category": "Backend Framework", "website": "https://nestjs.com"},
        "Fastify": {"patterns": [{"type": "script_content", "pattern": r"fastify"}], "category": "Backend Framework", "website": "https://www.fastify.io"},
    },
    "microsoft": {
        "Microsoft IIS": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"Microsoft-IIS"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"ASP\.NET"}
            ],
            "category": "Web Server",
            "website": "https://www.iis.net/"
        },
        "ASP.NET": {
            "patterns": [
                {"type": "header", "pattern": r"x-aspnet-version"},
                {"type": "header", "pattern": r"x-aspnetmvc-version"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"ASP\.NET"},
                {"type": "html", "pattern": r"__VIEWSTATE|__EVENTVALIDATION|__VIEWSTATEGENERATOR"},
                {"type": "html", "pattern": r"\.aspx"}
            ],
            "category": "Web Framework",
            "website": "https://dotnet.microsoft.com/apps/aspnet"
        },
        "ASP.NET Web Forms": {
            "patterns": [
                {"type": "html", "pattern": r"__VIEWSTATE"},
                {"type": "html", "pattern": r"__EVENTVALIDATION"},
                {"type": "html", "pattern": r"WebResource\.axd|ScriptResource\.axd"}
            ],
            "category": "Web Framework (Legacy)",
            "website": "https://learn.microsoft.com/en-us/previous-versions/aspnet/0z5x2h8y(v=vs.140)"
        },
        "Classic ASP": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"ASP"},
                {"type": "html", "pattern": r"\.asp(\?|$|")"}
            ],
            "category": "Web Framework (Legacy)",
            "website": "https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525837(v=vs.90)"
        }
    },
    "ai_ml": {
        "OpenAI": {"patterns": [{"type": "script_content", "pattern": r"openai|gpt-"}], "category": "AI / ML", "website": "https://openai.com"},
        "Anthropic Claude": {"patterns": [{"type": "script_content", "pattern": r"anthropic|claude"}], "category": "AI / ML", "website": "https://www.anthropic.com"},
    },
    "analytics": {
        "Google Analytics": {"patterns": [{"type": "script", "pattern": r"google-analytics|gtag|ga\.js"}], "category": "Analytics", "website": "https://analytics.google.com"},
        "Matomo": {"patterns": [{"type": "script", "pattern": r"matomo|piwik"}], "category": "Analytics", "website": "https://matomo.org"},
    },
    "ecommerce": {
        "Shopify": {"patterns": [{"type": "script", "pattern": r"shopify|cdn\.shopify\.com"}], "category": "E-commerce", "website": "https://www.shopify.com"},
        "WooCommerce": {"patterns": [{"type": "script", "pattern": r"woocommerce"}], "category": "E-commerce", "website": "https://woocommerce.com"},
    },
    "hosting_cdn": {
        "Vercel": {"patterns": [{"type": "header", "pattern": r"x-vercel", "value": r"1"}], "category": "Hosting / CDN", "website": "https://vercel.com"},
        "Netlify": {"patterns": [{"type": "header", "pattern": r"x-nf-request-id"}], "category": "Hosting / CDN", "website": "https://www.netlify.com"},
        "Cloudflare": {"patterns": [{"type": "header", "pattern": r"cf-ray"}], "category": "Hosting / CDN", "website": "https://www.cloudflare.com"},
    },
    "payment": {
        "Stripe": {"patterns": [{"type": "script", "pattern": r"stripe\.com|js\.stripe\.com"}], "category": "Payment", "website": "https://stripe.com"},
        "PayPal": {"patterns": [{"type": "script", "pattern": r"paypal\.com|paypalobjects"}], "category": "Payment", "website": "https://www.paypal.com"},
        "Razorpay": {"patterns": [{"type": "script", "pattern": r"razorpay"}], "category": "Payment", "website": "https://razorpay.com"},
    },
    "build_tools": {
        "Vite": {"patterns": [{"type": "script", "pattern": r"vite|/@vite/"}], "category": "Build Tool", "website": "https://vitejs.dev"},
        "Webpack": {"patterns": [{"type": "script", "pattern": r"webpack"}], "category": "Build Tool", "website": "https://webpack.js.org"},
    },
    "databases": {
        "MongoDB": {"patterns": [{"type": "script_content", "pattern": r"mongodb|mongoose"}], "category": "Database", "website": "https://www.mongodb.com"},
        "PostgreSQL": {"patterns": [{"type": "script_content", "pattern": r"postgres|postgresql"}], "category": "Database", "website": "https://www.postgresql.org"},
    },
    "monitoring": {
        "Sentry": {"patterns": [{"type": "script", "pattern": r"sentry|getsentry"}], "category": "Monitoring", "website": "https://sentry.io"},
        "Datadog": {"patterns": [{"type": "script", "pattern": r"datadog|ddrum"}], "category": "Monitoring", "website": "https://www.datadoghq.com"},
    },
    "cicd": {
        "GitHub Actions": {"patterns": [{"type": "html", "pattern": r"github\.com/.*/actions"}], "category": "CI/CD", "website": "https://github.com/features/actions"},
        "GitLab CI": {"patterns": [{"type": "html", "pattern": r"\.gitlab-ci\.yml"}], "category": "CI/CD", "website": "https://docs.gitlab.com/ee/ci/"},
        "Jenkins": {"patterns": [{"type": "html", "pattern": r"jenkins"}], "category": "CI/CD", "website": "https://www.jenkins.io"},
        "CircleCI": {"patterns": [{"type": "html", "pattern": r"circleci"}], "category": "CI/CD", "website": "https://circleci.com"},
    },
    "graphql": {
        "GraphQL": {"patterns": [{"type": "html", "pattern": r"graphql"}, {"type": "url", "pattern": r"/graphql"}], "category": "GraphQL", "website": "https://graphql.org"},
        "Apollo Client": {"patterns": [{"type": "script_content", "pattern": r"@apollo/client|ApolloProvider"}], "category": "GraphQL", "website": "https://www.apollographql.com"},
        "GraphQL Introspection": {"patterns": [{"type": "html", "pattern": r"__schema|__type"}, {"type": "url", "pattern": r"/graphql"}], "category": "GraphQL Introspection", "website": "https://graphql.org/learn/introspection/"},
    },
    "api": {
        "REST API": {"patterns": [{"type": "html", "pattern": r"/api/|rest|swagger|openapi"}, {"type": "url", "pattern": r"/api/"}], "category": "API / REST", "website": "https://restfulapi.net"},
        "Swagger / OpenAPI": {"patterns": [{"type": "html", "pattern": r"swagger|openapi"}], "category": "API Documentation", "website": "https://swagger.io"},
        "API Gateway - Kong": {"patterns": [{"type": "header", "pattern": r"x-kong-proxy-latency"}], "category": "API Gateway", "website": "https://konghq.com"},
        "API Gateway - AWS": {"patterns": [{"type": "header", "pattern": r"x-amzn-requestid"}], "category": "API Gateway", "website": "https://aws.amazon.com/api-gateway/"},
    },
    "waf": {
        "Cloudflare WAF": {"patterns": [{"type": "header", "pattern": r"cf-ray|cf-mitigated|cf-cache-status"}], "category": "WAF / Protection", "website": "https://www.cloudflare.com"},
        "AWS WAF": {"patterns": [{"type": "header", "pattern": r"x-amzn-waf|awselb"}], "category": "WAF / Protection", "website": "https://aws.amazon.com/waf/"},
        "Akamai WAF": {"patterns": [{"type": "header", "pattern": r"akamai|akamai-origin"}], "category": "WAF / Protection", "website": "https://www.akamai.com"},
        "Imperva / Incapsula": {"patterns": [{"type": "header", "pattern": r"x-iinfo|incap_ses|visid_incap"}], "category": "WAF / Protection", "website": "https://www.imperva.com"},
        "Sucuri WAF": {"patterns": [{"type": "header", "pattern": r"x-sucuri"}], "category": "WAF / Protection", "website": "https://sucuri.net"},
    },
    "cdn": {
        "Cloudflare CDN": {"patterns": [{"type": "header", "pattern": r"cf-ray|cf-cache-status"}], "category": "CDN", "website": "https://www.cloudflare.com"},
        "Fastly CDN": {"patterns": [{"type": "header", "pattern": r"x-served-by|fastly"}], "category": "CDN", "website": "https://www.fastly.com"},
        "Akamai CDN": {"patterns": [{"type": "header", "pattern": r"akamai"}], "category": "CDN", "website": "https://www.akamai.com"},
        "Amazon CloudFront": {"patterns": [{"type": "header", "pattern": r"x-amz-cf-id|x-cache"}], "category": "CDN", "website": "https://aws.amazon.com/cloudfront/"},
    },
}

SECURITY_HEADERS = {
    "content-security-policy": {"name": "Content Security Policy (CSP)", "description": "Controls resources the browser is allowed to load", "importance": "high"},
    "strict-transport-security": {"name": "HTTP Strict Transport Security (HSTS)", "description": "Forces HTTPS connections", "importance": "high"},
}
