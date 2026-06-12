# 🔍 TechScanner v1.3

<div align="center">

![TechScanner Banner](https://img.shields.io/badge/TechScanner-Advanced%20Tech%20Detection-blue?style=for-the-badge)
![Python Version](https://img.shields.io/badge/python-3.8%2B-green?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

**Advanced Technology Detection & Analysis Tool with CVE Vulnerability Scanning**

*Detect 200+ technologies with comprehensive security analysis and CVE vulnerability scanning*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [CVE Scanning](#cve-vulnerability-scanning) • [License](#license)

</div>

---

## 🎯 Features

### Technology Detection
- **200+ Technologies** across multiple categories (frameworks, CMS, servers, analytics, payment solutions, security tools, application servers, headless CMS, monitoring, and more)
- **7 Detection Methods** for comprehensive coverage:
  - Script source analysis
  - Inline JavaScript scanning
  - CSS reference detection
  - HTML pattern matching
  - Meta tag analysis
  - HTTP header inspection
  - Cookie detection
- **Confidence Scoring** based on multiple pattern matches
- **Version Detection** for major frameworks and technologies

### Security Analysis
- **Security Header Grading** (A+ to F) covering:
  - Content Security Policy (CSP)
  - HTTP Strict Transport Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - And more
- **Performance Indicators** analysis

### CVE Vulnerability Scanning
- **NIST NVD API Integration** for real-time vulnerability data
- **Severity Ratings**: Critical, High, Medium, Low
- **CVSS Scores** and detailed descriptions
- **Version-Specific Matching** when possible
- **Optional NVD API Key** support (10x faster rate limits)

### Batch Processing
- **Concurrent URL Analysis** with configurable concurrency
- **Multiple Output Formats**: JSON, CSV, Console
- **File-Based Processing** for scanning multiple URLs

---

## 📋 Technology Categories

- **JavaScript Frameworks**: React, Vue.js, Angular, jQuery, Next.js, Nuxt.js, Svelte, SvelteKit, Solid.js, Qwik, Remix, Ember.js, Preact, Alpine.js, HTMX, and more
- **CSS Frameworks**: Bootstrap, Tailwind CSS, Bulma, Foundation, Chakra UI, Ant Design, DaisyUI, etc.
- **CMS & Headless CMS**: WordPress, Drupal, Joomla, Shopify, Magento, Ghost, Webflow, Strapi, Sanity, Contentful, Payload CMS, Directus, etc.
- **Web Servers**: Nginx, Apache, Microsoft IIS, LiteSpeed, Caddy, Traefik, Envoy, Jetty
- **Application Servers**: Apache Tomcat, JBoss, WebLogic, WebSphere, GlassFish
- **Programming Languages**: PHP, Java, JSP, ASP.NET, ASP Classic, ColdFusion, Perl, Python, Go, Rust, Node.js
- **Backend Frameworks**: Express.js, Django, Flask, FastAPI, Laravel, Ruby on Rails, Spring, NestJS
- **Analytics & Marketing**: Google Analytics, Facebook Pixel, Hotjar, Mixpanel, Segment, Amplitude, Plausible, Matomo, HubSpot, etc.
- **Payment Solutions**: Stripe, PayPal, Square, Braintree, Klarna, Affirm
- **Security & Auth**: reCAPTCHA, hCaptcha, Cloudflare Turnstile, OpenSSL, Auth0, Clerk, Supabase Auth
- **Monitoring & Observability**: Sentry, Datadog, New Relic, LogRocket, Bugsnag, Rollbar
- **Load Balancers, CDNs & Hosting**: HAProxy, Cloudflare, Amazon CloudFront, Fastly, Akamai, Vercel, Netlify, Heroku, AWS, Google Cloud
- **And many more...** (Build tools, Error tracking, Video players, Social SDKs, etc.)

---

## 🚀 Installation

### Requirements
- Python 3.8+
- pip or uv package manager

### From Repository

```bash
# Clone the repository
git clone https://github.com/anondrox/techscanner.git
cd techscanner

# Install dependencies
pip install -r requirements.txt
# or with uv:
uv sync
```

### Dependencies
- `aiohttp` - Async HTTP client
- `beautifulsoup4` - HTML parsing
- `lxml` - Fast XML/HTML parser
- `rich` - Beautiful terminal output
- `requests` - HTTP library
- `nvdlib` - NIST NVD API wrapper

---

## 💡 Usage

### Basic Scanning

```bash
# Scan a single website
python techscanner.py https://example.com

# Brief output (technologies only)
python techscanner.py https://example.com --brief

# Hide the awesome banner
python techscanner.py https://example.com --no-banner
```

### CVE Vulnerability Scanning

```bash
# Enable CVE scanning with public API (limited rate)
python techscanner.py https://example.com --cve

# With NVD API key for faster scanning (10x rate limit)
export NVD_API_KEY="your-api-key-here"
python techscanner.py https://example.com --cve
```

**Get a free NVD API key:** https://nvd.nist.gov/developers/request-an-api-key

### Batch Processing

```bash
# Scan multiple URLs from a file (one URL per line)
python techscanner.py -f urls.txt

# With custom concurrency (default: 5)
python techscanner.py -f urls.txt -c 10

# Batch scanning with CVE detection
python techscanner.py -f urls.txt --cve -c 5
```

### Output Options

```bash
# Save results to JSON
python techscanner.py https://example.com -o results.json

# Save results to CSV
python techscanner.py https://example.com -o results.csv

# Raw JSON to stdout
python techscanner.py https://example.com --json
```

### Complete Command Reference

```bash
python techscanner.py [-h] [--cve] [--brief] [--no-banner] 
                      [-f FILE] [-c CONCURRENCY] 
                      [-o OUTPUT] [--json]
                      [url]

Positional Arguments:
  url                  Website URL to analyze

Optional Arguments:
  -h, --help          Show help message
  --cve               Enable CVE vulnerability scanning
  --brief             Show brief output (technologies only)
  --no-banner         Hide the TechScanner banner
  -f, --file FILE     Scan multiple URLs from file
  -c, --concurrency   Number of concurrent requests (default: 5)
  -o, --output FILE   Save output to JSON/CSV file
  --json              Output raw JSON to stdout
```

---

## 🔒 CVE Vulnerability Scanning

### How It Works

When you enable CVE scanning with `--cve`, TechScanner:

1. **Detects Technologies** on the target website
2. **Maps to CPE Identifiers** using a comprehensive technology-to-CPE database
3. **Extracts Version Information** from page content, headers, and scripts
4. **Queries NIST NVD API** for known vulnerabilities
5. **Displays Results** grouped by technology with severity ratings

### Example Output

```
╔═══════════════════════════ Vulnerability Summary ════════════════════════════╗
║ Total CVEs Found: 8 (1 Critical, 4 High, 3 Medium)                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

                          WordPress v6.8.3 - 5 CVE(s)                           
╭─────────────┬─────────┬───────┬──────┼─────────────────────────────────────────╮
│ CVE ID      │ Severity│ Score │ Pub… │ Description                             │
├─────────────┼─────────┼───────┼──────┼─────────────────────────────────────────┤
│ CVE-2024-?? │ HIGH    │ 7.5   │ 2024 │ SQL injection vulnerability in...       │
...
```

---

## 📊 Project Structure

```
techscanner/
├── techscanner.py           # Main CLI entry point
├── src/
│   ├── __init__.py          # Package initialization
│   ├── detector.py          # Core detection engine
│   ├── fingerprints.py      # Technology fingerprints database (200+ entries)
│   ├── cve_lookup.py        # CVE vulnerability lookup module
│   └── headers_analyzer.py  # Security header analysis
├── pyproject.toml           # Project configuration
├── requirements.txt           # Python dependencies
├── README.md                # This file
└── replit.md                # Replit-specific documentation
```

---

## 🛡️ Security Headers Analysis

TechScanner analyzes and grades security headers:

- **Grade A+/A** - Excellent security posture
- **Grade B** - Good security configuration
- **Grade C** - Acceptable but could be improved
- **Grade D/E** - Poor security headers
- **Grade F** - Critical security header issues

Analyzed headers include:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- And others

---

## 📈 Performance

- **Async Operations** for faster concurrent scanning
- **Optimized Detection** with efficient regex patterns
- **Rate-Limited API Calls** to avoid overwhelming services
- **Caching System** for repeated queries
- **Batch Processing** for scanning multiple URLs efficiently

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional technology fingerprints
- More accurate version detection patterns
- Enhanced CVE relevance filtering
- Performance optimizations
- Documentation improvements

Feel free to:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🎨 Design Credit

**Banner designed by anondrox** with security memes and emoji flair! 🎭

---

## 📞 Support

For issues, feature requests, or questions:
- Open an issue on GitHub

---

## 🔗 Resources

- **NIST National Vulnerability Database:** https://nvd.nist.gov/
- **NVD API Documentation:** https://nvd.nist.gov/developers/
- **CPE (Common Platform Enumeration):** https://nvd.nist.gov/products/cpe/

---

## 📝 Changelog

### v1.3 (June 2026)
- **Major Expansion**: Added 70+ new technology fingerprints for broader coverage
  - **New Languages**: Go, Rust
  - **New Frameworks**: SvelteKit, Solid.js, Qwik, Remix, NestJS, Traefik, Envoy
  - **Headless CMS**: Strapi, Sanity, Contentful, Payload CMS, Directus
  - **Monitoring**: Datadog, New Relic
  - **Auth Providers**: Auth0, Clerk, Supabase Auth
  - **Improved Patterns**: Better detection for existing technologies + new build tools and error tracking
- **Updated Documentation**: Reflects 200+ technologies

### v1.2 (November 28, 2025)
- **Enhanced Technology Detection**: Added 20+ new technology fingerprints
  - Application Servers: Apache Tomcat, JBoss, WebLogic, WebSphere, GlassFish, Jetty
  - Web Servers: Microsoft IIS, LiteSpeed, Caddy, HAProxy
  - Languages: Java, JSP, ASP Classic, ColdFusion, Perl, Python, Node.js
  - Security: OpenSSL, mod_ssl
- **Improved Version Detection**:
  - Apache version detection from Server headers
  - Microsoft IIS version detection
  - ASP.NET version detection (X-AspNet-Version, X-AspNetMvc-Version headers)
  - Tomcat, Java, OpenSSL version patterns
- **Expanded CVE Support**: Added CPE mappings for all new technologies

### v1.1 (November 28, 2025)
- Initial release with 100+ technology fingerprints
- CVE vulnerability scanning via NIST NVD API
- Security header grading (A+ to F)
- Batch processing support
- Multiple output formats (JSON, CSV)

<div align="center">

**TechScanner** - Detect. Analyze. Secure.

Made with ❤️ by the security-conscious developer community

</div>
