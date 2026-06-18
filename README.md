# 🔍 TechScanner v2.0

<div align="center">

![TechScanner Banner](https://img.shields.io/badge/TechScanner-Advanced%20Tech%20Detection-blue?style=for-the-badge)
![Python Version](https://img.shields.io/badge/python-3.8%2B-green?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

**Advanced Technology Detection & Analysis Tool with CVE Vulnerability Scanning**

*Detect 250+ technologies with AI-powered insights, comprehensive security analysis and CVE vulnerability scanning*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [New in v2.0](#new-in-v20) • [License](#license)

</div>

---

## 🎯 Features

### 🔍 Technology Detection
- **250+ Technologies** across 15+ categories
- **8 powerful detection methods** (headers, scripts, HTML, meta, cookies, URLs, CSS, and JS variables)
- **Weighted Confidence Scoring** — more matches = higher accuracy
- **Advanced Version Detection** from headers, meta tags, JSON, scripts, and endpoints

### 🛡️ Security & Analysis
- **Security Header Grading** (A+ to F)
- **Performance Indicators** (compression, caching, lazy loading, preload)
- **CVE Vulnerability Scanning** via NIST NVD with severity ratings

### 📊 Output & Reporting
- Beautiful Rich terminal output
- Export to **JSON**, **CSV**, and **HTML reports**
- Batch scanning with concurrency control

---

## 🆕 What's New in v2.0

- Massive expansion to **250+ technologies** (including AI/ML tools)
- New **AI & Machine Learning** detection category
- **HTML Report Generation** (`--html report.html`)
- Significantly improved confidence scoring and version detection
- Better support for modern frameworks and headless CMS
- Cleaner, more professional documentation

---

## 📋 Supported Technologies (v2.0)

**Major Categories:**

- **AI & Machine Learning**: OpenAI, LangChain, Hugging Face, TensorFlow.js
- **JavaScript Frameworks**: React, Vue.js, Angular, Next.js, Nuxt.js, SvelteKit, Solid.js, Qwik, Remix, and more
- **State Management**: Redux, Zustand, Jotai, TanStack Query
- **CSS & UI Frameworks**: Tailwind CSS, Bootstrap, Chakra UI, DaisyUI, shadcn/ui
- **CMS & Headless CMS**: WordPress, Strapi, Sanity, Contentful, Payload, Directus, Medusa, BigCommerce
- **Backend & Languages**: Node.js, Python, Go, Rust, PHP, Java, NestJS, FastAPI, Django, Laravel
- **Auth & Security**: Auth0, Clerk, Supabase Auth, Firebase Auth, reCAPTCHA
- **Monitoring**: Sentry, Datadog, New Relic
- **Hosting & CDN**: Vercel, Netlify, Cloudflare, AWS, Google Cloud
- **And many more** (analytics, payments, video, social SDKs, build tools...)

---

## 🚀 Installation

### Requirements
- Python **3.8+**
- `pip` or `uv`

### Quick Install

```bash
git clone https://github.com/anondrox/techscanner.git
cd techscanner

# Install all dependencies
pip install -r requirements.txt

# Or with uv (recommended for speed)
uv sync
```

### Dependencies

| Package           | Purpose                              |
|-------------------|--------------------------------------|
| `aiohttp`         | Async HTTP requests                  |
| `beautifulsoup4`  | HTML parsing                         |
| `lxml`            | Fast XML/HTML parser                 |
| `requests`        | HTTP library                         |
| `rich`            | Beautiful terminal UI                |
| `nvdlib`          | NIST NVD CVE lookup                  |
| `trafilatura`     | Web content extraction               |

---

## 💡 Usage

### Basic Scan
```bash
python techscanner.py https://example.com
```

### With CVE Scanning + HTML Report (Recommended)
```bash
python techscanner.py https://example.com --cve --html report.html
```

### Batch Scanning
```bash
python techscanner.py -f urls.txt --cve -c 10
```

### Export Options
```bash
python techscanner.py https://example.com -o results.json
python techscanner.py https://example.com -o results.csv
python techscanner.py https://example.com --html report.html
python techscanner.py https://example.com --json
```

### Useful Flags
| Flag              | Description                              |
|-------------------|------------------------------------------|
| `--cve`           | Enable CVE vulnerability scanning        |
| `--html FILE`     | Generate beautiful HTML report           |
| `--brief`         | Show only technologies (no security)     |
| `-c`, `--concurrency` | Number of concurrent scans          |
| `-f FILE`         | Scan multiple URLs from a file           |
| `-o FILE`         | Save output to JSON or CSV               |

---

## 📝 Changelog

### v2.0 (June 2026)
- Major upgrade with 250+ technologies
- New AI/ML detection category
- HTML report generation added
- Improved confidence scoring & version detection
- Better documentation and structure

### v1.3
- Added 70+ new fingerprints (Go, Rust, SvelteKit, Solid.js, Qwik, etc.)

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Add new technology fingerprints
- Improve version detection patterns
- Enhance HTML report design
- Report bugs or suggest features

---

## 📝 License

This project is licensed under the **MIT License**.

Made with ❤️ by anondrox
