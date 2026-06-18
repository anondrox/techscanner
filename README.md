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

### Technology Detection
- **250+ Technologies** across 15+ categories
- **8 Detection Methods** (including improved JS variable detection)
- **Weighted Confidence Scoring** for higher accuracy
- **Advanced Version Detection** from multiple sources (headers, meta, JSON, scripts, endpoints)
- **Tech Stack Insights** - Understand relationships between technologies

### Security & Performance
- **Security Header Grading** (A+ to F)
- **Performance Indicators** analysis
- **Vulnerability Summary** with risk scoring

### CVE Vulnerability Scanning
- NIST NVD API Integration
- Severity ratings and CVSS scores
- Version-specific matching

### Output & Reporting
- Beautiful terminal output with Rich
- JSON, CSV, and **new HTML reports**
- Batch processing with concurrency

---

## 🆕 New in v2.0 (Major Upgrade)

- **Expanded Fingerprints**: +50 new technologies including AI/ML tools, more modern frameworks, e-commerce platforms
- **Improved Confidence System**: Multi-pattern weighted scoring
- **Better Version Extraction**: Enhanced regex + endpoint scanning + JS variable parsing
- **HTML Report Generation**: `--html report.html` for beautiful shareable reports
- **Tech Stack Analysis**: Detects common stacks (e.g., "Next.js + Tailwind + Vercel")
- **Performance & Accuracy Improvements**

---

## 📋 Technology Categories (v2.0)

Includes all previous + new additions:
- **AI & Machine Learning**: OpenAI, LangChain.js, Hugging Face Transformers, TensorFlow.js, PyTorch.js
- **JavaScript Frameworks & Libraries**: React, Vue, Angular, Next.js, Nuxt, SvelteKit, Solid.js, Qwik, Remix, TanStack Query, Zustand, Redux, Jotai, and more
- **CSS & UI**: Tailwind, Bootstrap, Chakra, DaisyUI, shadcn/ui hints, etc.
- **Headless CMS & E-commerce**: Strapi, Sanity, Medusa, BigCommerce, Saleor
- **Backend & Languages**: Go, Rust, NestJS, FastAPI, Spring Boot hints
- **Auth & Security**: Auth0, Clerk, Supabase, Firebase Auth, reCAPTCHA v3
- **Monitoring & Observability**: Sentry, Datadog RUM, New Relic, Prometheus hints
- **And 200+ more...**

---

## 🚀 Installation

```bash
git clone https://github.com/anondrox/techscanner.git
cd techscanner
pip install -r requirements.txt
# or uv sync
```

## 💡 Usage (v2.0)

```bash
# Basic scan
python techscanner.py https://example.com

# With CVE + HTML report
python techscanner.py https://example.com --cve --html report.html

# Batch + JSON
python techscanner.py -f urls.txt --json -o results.json

# Full featured
python techscanner.py https://diageoindia.com --cve --html stack-report.html
```

New flags:
- `--html FILE` : Generate beautiful HTML report
- `--stack` : Show tech stack insights (default in detailed mode)

---

## 📝 Changelog

### v2.0 (June 2026) - Major Upgrade
- Massive fingerprint expansion (250+ technologies)
- Weighted confidence scoring
- Advanced multi-source version detection
- HTML report generation
- Tech stack relationship detection
- Improved CVE relevance
- Performance optimizations

### v1.3 (June 2026)
- Added 70+ new fingerprints (Go, Rust, SvelteKit, Solid.js, Qwik, Remix, NestJS, Strapi, Sanity, etc.)
- Improved patterns and version extraction

(Previous versions in git history)

---

## 📝 License

MIT License

Made with ❤️ by anondrox
