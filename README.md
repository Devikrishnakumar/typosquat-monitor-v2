# 🛡️ Typosquat & Brand Impersonation Monitor

An automated, real-time threat intelligence platform designed to detect, enrich, score, alert, and generate takedown reports for typosquatting, homoglyph, and brand impersonation domains.

---

## 📐 Architecture & Pipeline

```
[ Certificate Transparency (CT) Stream ]
                  │
                  ▼
   [ Ingestion & Permutation Filter ]  ◄── (dnstwist lookalike generator)
                  │
                  ▼
        [ Enrichment Engine ]
         ├─ Punycode / IDN Decoder   (idna: reveals homoglyphs like pаypal.com)
         ├─ DNS Liveness Check        (socket resolution)
         ├─ Headless Screenshot      (Playwright Chromium)
         ├─ Visual Similarity Engine (pHash comparison vs reference screenshot)
         ├─ Content Signal Parser    (BeautifulSoup: login forms, password inputs, text)
         └─ WHOIS / RDAP Lookup       (rdap.org: registrar & abuse contacts)
                  │
                  ▼
        [ Risk Scoring Engine ]      (Weighted composite score 0-100)
                  │
         ┌────────┴────────┐
         ▼                 ▼
  [ SQLite DB ]    [ Incident Response (HIGH Risk) ]
 (data/monitor.db)  ├─ Telegram Alert Bot
         │          └─ Automated PDF Takedown Report (xhtml2pdf + Jinja2)
         ▼
[ Streamlit Web Dashboard ]
 (dashboard/app.py)
```

---

## ✨ Features

- **Real-Time Ingestion**: Connects to Certificate Transparency (CT) log streams via WebSockets to evaluate newly issued SSL/TLS certificates globally.
- **Homoglyph & Punycode Decoding**: Converts Internationalized Domain Names (IDNs) (`xn--...`) into Unicode to expose visual lookalike tricks (e.g., Cyrillic `а` replacing Latin `a`).
- **Visual Similarity Engine**: Captures headless screenshots using **Playwright Chromium** and calculates perceptual hashes (`imagehash.phash`) against official brand reference screenshots.
- **Phishing HTML Extraction**: Parses DOM structures using **BeautifulSoup** for login forms, password input fields, and suspicious credential-harvesting language.
- **Network-Resilient WHOIS**: Queries modern HTTPS-based RDAP (`rdap.org`) for registrar info and abuse contact emails, bypassing raw WHOIS port 43 blocks.
- **Composite Risk Scoring**: Calculates a weighted score ($0 - 100$) categorized into `LOW`, `MEDIUM`, and `HIGH` risk levels.
- **Automated Takedown PDF Generation**: Generates complete legal takedown evidence reports in PDF format with side-by-side screenshot comparisons and registrar details.
- **Instant Alerts**: Sends Markdown-formatted alerts to **Telegram** for high-risk threats.
- **Interactive Security Dashboard**: Real-time **Streamlit** dashboard displaying metrics, threat severity filters, historical detection trends, and screenshot previews.

---

## 📊 Risk Scoring Weights

| Signal | Contribution | Description |
| :--- | :---: | :--- |
| **DNS Liveness** | **25 points** | Domain actively resolves to an IP address. |
| **Visual Similarity** | **35 points** | Perceptual hash distance (`pHash`) vs brand reference screenshot. |
| **Login Form Present** | **25 points** | Form containing `<input type="password">` detected. |
| **Suspicious Phrases** | **15 points** | Contains keywords like *"verify your account"*, *"unusual activity"*. |

- 🔴 **HIGH Risk**: Score $\ge 70$ (Triggers Telegram notification & PDF report generation)
- 🟠 **MEDIUM Risk**: Score $50 - 69$
- 🟢 **LOW Risk**: Score $< 50$

---

## 📁 Repository Structure

```
typosquat-monitor/
├── config/
│   └── brand_config.yaml           # Monitored brand settings
├── certstream_server_go/           # Go-based CT log server configuration
├── dashboard/
│   └── app.py                      # Streamlit live web dashboard
├── data/
│   ├── monitor.db                  # SQLite database
│   └── screenshots/                # Captured candidate screenshots
├── reference_assets/               # Reference brand screenshots & metadata
├── reports/                        # Generated PDF takedown reports
├── src/
│   ├── alerts/
│   │   └── telegram_bot.py         # Telegram alert integration
│   ├── enrichment/
│   │   ├── content_signals.py      # HTML login form & phrase detection
│   │   ├── dns_check.py            # Socket DNS resolution check
│   │   ├── punycode_decoder.py     # IDN / Punycode converter
│   │   ├── screenshot.py           # Playwright headless screenshot engine
│   │   ├── visual_similarity.py    # Perceptual hash comparison
│   │   └── whois_lookup.py         # RDAP registrar & abuse info lookup
│   ├── ingest/
│   │   ├── ct_stream_client.py     # Main CT stream websocket listener
│   │   └── permutation_filter.py   # dnstwist lookalike generator
│   ├── reporting/
│   │   ├── report_generator.py     # Jinja2 + xhtml2pdf engine
│   │   └── templates/
│   │       └── takedown_report.html.j2
│   ├── scoring/
│   │   └── risk_score.py           # Risk calculation logic
│   └── storage/
│       └── db.py                   # SQLite database helper functions
├── demo_high_risk_trigger.py       # Pipeline simulation & PDF generator script
├── test_multi_domain_proof.py      # Multi-domain proof-of-concept test
├── README.md                       # Project overview & documentation
└── DEVELOPMENT.md                  # Future enhancement & technical roadmap
```

---

## 🚀 Quick Start & Installation

### 1. Prerequisites
- Python 3.10+
- `pip` & `venv`

### 2. Environment Setup
Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/gopi-1204/typosquat-monitor.git
cd typosquat-monitor

python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies & Playwright
```bash
pip install python-dotenv dnstwist playwright streamlit xhtml2pdf imagehash jinja2 websocket-client requests pyyaml idna pillow bs4
playwright install chromium
```

---

## 💻 Usage Instructions

### 1. Run the Streamlit Dashboard
Launch the dashboard to monitor live candidate domain metrics and historical trends:
```bash
streamlit run dashboard/app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

### 2. Run the High-Risk Threat Simulation
Simulate a realistic high-risk domain detection, score calculation, and PDF report creation:
```bash
python demo_high_risk_trigger.py
```
*Generated report location:* `reports/takedown_flipkart-secure-login_com.pdf`

### 3. Start Live Monitoring (CT Stream Ingestion)
To stream live Certificate Transparency logs and automatically flag lookalikes:
```bash
# Using default brand from config/brand_config.yaml
python -m src.ingest.ct_stream_client

# Or monitor a specific brand domain via CLI:
python -m src.ingest.ct_stream_client --brand paypal.com
```

---

## 🔔 Setting Up Telegram Alerts (Optional)

Create a `.env` file in the project root:

```env
TELEGRAM_BOT_TOKEN="your_bot_token_here"
TELEGRAM_CHAT_ID="your_chat_id_here"
```

When a `HIGH`-risk candidate is flagged ($\ge 70$), a notification will be pushed to your Telegram chat.

---

## 📄 License
This project is released under the [MIT License](LICENSE).
