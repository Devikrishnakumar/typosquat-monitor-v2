# 🛠️ Development & Improvement Roadmap

This document outlines key technical improvements, architectural refactorings, and feature extensions to take the **Typosquat & Brand Impersonation Monitor** from an MVP to a high-throughput, enterprise-ready security platform.

---

## 🚀 1. Asynchronous & Multi-Worker Architecture

### Current Limitation
In `src/ingest/ct_stream_client.py`, incoming WebSocket messages are processed synchronously in `on_message()`. When a domain is flagged as suspicious, the system immediately runs DNS checks and launches Playwright Chromium to capture a screenshot (taking 5 to 20 seconds). During this time, the WebSocket loop is blocked, causing incoming Certificate Transparency (CT) messages to queue up or drop.

### Proposed Improvement
Decouple Ingestion from Enrichment using an asynchronous message queue (e.g. `asyncio.Queue`, `Redis`, or `Celery`):

```
[ CT WebSocket Stream ] ──(fast non-blocking filter)──► [ Redis / Async Queue ]
                                                                │
                                            ┌───────────────────┼───────────────────┐
                                            ▼                   ▼                   ▼
                                     [ Worker 1 ]        [ Worker 2 ]        [ Worker N ]
                                    (DNS + Screenshot)  (DNS + Screenshot)  (DNS + Screenshot)
```

**Implementation Steps:**
- Convert `ct_stream_client.py` to use `aiohttp` or `websockets` for async I/O.
- Push candidate domains into a worker pool (`concurrent.futures.ThreadPoolExecutor` or `asyncio` task group).
- Allow CT stream ingestion to run continuously at peak volume (>1,000 certs/sec).

---

## 🗄️ 2. Database & ORM Upgrade

### Current Limitation
`src/storage/db.py` uses raw SQLite queries and opens/closes a connection per helper function invocation.

### Proposed Improvement
- **Upgrade to SQLAlchemy ORM / Alembic**:
  - Structured schema migrations (`alembic`).
  - Native connection pooling.
  - Support for PostgreSQL / MySQL in production environments.
- **Add Candidate Lifecycle Management**:
  - Add status tracking fields: `new`, `under_investigation`, `takedown_requested`, `resolved`, `false_positive`.
  - Add audit timestamps and analyst notes.

---

## 🧠 3. Advanced Threat Enrichment & Machine Learning

### Current Limitation
Visual similarity uses perceptual hashing (`imagehash.phash`), which is fast and lightweight but sensitive to minor structural layout changes.

### Proposed Improvement
1. **Deep Learning / Computer Vision Embeddings**:
   - Integrate a lightweight pre-trained model (e.g. ResNet-18 or MobileNet) or OpenCV Structural Similarity Index (SSIM) to evaluate visual identity theft with higher precision.
2. **Subdomain & Mail Server (MX/SPF/DMARC) Signals**:
   - Check MX records (`dns.resolver`) to detect if the lookalike domain has active email infrastructure configured for spear-phishing campaigns.
   - Inspect SPF/DMARC TXT records.
3. **SSL Certificate Metadata Inspection**:
   - Check SSL issuer (e.g. Let's Encrypt / ZeroSSL vs enterprise CA), validity duration, and SAN count. Phishing domains frequently use free, short-lived certificates with single SAN entries.
4. **Favicon Hashing**:
   - Compute MMH3 hash of `/favicon.ico` and cross-reference with known brand favicon hashes (similar to Shodan / Censys search signatures).

---

## 🔌 4. REST API & Webhook Integration

### Proposed Features
Build a **FastAPI** backend interface to allow integration with Enterprise Security Operations Centers (SOC):

- `GET /api/candidates`: Query candidates filtered by risk score, brand, status, or date range.
- `POST /api/candidates/{id}/takedown`: Trigger manual PDF generation and dispatch.
- `POST /api/webhooks`: Send real-time alerts to Slack, Microsoft Teams, Jira Security Desk, or SIEM platforms (Splunk, Microsoft Sentinel).

---

## 🐳 5. Containerization & Production Deployment

### Docker Multi-Container Setup
Create a `docker-compose.yml` to run the full stack seamlessly in containerized environments:

```yaml
version: '3.8'

services:
  certstream-server:
    build: ./certstream_server_go
    ports:
      - "8081:8081"

  monitor-worker:
    build: .
    command: python -m src.ingest.ct_stream_client
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/typosquat
    depends_on:
      - certstream-server
      - db

  dashboard:
    build: .
    command: streamlit run dashboard/app.py --server.port=8501
    ports:
      - "8501:8501"
    depends_on:
      - db

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: typosquat
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

---

## 🧪 6. Comprehensive Test Suite

### Improvements
- Expand unit test coverage across `src/enrichment/` using `pytest`.
- Add mock network responses (`responses` / `pytest-mock`) for RDAP, DNS, and WebSocket events so tests run reliably offline.
- Add CI/CD GitHub Actions workflow for linting (`flake8` / `black`) and automated test execution.
