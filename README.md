# ThreatMesh 3D

Real-Time AI-Powered Cyber Threat Intelligence and Visualization Platform.

ThreatMesh 3D fetches live vulnerability data (CVEs), cross-references it against actively exploited threats, classifies each one against the MITRE ATT&CK framework using AI, and renders the result as an interactive 3D dashboard — with a second AI agent that double-checks any classification it wasn't fully confident about.

## Features

- **Live CVE Ingestion** — Rolling delta fetch from the NVD API, with a capped lookback window to stay reliable under real-world API conditions.
- **CISA KEV Cross-Reference** — Flags CVEs confirmed to be actively exploited in the wild, not just theoretically vulnerable.
- **AI Threat Classification** — Maps each actively exploited CVE to up to two MITRE ATT&CK techniques (an attack chain), each with a confidence level and supporting evidence extracted from the CVE's own description.
- **Multi-Agent Verification** — A second AI agent independently reviews any classification the first agent wasn't fully confident about, and confirms, revises, or flags it as insufficient.
- **Attack-Path Visualization** — Connects CVEs that share a vendor and product, surfacing patterns across the threat landscape.
- **Interactive 3D Dashboard** — Severity-colored, KEV-highlighted nodes rendered with React Three Fiber; click any node for full detail.
- **Automated PDF Report Export** — Generates an on-demand PDF with a severity summary and a table of the top 30 actively exploited CVEs.
- **Centralized Broadcast Architecture** — A single background task fetches and analyzes data once per cycle and sends the result to every connected client, so external API usage does not grow with the number of open browser tabs.

## Architecture

The system runs as a three-stage pipeline:

1. **Ingestion** — Pulls from the NVD API, the CISA KEV feed, and the MITRE ATT&CK dataset (fetched once at startup).
2. **Processing & Enrichment** — Merges and deduplicates the data, extracts vendor/product info, classifies threats with the primary AI agent, sends uncertain results to the verifier agent, and builds attack-path relationships.
3. **Client Visualization** — Broadcasts the result over WebSocket to a 3D dashboard, with an on-demand PDF export path alongside it.

See `docs/architecture-diagram.svg` for the full visual pipeline.

## Tech Stack

- **Backend:** Python, FastAPI, uvicorn, httpx, the OpenAI-compatible client (used with Gemini), ReportLab
- **Frontend:** React, Vite, Three.js, React Three Fiber (with drei), Tailwind CSS v4

## Setup

### Prerequisites
- Python 3.14 (tested with 3.14.7; other versions were not tested)
- Node.js and npm (tested with Node.js 24.20.0 and npm 12.0.2; other versions were not tested)
- A [Gemini API key](https://ai.google.dev/gemini-api/docs)
- An [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (optional, but strongly recommended — the default rate limit without one is much lower)

### Backend

```bash
cd backend
pip install fastapi "uvicorn[standard]" httpx openai reportlab
```

Set the API keys as environment variables. The server reads them directly, so a `.env` file is not loaded. In Windows PowerShell (current session only):

```
$env:GEMINI_API_KEY="your_key_here"
$env:NVD_API_KEY="your_key_here"
```

On macOS or Linux, use `export GEMINI_API_KEY=your_key_here` and `export NVD_API_KEY=your_key_here` instead. On Windows, `setx` keeps a variable permanently.

Run the server:

```bash
python main.py
```

The server starts on `http://127.0.0.1:8000`. Type `q` and press Enter in the terminal to shut it down cleanly.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the printed local URL (typically `http://localhost:5173`) in a browser.

## Configuration

Key tunable constants, all in `backend/main.py`:

| Constant | Purpose |
|---|---|
| `AI_SAMPLE_SIZE` | How many new CVEs the classifier processes per cycle |
| `VERIFICATION_CHUNK_SIZE` | How many flagged CVEs each verifier agent call handles |
| `MAX_DELTA_WINDOW` | Caps how far back a single NVD update request can look |
| `MAX_NODES` | Total node cap held in memory at once |
| `MIN_NON_KEV_NODES` | When the node limit is reached, this many of the newest non-exploited nodes are kept and the rest of the space goes to exploited nodes, so non-exploited nodes are never fully evicted |

## Known Limitations

- **No database, by design** — all data is fetched live and held only in memory; it resets on every server restart. The working dataset is small enough that this is a deliberate simplicity choice, not an oversight.
- **Local, single-developer demonstration** — there is no deployment plan or public hosting; this runs on `localhost` for evaluation and portfolio purposes.
- **Developer-led testing** — the system was tested by the developer against live data; formal user acceptance testing was not performed because the project has no external users.
- **AI output is a decision aid, not ground truth** — the ATT&CK mapping comes from an AI model. A second agent reviews low-confidence results, but neither agent is guaranteed to be right, so a person should check the results before acting on them.
- **Exploited CVEs get the AI analysis** — only CVEs listed in the CISA KEV catalog are sent to the AI, up to 40 new ones per cycle. Other CVEs show a standard advisory note.
- **Local use only** — the server accepts requests from any origin (open CORS) and has no login, so it should run only on `127.0.0.1` and should not be exposed to a network.

## Project Status

All four months of the project plan are finished, with some changes from the original plan: the 3D layout uses fixed hash-based positions instead of a force-directed layout, the AI analysis covers exploited (CISA KEV) CVEs only, exploited CVEs are marked with a pulsing ring but there is no separate alert feature, and there is no deployment guide because the project runs locally only. The work covered backend and NVD integration, real-time streaming with CISA KEV and AI analysis, MITRE ATT&CK mapping with attack-path visualization, and multi-agent verification with automated PDF reporting.

## References

1. MITRE Corporation. (2026). *Cyber threat intelligence repository (ATT&CK STIX data)* [Data set]. GitHub. https://github.com/mitre/cti
2. National Institute of Standards and Technology. (n.d.). *NVD vulnerability API and CPE configuration documentation.* https://nvd.nist.gov/developers/vulnerabilities
3. Cybersecurity and Infrastructure Security Agency. (n.d.). *Known Exploited Vulnerabilities Catalog.* https://www.cisa.gov/known-exploited-vulnerabilities-catalog
4. Google. (2026). *Gemini API documentation.* https://ai.google.dev/gemini-api/docs
5. Poimandres. (n.d.). *React Three Fiber documentation.* https://docs.pmnd.rs/react-three-fiber
6. ReportLab. (n.d.). *ReportLab PDF library documentation.* https://docs.reportlab.com