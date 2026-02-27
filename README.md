<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:0a1628,100:00d4ff&height=200&section=header&text=🛡️%20AEGIS%20CDR&fontSize=52&fontColor=00d4ff&fontAlignY=38&desc=AI-Powered%20Content%20Disarm%20%26%20Reconstruction%20Engine&descAlignY=58&descColor=c9d8f0&descSize=18" width="100%"/>

<br/>

<!-- Technology Badges -->
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![PyMuPDF](https://img.shields.io/badge/PyMuPDF-FF6B35?style=for-the-badge&logo=adobeacrobatreader&logoColor=white)
![LangChain](https://img.shields.io/badge/LangChain-1C3C3C?style=for-the-badge&logo=chainlink&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-F55036?style=for-the-badge&logo=groq&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)

<br/>

<!-- Status Badges -->
![Status](https://img.shields.io/badge/Status-Production%20Ready-00ff9d?style=flat-square&logo=checkmarx&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat-square&logo=github)
![Made with Love](https://img.shields.io/badge/Made%20with-❤️-red?style=flat-square)
![Security](https://img.shields.io/badge/Security-Zero%20Trust%20CDR-ff3c3c?style=flat-square&logo=shield&logoColor=white)

<br/>

<p align="center">
  <a href="#-quick-start">🚀 Quick Start</a> •
  <a href="#-how-aegis-works">⚙️ How It Works</a> •
  <a href="#-api-reference">📡 API Docs</a> •
  <a href="#-threat-detection-coverage">🎯 Coverage</a> •
  <a href="#-roadmap">🗺️ Roadmap</a>
</p>

<br/>

> **Aegis-CDR** is not a virus scanner — it's a **Content Disarm & Reconstruction** system.
> It deconstructs every PDF and DOCX file into atomic components, surgically strips all active threats,
> and rebuilds a pixel-perfect, mathematically safe document.
> Powered by **Groq LLaMA 3.3-70B** for AI-driven threat intelligence.

</div>

---

## 📋 Table of Contents

- [🔍 What is CDR?](#-what-is-cdr)
- [⚙️ How Aegis Works](#️-how-aegis-works)
- [🏗️ Architecture](#️-architecture)
- [✨ Features](#-features)
- [🧰 Tech Stack](#-tech-stack)
- [🚀 Quick Start](#-quick-start)
- [📁 Project Structure](#-project-structure)
- [📡 API Reference](#-api-reference)
- [🎯 Threat Detection Coverage](#-threat-detection-coverage)
- [📊 Risk Scoring Engine](#-risk-scoring-engine)
- [🖥️ Frontend Interface](#️-frontend-interface)
- [🧪 Testing](#-testing)
- [🗺️ Roadmap](#️-roadmap)
- [🤝 Contributing](#-contributing)
- [⚠️ Disclaimer](#️-disclaimer)

---

## 🔍 What is CDR?

**Content Disarm & Reconstruction (CDR)** is a cybersecurity technique that goes far beyond traditional antivirus. Instead of asking *"Is this file malicious?"* — which fails against zero-days — CDR **assumes every file is potentially dangerous** and treats it accordingly.

```
┌─────────────────────────────────────────────────────────────┐
│                    THE CDR PHILOSOPHY                        │
├──────────────────────┬──────────────────────────────────────┤
│  Traditional AV      │  Aegis CDR                           │
├──────────────────────┼──────────────────────────────────────┤
│  File → Scan         │  File → Decompose                    │
│  "Is this bad?"      │  "What is active content?"           │
│  ALLOW or BLOCK      │  Strip ALL active content            │
│  Fails on zero-days  │  Rebuild clean from safe parts       │
│  ~99% detection      │  100% — no active content can exist  │
└──────────────────────┴──────────────────────────────────────┘
```

The reconstructed document looks **identical** to the original — all text, images, and formatting preserved — but is **mathematically impossible** to contain executable threats.

---

## ⚙️ How Aegis Works

Aegis-CDR processes every document through **4 hardened security layers**:

```
  ╔══════════════════════════════════════════════════════════╗
  ║                   AEGIS-CDR PIPELINE                     ║
  ╚══════════════════════════════════════════════════════════╝

  📥  UNTRUSTED FILE (PDF / DOCX)
       │
       ▼
  ╔═══════════════════════════════════════════════════════╗
  ║  LAYER 1 ── INGESTION & FINGERPRINTING               ║
  ║                                                       ║
  ║  • Reads first 8 bytes — true magic number detection ║
  ║  • Detects real MIME type, ignores file extension     ║
  ║  • Blocks MZ (PE .exe), ELF, shell scripts in        ║
  ║    disguise                                           ║
  ║  • For ZIP-based files: inspects [Content_Types].xml ║
  ║    to confirm genuine OOXML structure                 ║
  ╚═══════════════════════════════════════════════════════╝
       │  ✅ PASS / 🚨 BLOCKED
       ▼
  ╔═══════════════════════════════════════════════════════╗
  ║  LAYER 2 ── DECOMPOSITION ENGINE                     ║
  ║                                                       ║
  ║  PDF:  Iterates every xref object in the PDF tree    ║
  ║        Scans dictionary keys for threat signatures   ║
  ║  DOCX: Unzips OPC package, maps all XML parts        ║
  ║        Reads all relationship files (.rels)           ║
  ║  • Builds complete threat surface map                 ║
  ║  • Records all active content locations              ║
  ╚═══════════════════════════════════════════════════════╝
       │
       ▼
  ╔═══════════════════════════════════════════════════════╗
  ║  LAYER 3 ── SANITIZATION (DISARM)                    ║
  ║                                                       ║
  ║  PDF:  xref_set_key() nulls dangerous dict entries   ║
  ║        Removes /JavaScript /OpenAction /AA /Launch   ║
  ║        /EmbeddedFile /RichMedia /Sound /Movie        ║
  ║  DOCX: Deletes vbaProject.bin, customXml/, activeX/  ║
  ║        Strips attachedTemplate from .rels files      ║
  ║        Scrubs DDEAUTO, MACROBUTTON fields in XML     ║
  ║        Neutralizes external hyperlinks → "#"         ║
  ╚═══════════════════════════════════════════════════════╝
       │
       ▼
  ╔═══════════════════════════════════════════════════════╗
  ║  LAYER 4 ── RECONSTRUCTION + AI SENTRY               ║
  ║                                                       ║
  ║  PDF:  Incremental save — appends only delta bytes   ║
  ║        Output size ≈ input size (no re-encoding)     ║
  ║  DOCX: Re-zips clean package with sanitized XML      ║
  ║  AI:   Groq LLaMA 3.3-70B analyzes threat report    ║
  ║        Generates natural-language security summary   ║
  ║        Risk score 0-100 + visual integrity check     ║
  ║  📤 CLEAN FILE + JSON THREAT INTELLIGENCE REPORT    ║
  ╚═══════════════════════════════════════════════════════╝
```

### 🛡️ PDF Sanitization Modes

Aegis uses a **3-tier fallback strategy** for PDF processing:

| Mode | When Used | Output Quality | Size Impact |
|------|-----------|----------------|-------------|
| **Scrub + Incremental Save** | Default — all clean PDFs | Perfect fidelity | ≈ Same as input |
| **Full Reconstruction** | When scrub mode fails | High fidelity | +10–15% |
| **Pixel-Only Fallback** | When risk score ≥ 75 or reconstruction fails | Rasterized (not searchable) | Variable |

---

## 🏗️ Architecture

```
aegis-cdr/
├── 🔌 api/
│   └── main.py                 # FastAPI REST API + static frontend serving
│
├── 🧠 core/
│   ├── pdf/
│   │   └── sanitizer.py        # 4-mode PDF CDR engine
│   ├── docx/
│   │   └── sanitizer.py        # DOCX ZIP/XML surgical disarming
│   └── ai/
│       └── sentry.py           # Groq LLM threat intelligence layer
│
├── 🛠️ utils/
│   └── validator.py            # SafeTypeValidator — magic byte fingerprinting
│
├── 📋 rules/
│   └── aegis_rules.yar         # 13 YARA detection patterns
│
├── 🌐 static/
│   └── index.html              # Complete frontend — zero npm, zero dependencies
│
├── 🧪 create_test_files.py     # Generates malicious test files for validation
├── ⚡ aegis_standalone.py      # CLI — test without starting API
├── 📄 .env.example             # Environment configuration template
└── 📦 requirements.txt         # Python dependencies
```

---

## ✨ Features

<details>
<summary><b>🔒 Security Engine — Click to expand</b></summary>

| Feature | Detail |
|---------|--------|
| **Magic Byte Validation** | Reads true binary signature — extension is irrelevant |
| **Extension Spoof Detection** | Catches `.exe` renamed to `.pdf`, PE headers in `.docx` |
| **PDF JavaScript Removal** | Strips `/JavaScript`, `/JS` from all xref objects |
| **OpenAction Disarming** | Removes auto-execute triggers from document catalog |
| **Additional Actions (AA)** | Strips page-level and field-level event handlers |
| **Launch Action Blocking** | Removes shell command execution annotations |
| **EmbeddedFile Extraction** | Detects and removes attached file payloads |
| **Rich Media Stripping** | Removes Flash/video embedding (historic exploit vector) |
| **Widget Annotation Removal** | Strips interactive form fields with action triggers |
| **PostScript XObject Detection** | Flags `/XObject` + `/PS` — used in CVE exploitation |
| **VBA Macro Removal** | Deletes `vbaProject.bin` (verified by OLE2 magic bytes) |
| **Remote Template Blocking** | Strips `attachedTemplate` external DOTM injection |
| **DDE Field Stripping** | Removes `DDEAUTO`, `DDE`, `MACROBUTTON` fields |
| **OLE Object Blocking** | Removes embedded OLE2 executable objects |
| **ActiveX Removal** | Deletes `word/activeX/` directory entirely |
| **External Link Neutralization** | Replaces tracking/phishing URLs with `#` |
| **Custom XML Blocking** | Removes `customXml/` parts (data injection vector) |
| **Pixel-Only Fallback** | Emergency rasterization — output is pure images, zero attack surface |

</details>

<details>
<summary><b>🤖 AI Intelligence Layer — Click to expand</b></summary>

| Feature | Detail |
|---------|--------|
| **Groq LLaMA 3.3-70B** | State-of-the-art LLM for threat narrative generation |
| **Natural Language Reports** | Plain-English explanation of every threat found |
| **Contextual Risk Reasoning** | AI understands *why* each threat is dangerous |
| **Risk Score 0–100** | Weighted cumulative scoring across all threat types |
| **5 Risk Levels** | CLEAN / LOW / MEDIUM / HIGH / CRITICAL |
| **Threat Categorization** | Groups into: Scripts, Macros, Links, Embedded Objects, Auto-Execute |
| **Visual Integrity Check** | Compares original vs clean page count |
| **Model Selection** | Configurable: llama-3.3-70b / llama-3.1-8b / mixtral-8x7b |
| **Rule-Based Fallback** | Fully deterministic scoring — works with no API key |

</details>

<details>
<summary><b>🖥️ Frontend Interface — Click to expand</b></summary>

| Feature | Detail |
|---------|--------|
| **Zero Dependencies** | Single HTML file — no npm, no Node.js, no build step |
| **Drag & Drop Upload** | Drop PDF or DOCX directly, with animated feedback |
| **Processing Animation** | 5-step pipeline visualization while scanning |
| **Animated Risk Gauge** | SVG ring meter animates from 0 to threat score |
| **Color-Coded Risk Level** | Green → Cyan → Gold → Orange → Red based on score |
| **Threat Breakdown Bars** | Animated category bars with per-category counts |
| **Threat Item List** | Individual threat descriptions for ≤15 threats |
| **Stats Dashboard** | Threats found, original size, clean size, processing time, pages |
| **Groq AI Report** | Full natural-language analysis with model attribution |
| **One-Click Download** | Download sanitized file directly from results |
| **Cyberpunk Aesthetic** | Dark theme, grid background, scan-line animation, glowing accents |

</details>

---

## 🧰 Tech Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| ![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white&style=flat) | **Python** | 3.10+ | Core engine language |
| ![FastAPI](https://img.shields.io/badge/-FastAPI-009688?logo=fastapi&logoColor=white&style=flat) | **FastAPI** | 0.111 | REST API + static file serving |
| ![PyMuPDF](https://img.shields.io/badge/-PyMuPDF-FF6B35?logo=adobeacrobatreader&logoColor=white&style=flat) | **PyMuPDF (fitz)** | 1.24 | PDF parsing, xref surgery, incremental save |
| ![python-docx](https://img.shields.io/badge/-python--docx-2B579A?logo=microsoftword&logoColor=white&style=flat) | **python-docx** | 1.1 | OOXML ZIP manipulation |
| ![LangChain](https://img.shields.io/badge/-LangChain-1C3C3C?logo=chainlink&logoColor=white&style=flat) | **LangChain** | 0.2 | LLM orchestration framework |
| ![Groq](https://img.shields.io/badge/-Groq-F55036?logo=groq&logoColor=white&style=flat) | **Groq API** | — | Ultra-fast LLM inference |
| ![LLaMA](https://img.shields.io/badge/-LLaMA_3.3_70B-0467DF?logo=meta&logoColor=white&style=flat) | **LLaMA 3.3-70B** | — | Threat narrative generation |
| ![YARA](https://img.shields.io/badge/-YARA-FF0000?logo=virustotal&logoColor=white&style=flat) | **YARA** | 4.5 | Pattern-based malware detection |
| ![HTML5](https://img.shields.io/badge/-HTML5-E34F26?logo=html5&logoColor=white&style=flat) | **Vanilla JS + HTML5** | ES2024 | Zero-dependency browser frontend |
| ![lxml](https://img.shields.io/badge/-lxml-2B7BB9?logo=python&logoColor=white&style=flat) | **lxml** | 5.2 | XML processing for DOCX parts |

---

## 🚀 Quick Start

### Prerequisites

- Python **3.10+**
- A **Groq API key** — get one free at [console.groq.com](https://console.groq.com/)
- Git

### Step 1 — Clone & Install

```bash
# Clone the repository
git clone https://github.com/Nauman123-coder/aegis-cdr.git
cd aegis-cdr

# Create virtual environment
python -m venv .venv

# Activate (Windows Git Bash)
source .venv/Scripts/activate

# Activate (Linux / macOS)
source .venv/bin/activate

# Install all dependencies
pip install -r requirements.txt
```

### Step 2 — Configure Groq

```bash
# Copy the environment template
cp .env.example .env
```

Open `.env` and add your key:

```env
# Required
GROQ_API_KEY=gsk_your_groq_api_key_here

# Optional — choose your model
GROQ_MODEL=llama-3.3-70b-versatile
```

> **Model Options:**
> | Model | Speed | Quality | Best For |
> |-------|-------|---------|----------|
> | `llama-3.1-8b-instant` | ⚡⚡⚡ | ★★★ | High-volume scanning |
> | `llama-3.3-70b-versatile` | ⚡⚡ | ★★★★★ | **Recommended** |
> | `mixtral-8x7b-32768` | ⚡⚡ | ★★★★ | Long documents |

### Step 3 — Launch

```bash
uvicorn api.main:app --reload
```

**That's it.** Open **`http://localhost:8000`** — the full drag-and-drop UI loads instantly.
No npm. No Node.js. No second terminal. No build step.

---

## 📁 Project Structure

```
aegis-cdr/
│
├── api/
│   └── main.py              ← FastAPI application
│                              POST /api/sanitize — main CDR endpoint
│                              GET  /api/download/{token} — file download
│                              GET  /api/health — Groq status check
│                              GET  / — serves the frontend
│
├── core/
│   ├── pdf/
│   │   └── sanitizer.py     ← PDF CDR Engine
│   │                          _scan_for_threats()  — xref/annotation scanner
│   │                          _scrub_inplace()     — surgical key removal
│   │                          _pixel_only_fallback() — emergency rasterizer
│   │
│   ├── docx/
│   │   └── sanitizer.py     ← DOCX CDR Engine
│   │                          Unzips OPC package
│   │                          Strips .rels, deletes vbaProject.bin
│   │                          Scrubs document.xml fields
│   │                          Re-zips clean package
│   │
│   └── ai/
│       └── sentry.py        ← AI Sentry (Groq Integration)
│                              summarize() — Groq LLM narrative
│                              risk_score() — weighted 0-100 scoring
│                              categorize_threats() — grouping engine
│
├── utils/
│   └── validator.py         ← SafeTypeValidator
│                              detect_true_type() — magic byte detection
│                              validate_extension_matches() — spoof check
│
├── rules/
│   └── aegis_rules.yar      ← 13 YARA Detection Rules
│                              PDF_Embedded_JavaScript
│                              PDF_OpenAction_AutoLaunch
│                              PDF_Heap_Spray_Pattern
│                              DOCX_VBA_Macro_Present
│                              DOCX_External_Template_Injection (T1221)
│                              DOCX_DDE_Injection (T1559.002)
│                              Generic_Suspicious_PowerShell
│                              Generic_Base64_Shellcode
│                              + 5 more
│
├── static/
│   └── index.html           ← Complete Frontend (620 lines, zero deps)
│                              Drag-drop upload zone
│                              5-step processing animation
│                              Animated SVG risk gauge
│                              Threat breakdown bar charts
│                              Groq AI analysis panel
│                              Download button
│
├── create_test_files.py     ← Test File Generator
│                              malicious_test.pdf (5 threat types)
│                              malicious_test.docx (8 threat types)
│                              spoofed_exe.pdf (MZ magic in .pdf)
│
├── aegis_standalone.py      ← CLI Interface
├── .env.example             ← Environment template
└── requirements.txt         ← Python dependencies
```

---

## 📡 API Reference

### `POST /api/sanitize`

Upload a PDF or DOCX — receive a full threat intelligence report and download token.

**Request**
```
Content-Type: multipart/form-data
Body: file=<binary>
```

**Response**
```json
{
  "status": "sanitized",
  "original_filename": "invoice.pdf",
  "sanitized_filename": "SAFE_invoice.pdf",
  "true_mime_type": "application/pdf",
  "file_size_original": 816384,
  "file_size_sanitized": 798720,
  "processing_time_ms": 1247,
  "page_count_original": 15,
  "page_count_sanitized": 15,
  "items_removed_count": 13,
  "threat_categories": [
    {
      "name": "Scripts & JavaScript",
      "items": [
        "Document Catalog xref 1: /JavaScript detected and stripped",
        "Threat in xref 1: /JS",
        "Threat in xref 3: /JavaScript"
      ],
      "icon": "⚡"
    },
    {
      "name": "Auto-Execute Actions",
      "items": [
        "Document Catalog xref 1: /OpenAction detected and stripped",
        "Threat in xref 1: /AA"
      ],
      "icon": "🚀"
    }
  ],
  "risk": {
    "score": 100,
    "level": "CRITICAL",
    "color": "#ff1a1a",
    "rationale": "Embedded JavaScript; Auto-execute on open; Shell launch command"
  },
  "ai_summary": "A thorough analysis of invoice.pdf revealed critical threats including JavaScript and OpenAction exploits, which could have allowed arbitrary code execution and unauthorized system access if not neutralized. The removal of 13 malicious items has mitigated the risk of these exploits being used to compromise system security. The document is now safe for use, with all identified threats stripped and visual integrity confirmed at 15 pages.",
  "groq_powered": true,
  "fallback_used": false,
  "download_token": "aegis_1709123456_SAFE_invoice.pdf"
}
```

**Error Responses**

| Status | Error Code | Description |
|--------|-----------|-------------|
| `415` | `FILE_BLOCKED` | Magic bytes indicate dangerous file type |
| `415` | `UNSUPPORTED_TYPE` | Not PDF or DOCX |
| `500` | `SANITIZATION_FAILED` | Internal processing error |

---

### `GET /api/download/{token}`

Download the sanitized file by token.

```bash
curl http://localhost:8000/api/download/aegis_1709123456_SAFE_invoice.pdf \
  --output SAFE_invoice.pdf
```

---

### `GET /api/health`

Check server status and Groq configuration.

```json
{
  "status": "operational",
  "version": "2.0.0",
  "groq": {
    "configured": true,
    "model": "llama-3.3-70b-versatile"
  },
  "ui": "http://localhost:8000",
  "supported_formats": ["PDF", "DOCX"]
}
```

---

## 🎯 Threat Detection Coverage

### PDF Threat Matrix

| Threat | PDF Key | Points | Impact |
|--------|---------|--------|--------|
| Embedded JavaScript | `/JavaScript`, `/JS` | +40 | Arbitrary code execution on open |
| Auto-Execute Action | `/OpenAction` | +30 | Triggers immediately when PDF opens |
| Additional Actions | `/AA` | +25 | Page/annotation/field event triggers |
| Shell Launch | `/Launch` | +50 | Spawns external process (cmd.exe, bash) |
| Embedded File | `/EmbeddedFile` | +20 | Attached payload (exe, dll, bat) |
| Rich Media | `/RichMedia` | +30 | Flash/video execution context |
| Form Widget | `/Widget` | +20 | Interactive field with action trigger |
| PostScript XObject | `/XObject + /PS` | +35 | PostScript code injection |
| External URI | `/URI` | +10 | Tracking pixel / SSRF / phishing |

### DOCX Threat Matrix

| Threat | Location | Points | Impact |
|--------|----------|--------|--------|
| VBA Macros | `vbaProject.bin` | +45 | AutoOpen/AutoExec code execution |
| Remote Template | `attachedTemplate` rel | +30 | Loads macro payload from remote URL |
| DDE Field | `DDEAUTO` in instrText | +35 | Dynamic Data Exchange cmd.exe execution |
| Macro Button | `MACROBUTTON` field | +40 | Click-triggered macro execution |
| OLE Object | `word/embeddings/` | +35 | Embedded executable object |
| ActiveX Control | `word/activeX/` | +40 | Script-executable browser control |
| External Hyperlink | `word/_rels/` | +10 | Tracking/phishing/SSRF link |
| Custom XML | `customXml/` | +10 | Schema-based data injection |

### YARA Rules (13 Patterns)

```
PDF_Embedded_JavaScript         — /JS and /JavaScript in PDF streams
PDF_OpenAction_AutoLaunch       — /OpenAction trigger detection
PDF_Heap_Spray_Pattern          — Large repeated NOP sled patterns
PDF_Suspicious_URI              — Encoded/obfuscated URI actions
DOCX_VBA_Macro_Present          — OLE2 vbaProject.bin signature
DOCX_External_Template_Injection — MITRE ATT&CK T1221
DOCX_DDE_Injection              — MITRE ATT&CK T1559.002
DOCX_Macro_Auto_Execute         — AutoOpen/AutoExec triggers
Generic_Suspicious_PowerShell   — Encoded PowerShell download cradles
Generic_Base64_Shellcode        — Base64-encoded executable payloads
Generic_URL_Obfuscation         — Hex/percent-encoded malicious URLs
Generic_PE_In_Document          — MZ magic bytes inside document stream
Generic_OLE_Embedded            — OLE2 compound document signature
```

---

## 📊 Risk Scoring Engine

Aegis computes a cumulative risk score based on all threats found:

```
Score = Σ(threat_points) capped at 100
```

| Score | Level | Color | Indicator |
|-------|-------|-------|-----------|
| 0 | ✅ **CLEAN** | `#00ff9d` | No active content |
| 1 – 19 | 🔵 **LOW** | `#00c9ff` | Tracking links or custom XML only |
| 20 – 39 | 🟡 **MEDIUM** | `#ffd700` | Embedded files or form widgets |
| 40 – 69 | 🟠 **HIGH** | `#ff6b35` | VBA macros, DDE injection, OLE objects |
| 70 – 100 | 🔴 **CRITICAL** | `#ff1a1a` | JavaScript, LaunchAction, or pixel fallback |

**Example Scoring:**

```
Document with VBA macro (+45) + DDE injection (+35) + 2 hyperlinks (+20) = 100 → CRITICAL
Document with 3 tracking hyperlinks only (+30) = 30 → MEDIUM
Clean research paper = 0 → CLEAN ✅
```

---

## 🖥️ Frontend Interface

The entire frontend is a **single self-contained HTML file** (`static/index.html`) served directly by FastAPI. No npm, no Node.js, no build tools required.

### UI States

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   DROP ZONE   │───▶│  PROCESSING  │───▶│   RESULTS    │───▶│  DOWNLOAD    │
│               │    │              │    │              │    │              │
│  Drag & Drop  │    │ Step-by-step │    │  Risk Gauge  │    │  SAFE_*.pdf  │
│  or Browse    │    │  animation   │    │  Threat Bars │    │  or .docx    │
│               │    │  5 stages    │    │  AI Report   │    │              │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

### Processing Stages (animated in UI)

1. 🔍 Fingerprinting magic bytes
2. 🧩 Decomposing component tree
3. 💣 Disarming active content
4. 🏗️ Reconstructing clean document
5. 🤖 Groq AI Sentry analysis

### Design System

```
Background:  #060a10 (near-black)
Surface:     #0c1220 / #111827
Accent:      #00d4ff (cyan)
Success:     #00ff9d (green)
Danger:      #ff3c3c (red)
Warning:     #ffd700 (gold)
Font:        Share Tech Mono + Rajdhani (Google Fonts)
Effects:     Animated grid, corner glows, scan-line, SVG ring meter
```

---

## 🧪 Testing

### Generate Malicious Test Files

```bash
python create_test_files.py
```

Produces `test_files/` with three validation files:

**`malicious_test.pdf`** — Hand-crafted PDF with 5 real threat structures:
- `/OpenAction` with `/JavaScript` in catalog (auto-runs on open)
- `/AA` Additional Actions on catalog and page
- `/Launch` annotation pointing to `cmd.exe /c calc.exe`
- `/EmbeddedFile` attachment (`malware_payload.exe`)
- `/URI` external tracking link

→ Expected: **Risk CRITICAL (100)** | Threats: 13 | Groq names JS/OpenAction/Launch

---

**`malicious_test.docx`** — Full-threat DOCX with 8 attack vectors:
- `vbaProject.bin` with real OLE2 magic bytes + `AutoOpen` + `Shell` macro
- External template injection via `attachedTemplate`
- `DDEAUTO` field with `cmd.exe + PowerShell -EncodedCommand`
- `MACROBUTTON` field
- 2× external hyperlinks (phishing + tracking pixel)
- ActiveX control with CLSID
- 3× `customXml` parts with base64 payload

→ Expected: **Risk CRITICAL (100)** | Threats: 14 | All 5 categories populated

---

**`spoofed_exe.pdf`** — Windows PE executable with `.pdf` extension:
- MZ magic bytes: `4D 5A 90 00 03 00...`
- Claimed extension: `.pdf`
- True type: `application/x-msdownload`

→ Expected: **🚨 BLOCKED at Layer 1** — never reaches sanitization

---

### CLI Testing

```bash
# Sanitize a single file
python aegis_standalone.py --file document.pdf

# Enable pixel fallback for high-risk files
python aegis_standalone.py --file risky.pdf --pixel-fallback

# Run built-in demo (creates and sanitizes test files automatically)
python aegis_standalone.py --demo

# API health check
curl http://localhost:8000/api/health
```

---

## 🗺️ Roadmap

- [x] PDF CDR engine with incremental save
- [x] DOCX CDR engine with full XML sanitization
- [x] Groq LLM threat intelligence
- [x] Magic byte fingerprinting
- [x] Zero-dependency frontend
- [x] Risk scoring engine
- [x] YARA rule integration
- [ ] **XLSX support** — Spreadsheet CDR (macro-enabled workbooks)
- [ ] **PPTX support** — Presentation CDR
- [ ] **RTF support** — Rich Text Format
- [ ] **Email pipeline** — `.eml` / `.msg` attachment scanning
- [ ] **Batch API** — Async queue for multiple files
- [ ] **Docker container** — One-command deployment
- [ ] **Webhook callbacks** — POST results to external URL
- [ ] **Audit log** — Persistent scan history with search
- [ ] **Password-protected PDF** — Decrypt before sanitize
- [ ] **Report export** — PDF/HTML threat report download

---

## 🤝 Contributing

Contributions are warmly welcome!

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/aegis-cdr.git
cd aegis-cdr

# Set up development environment
python -m venv .venv
source .venv/Scripts/activate   # Windows
source .venv/bin/activate       # Linux/macOS
pip install -r requirements.txt
cp .env.example .env            # Add your GROQ_API_KEY

# Create a feature branch
git checkout -b feature/your-feature-name

# Make changes, then commit
git add .
git commit -m "feat: add XLSX support"

# Push and open PR
git push origin feature/your-feature-name
```

### Contribution Areas

| Area | Description |
|------|-------------|
| 🆕 New file formats | Add XLSX, PPTX, RTF, EML engines |
| 🔍 Detection rules | New YARA rules, threat signatures |
| 🤖 AI improvements | Better prompts, structured Groq output |
| 🎨 Frontend | UI improvements, dark/light theme |
| 📦 Deployment | Docker, CI/CD, cloud deployment guides |
| 📝 Documentation | Examples, tutorials, threat research |

---

## ⚠️ Disclaimer

Aegis-CDR is a security research and document sanitization tool.

- The test files in `create_test_files.py` contain **simulated** threat structures — **no working exploits or actual malware**
- Always run in an isolated environment when processing real-world untrusted files
- Aegis-CDR is a defence tool — do not use to craft malicious documents
- The pixel fallback mode produces rasterized output — text will not be searchable/copyable

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00d4ff,50:0a1628,100:0d1117&height=120&section=footer" width="100%"/>

**Built with 🛡️ by [Nauman Ahmad](https://github.com/Nauman123-coder)**

*Detect. Neutralize. Reconstruct.*

⭐ **Star this repo** if Aegis-CDR helped secure your documents!

[![GitHub stars](https://img.shields.io/github/stars/Nauman123-coder/aegis-cdr?style=social)](https://github.com/Nauman123-coder/aegis-cdr/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Nauman123-coder/aegis-cdr?style=social)](https://github.com/Nauman123-coder/aegis-cdr/network/members)
[![GitHub watchers](https://img.shields.io/github/watchers/Nauman123-coder/aegis-cdr?style=social)](https://github.com/Nauman123-coder/aegis-cdr/watchers)

</div>
