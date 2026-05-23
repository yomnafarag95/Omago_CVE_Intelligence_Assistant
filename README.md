<div align="center">

# Omago — CVE Intelligence Assistant

### A RAG-powered cybersecurity assistant for natural language vulnerability analysis

*Queen's University · CSAI 810 · 2025*

[![HuggingFace](https://img.shields.io/badge/Live_Demo-HuggingFace_Spaces-ff9d00?style=for-the-badge&logo=huggingface&logoColor=white)](https://huggingface.co/spaces/yomnafarag95/omago-cve-assistant)
[![Python](https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Groq](https://img.shields.io/badge/LLM-Llama_3.1_70B_via_Groq-f54e42?style=for-the-badge)](https://groq.com)
[![LangChain](https://img.shields.io/badge/Framework-LangChain-1c3c3c?style=for-the-badge)](https://langchain.com)

<br>

![Omago Dashboard](assets/dashboard.png)

<br>

> Security teams spend hours manually cross-referencing NVD entries, CISA advisories, and exploit databases to understand a single vulnerability. Omago answers those questions in natural language — in under 5 seconds.

</div>

---

## What It Does

Omago is a RAG (Retrieval-Augmented Generation) system that lets you ask plain-English questions about CVEs and get grounded, accurate answers pulled from three authoritative sources in real time.

```
"Is CVE-2021-44228 actively exploited?"
      ↓
Omago retrieves context from NVD + CISA KEV + Exploit-DB
      ↓
Llama 3.1-70B synthesises a structured, sourced answer
      ↓
Answer in < 5 seconds
```

---

## Data Sources

| Source | Coverage | CVEs | Freshness | Role |
|:---|:---|:---:|:---:|:---|
| NVD (National Vulnerability Database) | 2020–2024 | 130,000+ | 2–6 hr lag | Primary semantic search layer |
| CISA KEV (Known Exploited Vulnerabilities) | Active | 1,100+ | Weekly | Urgency escalation — confirmed exploits |
| Exploit-DB | Active | 15,000+ | 24–48 hr | Weaponisation proof via exploit code |

All sources are public domain, fetched via NVD REST API, CISA KEV JSON feed, and Exploit-DB bulk CSV.

---

## Architecture

```
User Query (natural language)
         |
         v
  Sentence Transformers
  (semantic embedding)
         |
         v
  FAISS / ChromaDB
  (vector similarity search)
         |
         v
  Retrieved CVE context
  (NVD + CISA KEV + Exploit-DB)
         |
         v
  LangChain RAG pipeline
         |
         v
  Llama 3.1-70B via Groq API
         |
         v
  Structured answer < 5s
```

**Why this stack:**

- **Llama 3.1-70B via Groq** — 86% answer accuracy, 1.8s inference latency, chosen over GPT-4 and Claude for best accuracy/speed/cost balance at $47/mo
- **Sentence Transformers** — semantic embeddings that understand vulnerability descriptions, not just keyword matches
- **FAISS + ChromaDB** — fast approximate nearest-neighbour retrieval over 130K+ CVE vectors
- **LangChain** — orchestrates retrieval, prompt construction, and API calls in a clean pipeline

---

## Interface

Omago has four sections accessible from the sidebar:

| Section | What it does |
|:---|:---|
| **Home** | Conversational interface — ask anything about CVEs |
| **Dashboard** | Overview of indexed CVEs, severity distribution, data source stats |
| **Analysis** | Deep-dive into a specific CVE — CVSS score, exploit status, remediation |
| **CVE Lookup** | Direct search by CVE ID or keyword |

---

## Performance

| Metric | Target | Achieved |
|:---|:---:|:---:|
| Response latency | < 5s | 1.8s (LLM inference) |
| Answer accuracy | > 80% | 86% |
| False retrieval rate | Low | — |

---

## Getting Started

### Prerequisites

- Python 3.8+
- A free [Groq API key](https://console.groq.com)

### Install

```bash
git clone https://github.com/yomnafarag95/Omago_CVE_Intelligence_Assistant.git
cd Omago_CVE_Intelligence_Assistant
pip install langchain groq faiss-cpu sentence-transformers requests
```

### Configure

```bash
cp .env.example .env
# Add your Groq API key to .env:
# GROQ_API_KEY=your_key_here
```

### Ingest data

```bash
python ingest.py
```

This fetches NVD (2020–2024), CISA KEV, and Exploit-DB and builds the vector index. Run once — takes a few minutes on first run.

### Launch

```bash
python app.py
```

Then open the app in your browser and start asking questions.

### Or try the live demo

The app is deployed on HuggingFace Spaces — no setup needed:

[huggingface.co/spaces/yomnafarag95/omago-cve-assistant](https://huggingface.co/spaces/yomnafarag95/omago-cve-assistant)

---

## Example Queries

```
"What is CVE-2021-44228 and is it actively exploited?"
"Show me all critical CVEs added to CISA KEV this month"
"What is the CVSS score of CVE-2023-44487 and is there a patch?"
"Which Log4j vulnerabilities have public exploit code on Exploit-DB?"
```

---

## Dataset Summary

| Split | Source | Count |
|:---|:---|:---:|
| Primary CVE corpus | NVD 2020–2024 | 130,000+ |
| Confirmed exploits | CISA KEV | 1,100+ |
| Exploit code | Exploit-DB | 15,000+ |

---

## Citation

```bibtex
@misc{elgendy2025omago,
  title   = {Omago: A RAG-Powered CVE Intelligence Assistant},
  author  = {Elgendy, Yomna and Elgendy, Yasmeen},
  school  = {School of Computing, Queen's University},
  course  = {CSAI 810},
  year    = {2025}
}
```

---

## Acknowledgements

Thanks to NIST for the NVD API, CISA for the KEV feed, Offensive Security for Exploit-DB, and the teams behind LangChain, Groq, and Sentence-Transformers.

---

<div align="center">
  <sub>Built at Queen's University · School of Computing · Kingston, ON, Canada</sub>
</div>
