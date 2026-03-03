"""
utils/groq_client.py
────────────────────
Groq API wrapper using Llama 3.1-70B.
Handles RAG-style prompting with CVE context injection.
"""

import os
import json
import requests
from typing import Optional
from dotenv import load_dotenv

# Load .env from project root (parent of utils/)
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(dotenv_path=os.path.join(_root, ".env"), override=False)

def get_groq_client():
    """Return headers for Groq API calls."""
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key or api_key == "your_groq_api_key_here":
        return None
    return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}


def ask_omago(user_query: str, cve_context: str = "", chat_history: list = None) -> str:
    """
    Send a query to Llama 3.1-70B via Groq with optional CVE context.

    Parameters
    ----------
    user_query   : The user's question
    cve_context  : Retrieved CVE data to inject as context (RAG)
    chat_history : List of {"role": ..., "content": ...} dicts

    Returns
    -------
    str  – model response text, or a fallback message
    """
    headers = get_groq_client()
    if not headers:
        return (
            "Groq API key not configured. Add your GROQ_API_KEY to the .env file "
            "to enable live AI responses. You can get a free key at https://console.groq.com/keys"
        )

    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    max_tokens = int(os.getenv("GROQ_MAX_TOKENS", "1024"))

    system_prompt = (
        "You are Omago, an expert CVE Intelligence Assistant specializing in cybersecurity "
        "vulnerability analysis. You use a multi-layer dataset architecture:\n"
        "  1. NVD (National Vulnerability Database) – authoritative CVE descriptions and CVSS scores\n"
        "  2. CISA KEV (Known Exploited Vulnerabilities) – confirmed active exploitation signals\n"
        "  3. Exploit-DB – weaponization indicators and proof-of-concept code\n\n"
        "When analyzing vulnerabilities, provide: CVE ID, CVSS score, severity, attack vector, "
        "exploitation status (KEV), weaponization status (Exploit-DB), and remediation guidance.\n"
        "Be concise, technical, and accurate. Format responses clearly."
    )

    if cve_context:
        system_prompt += f"\n\nRetrieved CVE Intelligence Context:\n{cve_context}"

    messages = [{"role": "system", "content": system_prompt}]

    # Include recent chat history (last 6 turns max)
    if chat_history:
        for msg in chat_history[-6:]:
            messages.append({"role": msg["role"], "content": msg["content"]})

    messages.append({"role": "user", "content": user_query})

    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.3,  # Lower temp for factual CVE analysis
    }

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except requests.exceptions.Timeout:
        return "Request timed out. Please try again."
    except requests.exceptions.HTTPError as e:
        if resp.status_code == 401:
            return "Invalid Groq API key. Please check your .env file."
        elif resp.status_code == 429:
            return "Groq rate limit reached. Please wait a moment and try again."
        return f"API error: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"
