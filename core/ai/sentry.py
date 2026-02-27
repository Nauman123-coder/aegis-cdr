"""
core/ai/sentry.py — Layer 4: The AI "Sentry" Wrapper (Groq Edition)

AegisSentry uses Groq's blazing-fast LLM inference via LangChain
to generate threat summaries, integrity checks, and risk analysis.

Supported Groq models:
  - llama-3.3-70b-versatile (recommended)
  - llama-3.1-8b-instant (fast)
  - mixtral-8x7b-32768

Set env: GROQ_API_KEY=your_key
"""

import os
import logging
from typing import Optional

log = logging.getLogger("aegis.sentry")

GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")


class AegisSentry:
    """
    AI Sentry — Groq-powered threat intelligence layer.
    Falls back to deterministic rule-based mode if no API key present.
    """

    def __init__(self):
        self.llm = self._init_llm()
        self._groq_available = self.llm is not None

    def _init_llm(self):
        """Initialize Groq via LangChain."""
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            log.warning("[Sentry] GROQ_API_KEY not set — using rule-based mode.")
            return None
        try:
            from langchain_groq import ChatGroq
            llm = ChatGroq(
                model=GROQ_MODEL,
                groq_api_key=api_key,
                temperature=0.2,
                max_tokens=600,
            )
            log.info(f"[Sentry] Groq LLM initialized: {GROQ_MODEL}")
            return llm
        except ImportError:
            log.warning("[Sentry] langchain-groq not installed. Run: pip install langchain-groq")
            return None
        except Exception as e:
            log.warning(f"[Sentry] Groq init failed: {e}")
            return None

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    def summarize(
        self,
        items_removed: list[str],
        page_count_original: int,
        page_count_sanitized: int,
        filename: str = "document",
    ) -> str:
        integrity = self._check_integrity(page_count_original, page_count_sanitized)

        if not items_removed and page_count_original == page_count_sanitized:
            return (
                f"{filename} passed all threat checks. "
                "No active content, macros, scripts, or suspicious links were found. "
                "The document is clean and safe to use."
            )

        if self.llm:
            return self._groq_summary(items_removed, integrity, filename)
        return self._rule_based_summary(items_removed, integrity, filename)

    def risk_score(self, items_removed: list[str]) -> dict:
        """Returns risk score dict with score (0-100), level, rationale, and color."""
        score = 0
        rationale_parts = []

        scoring_map = {
            # PDF active content (match xref scanner output patterns)
            "/javascript":    (40, "Embedded JavaScript"),
            "/js":            (40, "Embedded JavaScript"),
            "/openaction":    (30, "Auto-execute on open"),
            "/aa":            (25, "Additional actions"),
            "/launch":        (50, "Shell launch command"),
            "/embeddedfile":  (20, "Embedded file attachment"),
            "/xobject":       (15, "Embedded XObject (image/form/PS)"),
            "/uri":           (10, "URI action link"),
            "/sound":         (20, "Embedded sound object"),
            "/movie":         (25, "Embedded movie object"),
            "/richmedia":     (30, "Rich media embedding"),
            "/widget":        (20, "Interactive form widget"),
            "dangerous annotation": (20, "Dangerous page annotation"),
            # DOCX threats
            "vbaproject":     (45, "VBA macros"),
            "oleobject":      (35, "OLE object embedding"),
            "activex":        (40, "ActiveX control"),
            "attachedtemplate": (30, "Remote template injection"),
            "dde":            (35, "DDE field injection"),
            "macrobutton":    (40, "Macro-linked button"),
            "blocked file":   (15, "Blocked dangerous file"),
            "customxml":      (10, "Custom XML data part"),
            "hyperlink":      (10, "External hyperlink"),
            "external link":  (10, "External tracking link"),
            # Fallback
            "pixel-fallback": (75, "Emergency rasterization required"),
        }

        for item in items_removed:
            item_lower = item.lower()
            for keyword, (pts, label) in scoring_map.items():
                if keyword in item_lower:
                    score += pts
                    rationale_parts.append(label)
                    break

        score = min(score, 100)

        if score >= 70:
            level, color = "CRITICAL", "#ff1a1a"
        elif score >= 40:
            level, color = "HIGH", "#ff6b35"
        elif score >= 20:
            level, color = "MEDIUM", "#ffd700"
        elif score > 0:
            level, color = "LOW", "#00c9ff"
        else:
            level, color = "CLEAN", "#00ff9d"

        return {
            "score": score,
            "level": level,
            "color": color,
            "rationale": "; ".join(dict.fromkeys(rationale_parts)) or "No threats found",
        }

    def categorize_threats(self, items_removed: list[str]) -> dict:
        """Group removed items into display categories for the frontend."""
        categories = {
            "Scripts & JavaScript": [],
            "Macros & VBA": [],
            "External Links": [],
            "Embedded Objects": [],
            "Auto-Execute Actions": [],
            "Custom XML": [],
            "Other": [],
        }
        for item in items_removed:
            il = item.lower()
            if any(k in il for k in ["javascript", "/js", "script", "dde", "macrobutton"]):
                categories["Scripts & JavaScript"].append(item)
            elif any(k in il for k in ["vba", "macro", "autoopen", "autoexec"]):
                categories["Macros & VBA"].append(item)
            elif any(k in il for k in ["hyperlink", "external link", "/uri", "url", "link neutralized"]):
                categories["External Links"].append(item)
            elif any(k in il for k in ["ole", "embed", "activex", "attachedtemplate",
                                        "/xobject", "/sound", "/movie", "/richmedia",
                                        "/widget", "annotation", "blocked file"]):
                categories["Embedded Objects"].append(item)
            elif any(k in il for k in ["/openaction", "/launch", "/aa", "autoexecute"]):
                categories["Auto-Execute Actions"].append(item)
            elif any(k in il for k in ["customxml", "custom xml", "custom_xml"]):
                categories["Custom XML"].append(item)
            else:
                categories["Other"].append(item)
        return {k: v for k, v in categories.items() if v}

    # ──────────────────────────────────────────────────────────────
    # Integrity Check
    # ──────────────────────────────────────────────────────────────

    def _check_integrity(self, original: int, sanitized: int) -> str:
        if original == 0:
            return "Page count could not be determined."
        if original == sanitized:
            return f"Visual integrity confirmed. Page count unchanged: {sanitized} page(s)."
        delta = original - sanitized
        if delta > 0:
            return (
                f"Visual integrity notice: {delta} page(s) affected. "
                f"Original: {original}, Sanitized: {sanitized}. "
                f"Expected if pages contained only active content."
            )
        return (
            f"Visual integrity notice: sanitized version has {abs(delta)} additional page(s). "
            f"Original: {original}, Sanitized: {sanitized}."
        )

    # ──────────────────────────────────────────────────────────────
    # Groq LLM Summary
    # ──────────────────────────────────────────────────────────────

    def _groq_summary(self, items_removed: list[str], integrity: str, filename: str) -> str:
        try:
            from langchain_core.messages import HumanMessage, SystemMessage

            threat_list = "\n".join(f"- {item}" for item in items_removed[:20])
            risk = self.risk_score(items_removed)

            messages = [
                SystemMessage(content=(
                    "You are Aegis, an expert cybersecurity AI specializing in document threat analysis. "
                    "Write a concise 3-sentence professional security report about what was found and removed. "
                    "Be specific about the threat types and their potential impact if not neutralized. "
                    "Use plain text only — no markdown, no bullet points, no headers. "
                    "End with one sentence about the document's safety status after sanitization."
                )),
                HumanMessage(content=(
                    f"File: {filename}\n"
                    f"Risk Level: {risk['level']} ({risk['score']}/100)\n"
                    f"Items removed ({len(items_removed)} total):\n{threat_list}\n\n"
                    f"Integrity check: {integrity}\n\n"
                    "Write the security report now:"
                ))
            ]

            response = self.llm.invoke(messages)
            return response.content.strip()

        except Exception as e:
            log.warning(f"[Sentry] Groq summary error: {e}")
            return self._rule_based_summary(items_removed, integrity, filename)

    # ──────────────────────────────────────────────────────────────
    # Rule-Based Fallback
    # ──────────────────────────────────────────────────────────────

    def _rule_based_summary(self, items_removed: list[str], integrity: str, filename: str) -> str:
        risk = self.risk_score(items_removed)
        cats = self.categorize_threats(items_removed)

        cat_summary = ", ".join(
            f"{len(v)} {k.lower()}" for k, v in cats.items()
        )

        return (
            f"Aegis neutralized {len(items_removed)} threat(s) in '{filename}': {cat_summary}. "
            f"Risk assessment: {risk['level']} (score {risk['score']}/100) — {risk['rationale']}. "
            f"{integrity} The sanitized document has been reconstructed using positive selection "
            f"and is safe to open."
        )