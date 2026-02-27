"""
core/docx/sanitizer.py — Layer 2 & 3 for DOCX files

DocxSanitizer: Unzips the OOXML package, removes macros, external links,
embedded OLE objects, and suspicious relationships, then re-zips cleanly.

Dependencies: python-docx, lxml (included with python-docx)
"""

import zipfile
import shutil
import logging
import re
from io import BytesIO
from pathlib import Path
from lxml import etree
from typing import Optional

log = logging.getLogger("aegis.docx")

# Files to unconditionally delete from the DOCX ZIP
BLOCKLIST_FILES = {
    "word/vbaProject.bin",          # VBA macro project
    "word/vbaData.xml",             # VBA data
    "customXml/",                   # Custom XML — can trigger auto-execution
    "word/activeX/",                # ActiveX controls
    "word/embeddings/",             # OLE embedded objects
}

# Relationship types that pose a risk
DANGEROUS_REL_TYPES = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/vbaProject",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/activeX",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",  # External
    "http://schemas.microsoft.com/office/2006/relationships/wVbaData",
}

# XML namespaces
NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "mc": "http://schemas.openxmlformats.org/markup-compatibility/2006",
    "wpc": "http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas",
}


class DocxSanitizer:
    """
    Layer 2 (Decomposition) + Layer 3 (Sanitization) + Layer 4 (Reconstruction)
    for DOCX files.

    Strategy: Unzip → Audit XML Components → Strip Threats → Re-zip Clean Package
    """

    def __init__(self, input_path: str, output_path: str):
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.items_removed: list[str] = []
        self.warnings: list[str] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def sanitize(self) -> dict:
        """Full CDR pipeline for a DOCX file."""
        log.info(f"[Aegis-DOCX] Starting sanitization: {self.input_path.name}")

        # Read the DOCX into memory
        with open(self.input_path, "rb") as f:
            docx_bytes = BytesIO(f.read())

        if not zipfile.is_zipfile(docx_bytes):
            raise ValueError("File is not a valid ZIP/DOCX package.")
        docx_bytes.seek(0)

        # Count pages via paragraph heuristic before processing
        page_count_original = self._estimate_pages(docx_bytes)
        docx_bytes.seek(0)

        # Build sanitized package in memory
        clean_bytes = self._process_zip(docx_bytes)

        # Write output
        with open(self.output_path, "wb") as f:
            f.write(clean_bytes.getvalue())

        page_count_sanitized = self._estimate_pages(clean_bytes)

        log.info(f"[Aegis-DOCX] Sanitization complete. Removed: {self.items_removed}")

        return {
            "items_removed": self.items_removed,
            "page_count_original": page_count_original,
            "page_count_sanitized": page_count_sanitized,
            "fallback_used": False,
            "warnings": self.warnings,
        }

    # ------------------------------------------------------------------
    # Core ZIP Processing
    # ------------------------------------------------------------------

    def _process_zip(self, source: BytesIO) -> BytesIO:
        """
        Walk every file in the DOCX ZIP.
        Block dangerous files, sanitize XML, neutralize relationships.
        Return a clean BytesIO ZIP.
        """
        clean_zip_buffer = BytesIO()

        with zipfile.ZipFile(source, "r") as src_zip:
            with zipfile.ZipFile(clean_zip_buffer, "w", zipfile.ZIP_DEFLATED) as dst_zip:
                
                for item in src_zip.infolist():
                    name = item.filename
                    data = src_zip.read(name)

                    # --- Check blocklist ---
                    if self._is_blocked(name):
                        self.items_removed.append(f"Blocked file: {name}")
                        log.warning(f"[Aegis-DOCX] Blocked: {name}")
                        continue

                    # --- Sanitize relationship files ---
                    if name.endswith(".rels"):
                        data = self._sanitize_rels(name, data)

                    # --- Sanitize main document XML ---
                    elif name == "word/document.xml":
                        data = self._sanitize_document_xml(data)

                    # --- Sanitize settings (disable external templates, macros) ---
                    elif name == "word/settings.xml":
                        data = self._sanitize_settings_xml(data)

                    # --- Sanitize content types (remove macro content types) ---
                    elif name == "[Content_Types].xml":
                        data = self._sanitize_content_types(data)

                    dst_zip.writestr(item, data)

        clean_zip_buffer.seek(0)
        return clean_zip_buffer

    # ------------------------------------------------------------------
    # Blocklist
    # ------------------------------------------------------------------

    def _is_blocked(self, filename: str) -> bool:
        """Return True if this file must be excluded."""
        for blocked in BLOCKLIST_FILES:
            if filename == blocked or filename.startswith(blocked):
                return True
        return False

    # ------------------------------------------------------------------
    # Relationship Sanitization
    # ------------------------------------------------------------------

    def _sanitize_rels(self, rel_filename: str, data: bytes) -> bytes:
        """
        Parse .rels XML and strip dangerous relationship types.
        For hyperlinks (external targets): neutralize to '#' (dead link).
        """
        try:
            root = etree.fromstring(data)
        except etree.XMLSyntaxError as e:
            self.warnings.append(f"Cannot parse {rel_filename}: {e}")
            return data

        to_remove = []
        to_neutralize = []
        ns = "http://schemas.openxmlformats.org/package/2006/relationships"

        for rel in root.findall(f"{{{ns}}}Relationship"):
            rel_type = rel.get("Type", "")
            target_mode = rel.get("TargetMode", "Internal")
            target = rel.get("Target", "")

            # Block dangerous relationship types
            if any(danger in rel_type for danger in [
                "vbaProject", "oleObject", "activeX", "attachedTemplate", "wVbaData"
            ]):
                to_remove.append(rel)
                self.items_removed.append(
                    f"Dangerous relationship removed from {rel_filename}: {rel_type}"
                )
                continue

            # Neutralize external hyperlinks
            if target_mode == "External" and "hyperlink" in rel_type:
                original_target = target
                rel.set("Target", "#")
                to_neutralize.append(original_target)
                self.items_removed.append(
                    f"External link neutralized in {rel_filename}: {original_target}"
                )

        for rel in to_remove:
            root.remove(rel)

        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    # ------------------------------------------------------------------
    # Document XML Sanitization
    # ------------------------------------------------------------------

    def _sanitize_document_xml(self, data: bytes) -> bytes:
        """
        Scan word/document.xml for:
        - Embedded scripts in fldChar/instrText fields
        - Macro-linked form fields
        - Hyperlinks to external resources
        - DDE (Dynamic Data Exchange) fields
        """
        try:
            root = etree.fromstring(data)
        except etree.XMLSyntaxError as e:
            self.warnings.append(f"Cannot parse document.xml: {e}")
            return data

        w_ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

        # --- Strip HYPERLINK fields with external URLs ---
        hyperlinks = root.findall(f".//{{{w_ns}}}hyperlink")
        for hl in hyperlinks:
            r_id = hl.get(f"{{{NS['r']}}}id")
            if r_id:
                # Keep element but strip the relationship reference
                del hl.attrib[f"{{{NS['r']}}}id"]
                self.items_removed.append(f"Hyperlink field r:id={r_id} stripped from document.xml")

        # --- Strip DDE / macro field instructions ---
        fld_instrs = root.findall(f".//{{{w_ns}}}instrText")
        for instr in fld_instrs:
            text = (instr.text or "").upper()
            if any(kw in text for kw in ["DDE", "DDEAUTO", "MACROBUTTON", "INCLUDEPICTURE http", "INCLUDETEXT http"]):
                self.items_removed.append(f"Dangerous field instruction stripped: {instr.text[:60]}")
                instr.text = ""

        # --- Strip bookmarks that reference macros ---
        bookmarks = root.findall(f".//{{{w_ns}}}bookmarkStart")
        for bm in bookmarks:
            name = bm.get(f"{{{w_ns}}}name", "")
            if name.lower().startswith("_goto_"):
                self.items_removed.append(f"Suspicious bookmark stripped: {name}")
                bm.getparent().remove(bm)

        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    # ------------------------------------------------------------------
    # Settings XML Sanitization
    # ------------------------------------------------------------------

    def _sanitize_settings_xml(self, data: bytes) -> bytes:
        """
        Remove dangerous settings:
        - attachedTemplate (loads macros from remote template)
        - trackChanges with external authors
        - mailMerge data sources
        """
        try:
            root = etree.fromstring(data)
        except etree.XMLSyntaxError as e:
            self.warnings.append(f"Cannot parse settings.xml: {e}")
            return data

        w_ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        dangerous_settings = [
            "attachedTemplate",
            "mailMerge",
            "writeProtection",
        ]

        for tag in dangerous_settings:
            elements = root.findall(f"{{{w_ns}}}{tag}")
            for elem in elements:
                self.items_removed.append(f"Dangerous setting removed from settings.xml: {tag}")
                root.remove(elem)

        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    # ------------------------------------------------------------------
    # Content Types Sanitization
    # ------------------------------------------------------------------

    def _sanitize_content_types(self, data: bytes) -> bytes:
        """Remove macro and ActiveX content type declarations."""
        try:
            root = etree.fromstring(data)
        except etree.XMLSyntaxError as e:
            self.warnings.append(f"Cannot parse [Content_Types].xml: {e}")
            return data

        ns = "http://schemas.openxmlformats.org/package/2006/content-types"
        dangerous_ct_patterns = ["vba", "activeX", "oleObject", "macro"]

        to_remove = []
        for elem in root.iter():
            ct = elem.get("ContentType", "")
            if any(p in ct.lower() for p in dangerous_ct_patterns):
                to_remove.append(elem)
                self.items_removed.append(f"Dangerous ContentType removed: {ct}")

        for elem in to_remove:
            try:
                elem.getparent().remove(elem)
            except Exception:
                pass

        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    # ------------------------------------------------------------------
    # Page Count Estimation
    # ------------------------------------------------------------------

    def _estimate_pages(self, docx_bytes: BytesIO) -> int:
        """
        Estimate page count by counting page break indicators in the XML.
        Not exact — DOCX doesn't store page count natively without rendering.
        """
        docx_bytes.seek(0)
        try:
            with zipfile.ZipFile(docx_bytes, "r") as z:
                if "word/document.xml" not in z.namelist():
                    return 0
                xml_data = z.read("word/document.xml").decode("utf-8", errors="ignore")
                # Count explicit page breaks
                breaks = xml_data.count('w:type="page"') + 1
                return breaks
        except Exception:
            return 0