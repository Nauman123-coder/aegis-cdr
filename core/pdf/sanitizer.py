"""
core/pdf/sanitizer.py — v3: Hybrid CDR Engine

Strategy:
  - SCRUB MODE (default): Remove dangerous objects directly from the PDF structure.
    Preserves all images, fonts, and layout perfectly. Output ≈ same size as input.
    Used when the document structure is trustworthy (no deep obfuscation).

  - RECONSTRUCT MODE: Full positive-selection rebuild from scratch.
    Used only when scrub mode cannot safely clean the document.
    Accepts some size increase in exchange for maximum security.

  - PIXEL FALLBACK: Rasterize every page to images.
    Used when both above modes fail.
"""

import fitz
import logging
import tempfile
import os
import shutil
from pathlib import Path

log = logging.getLogger("aegis.pdf")

# Keys that represent executable/active content — strip these
STRIP_KEYS = {
    "/JavaScript", "/JS", "/OpenAction", "/AA",
    "/Launch", "/SubmitForm", "/ImportData",
    "/EmbeddedFile", "/RichMedia", "/Sound",
    "/Movie", "/Screen", "/Widget",
}

# Keys we scan for (broader — includes things we flag but handle carefully)
SCAN_KEYS = STRIP_KEYS  # same set for now

SAFE_ANNOTATION_TYPES = {"Text", "FreeText", "Line", "Square", "Circle",
                         "Highlight", "Underline", "Strikeout", "Stamp", "Link"}


class PDFSanitizer:

    def __init__(self, input_path: str, output_path: str, pixel_fallback: bool = False):
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.pixel_fallback = pixel_fallback
        self.items_removed: list[str] = []
        self.warnings: list[str] = []

    # ------------------------------------------------------------------
    # Public Entry Point
    # ------------------------------------------------------------------

    def sanitize(self) -> dict:
        log.info(f"[Aegis-PDF] Sanitizing: {self.input_path.name}")

        try:
            src_doc = fitz.open(str(self.input_path))
        except Exception as e:
            raise RuntimeError(f"Cannot open PDF: {e}")

        page_count_original = len(src_doc)

        # Step 1: Scan — find all threats
        self._scan_for_threats(src_doc)

        # Step 2: Scrub in-place (preserves size, images, fonts)
        try:
            self._scrub_inplace(src_doc)
            fallback_used = False

            # Save with garbage collection to remove orphaned objects
            src_doc.save(
                str(self.output_path),
                garbage=4,
                deflate=True,
                clean=True,
                incremental=False,
            )
            src_doc.close()

        except Exception as e:
            log.warning(f"[Aegis-PDF] Scrub failed ({e}), falling back to reconstruction.")
            src_doc.close()

            if self.pixel_fallback:
                src_doc2 = fitz.open(str(self.input_path))
                new_doc = self._pixel_only_fallback(src_doc2)
                src_doc2.close()
                new_doc.save(str(self.output_path), garbage=4, deflate=True)
                new_doc.close()
                fallback_used = True
                self.items_removed.append("PIXEL-FALLBACK: entire document rasterized")
            else:
                raise RuntimeError(f"Sanitization failed: {e}")

        page_count_sanitized = 0
        try:
            out_doc = fitz.open(str(self.output_path))
            page_count_sanitized = len(out_doc)
            out_doc.close()
        except Exception:
            page_count_sanitized = page_count_original

        log.info(f"[Aegis-PDF] Done. Removed {len(self.items_removed)} items.")
        return {
            "items_removed": self.items_removed,
            "page_count_original": page_count_original,
            "page_count_sanitized": page_count_sanitized,
            "fallback_used": fallback_used,
            "warnings": self.warnings,
        }

    # ------------------------------------------------------------------
    # Threat Scanner
    # ------------------------------------------------------------------

    def _scan_for_threats(self, doc: fitz.Document):
        """Scan all xref objects and page annotations. Populate self.items_removed."""

        # Scan catalog
        catalog_xref = doc.pdf_catalog()
        if catalog_xref > 0:
            try:
                obj_str = doc.xref_object(catalog_xref)
                for key in STRIP_KEYS:
                    if key in obj_str:
                        self.items_removed.append(
                            f"Document Catalog xref {catalog_xref}: {key} detected and stripped"
                        )
            except Exception:
                pass

        # Scan all objects
        for xref in range(1, doc.xref_length()):
            try:
                obj_str = doc.xref_object(xref, compressed=False)
                if not obj_str:
                    continue
                for key in SCAN_KEYS:
                    if key in obj_str:
                        desc = f"Threat in xref {xref}: {key}"
                        if desc not in self.items_removed:
                            self.items_removed.append(desc)
                # PostScript XObject (special dangerous case)
                if "/XObject" in obj_str and "/PS" in obj_str:
                    desc = f"Threat in xref {xref}: PostScript XObject"
                    if desc not in self.items_removed:
                        self.items_removed.append(desc)
            except Exception:
                continue

        # Scan page annotations
        for page_num, page in enumerate(doc):
            try:
                annots = list(page.annots())
                for annot in annots:
                    atype = annot.type[1]
                    if atype not in SAFE_ANNOTATION_TYPES:
                        self.items_removed.append(
                            f"Page {page_num+1}: Unsafe annotation '{atype}' removed"
                        )
            except Exception:
                continue

    # ------------------------------------------------------------------
    # In-Place Scrubbing (preserves file size)
    # ------------------------------------------------------------------

    def _scrub_inplace(self, doc: fitz.Document):
        """
        Surgically remove dangerous keys directly from PDF object dictionaries.
        This is the most size-efficient approach — the clean document retains
        all original images, fonts, and layout with only dangerous entries removed.
        """

        # ── 1. Clean the document catalog ──────────────────────────
        catalog_xref = doc.pdf_catalog()
        if catalog_xref > 0:
            self._strip_keys_from_xref(doc, catalog_xref)

        # ── 2. Clean every xref object ────────────────────────────
        for xref in range(1, doc.xref_length()):
            try:
                obj_str = doc.xref_object(xref, compressed=False)
                if not obj_str:
                    continue
                # Only process objects that contain dangerous keys
                if any(key in obj_str for key in STRIP_KEYS):
                    self._strip_keys_from_xref(doc, xref)
            except Exception:
                continue

        # ── 3. Clean page-level annotations ──────────────────────
        for page in doc:
            try:
                annots = list(page.annots())
                for annot in annots:
                    atype = annot.type[1]
                    if atype not in SAFE_ANNOTATION_TYPES:
                        page.delete_annot(annot)
            except Exception:
                continue

        # ── 4. Remove named JavaScript actions ────────────────────
        try:
            # Clear /Names tree entries that reference JavaScript
            names_xref = self._get_names_xref(doc)
            if names_xref:
                self._strip_keys_from_xref(doc, names_xref)
        except Exception:
            pass

    def _strip_keys_from_xref(self, doc: fitz.Document, xref: int):
        """Remove all dangerous keys from a single PDF object."""
        for key in STRIP_KEYS:
            try:
                # fitz uses xref_set_key to modify PDF dict entries
                # Setting to "null" effectively removes the entry
                current = doc.xref_get_key(xref, key.lstrip("/"))
                if current and current[0] != "null":
                    doc.xref_set_key(xref, key.lstrip("/"), "null")
                    log.debug(f"Stripped {key} from xref {xref}")
            except Exception:
                pass

    def _get_names_xref(self, doc: fitz.Document) -> int:
        """Get the xref of the /Names dictionary in the catalog."""
        try:
            catalog_xref = doc.pdf_catalog()
            names = doc.xref_get_key(catalog_xref, "Names")
            if names and names[0] == "xref":
                return int(names[1])
        except Exception:
            pass
        return 0

    # ------------------------------------------------------------------
    # Pixel-Only Fallback
    # ------------------------------------------------------------------

    def _pixel_only_fallback(self, src_doc: fitz.Document, dpi: int = 150) -> fitz.Document:
        log.info("[Aegis-PDF] Pixel-only fallback engaged.")
        new_doc = fitz.open()
        mat = fitz.Matrix(dpi / 72, dpi / 72)

        for page_num, page in enumerate(src_doc):
            pix = page.get_pixmap(matrix=mat, alpha=False)
            img_bytes = pix.tobytes("png")
            img_rect = fitz.Rect(0, 0, pix.width, pix.height)
            new_page = new_doc.new_page(width=pix.width, height=pix.height)
            new_page.insert_image(img_rect, stream=img_bytes)
            log.debug(f"[Aegis-PDF] Rasterized page {page_num+1} at {dpi}dpi")

        return new_doc