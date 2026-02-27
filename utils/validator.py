"""
utils/validator.py — Layer 1: Ingestion & Fingerprinting

Detects true MIME type via magic bytes (file signatures).
Prevents extension spoofing (e.g., a .pdf that is actually a .exe).
"""

import struct
from typing import Optional


# Magic byte signatures → MIME type
MAGIC_SIGNATURES = {
    # PDF: %PDF
    b"%PDF": "application/pdf",
    
    # ZIP-based formats (DOCX, XLSX, PPTX share PK header)
    b"PK\x03\x04": "application/zip",  # Refined below by content inspection
    
    # PE executable
    b"MZ": "application/x-msdownload",
    
    # ELF binary
    b"\x7fELF": "application/x-elf",
    
    # Mach-O (macOS binary)
    b"\xfe\xed\xfa\xce": "application/x-mach-binary",
    b"\xfe\xed\xfa\xcf": "application/x-mach-binary",
    
    # Shell script
    b"#!/": "text/x-shellscript",
    b"#! /": "text/x-shellscript",
    
    # HTML
    b"<!DOC": "text/html",
    b"<html": "text/html",
    
    # JavaScript (heuristic)
    b"(func": "application/javascript",
}

# Known-safe OOXML content_types signatures inside ZIP
OOXML_CONTENT_TYPE_MAP = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": 
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

DANGEROUS_TYPES = {
    "application/x-msdownload",
    "application/x-elf",
    "application/x-mach-binary",
    "text/x-shellscript",
    "application/javascript",
    "application/x-bat",
    "application/x-sh",
}


class SafeTypeValidator:
    """
    Validates file authenticity using magic number analysis.
    
    Usage:
        validator = SafeTypeValidator()
        mime = validator.detect_true_type(file_bytes)
    """

    def detect_true_type(self, data: bytes) -> str:
        """
        Inspect magic bytes and return the true MIME type.
        Raises ValueError for dangerous or spoofed file types.
        """
        if len(data) < 8:
            raise ValueError("File too small to be a valid document.")

        detected = self._check_magic(data)
        
        # Refine ZIP detection: check if it's actually a DOCX/XLSX
        if detected == "application/zip":
            detected = self._inspect_zip_content(data)

        if detected in DANGEROUS_TYPES:
            raise ValueError(
                f"DANGEROUS FILE BLOCKED — True type is '{detected}'. "
                f"Extension spoofing or malicious file detected."
            )

        if detected is None:
            raise ValueError(
                "Unknown file format. Only PDF and Office documents are accepted."
            )

        return detected

    def _check_magic(self, data: bytes) -> Optional[str]:
        """Match leading bytes against known signatures."""
        for magic, mime in MAGIC_SIGNATURES.items():
            if data[:len(magic)] == magic:
                return mime
        return None

    def _inspect_zip_content(self, data: bytes) -> str:
        """
        For ZIP-based files, look inside [Content_Types].xml
        to determine if it's a genuine Office Open XML document.
        """
        import zipfile
        import io

        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            names = z.namelist()

            # Must contain [Content_Types].xml for OOXML
            if "[Content_Types].xml" not in names:
                return "application/zip"

            ct_xml = z.read("[Content_Types].xml").decode("utf-8", errors="ignore")

            # Word document signature
            if "wordprocessingml.document.main" in ct_xml:
                return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            if "spreadsheetml.sheet.main" in ct_xml:
                return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            if "presentationml.presentation.main" in ct_xml:
                return "application/vnd.openxmlformats-officedocument.presentationml.presentation"

            return "application/zip"

        except Exception:
            return "application/zip"

    def validate_extension_matches(self, filename: str, true_mime: str) -> bool:
        """
        Secondary check: warn if claimed extension doesn't match true MIME.
        Returns False if mismatch detected (spoofing attempt).
        """
        ext_map = {
            ".pdf": "application/pdf",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        }
        suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        expected = ext_map.get(suffix)
        if expected and expected != true_mime:
            return False  # Spoofing detected
        return True