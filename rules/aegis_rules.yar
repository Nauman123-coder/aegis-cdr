/*
 * Project Aegis-CDR YARA Rules
 * 
 * These rules are applied to extracted PDF/DOCX component streams
 * BEFORE reconstruction to catch obfuscated threats that structural
 * analysis might miss.
 * 
 * Usage: yara aegis_rules.yar <component_file>
 */

rule PDF_Embedded_JavaScript {
    meta:
        description = "Detects JavaScript embedded in PDF objects"
        severity = "HIGH"
        cve_refs = "CVE-2010-0188, CVE-2013-2729"
    strings:
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $eval = "eval(" nocase
        $unescape = "unescape(" nocase
        $shellcode_marker = "%u9090" // NOP sled Unicode escape
    condition:
        ($js1 or $js2) and ($eval or $unescape or $shellcode_marker)
}

rule PDF_OpenAction_AutoLaunch {
    meta:
        description = "Detects PDF auto-execute on open"
        severity = "CRITICAL"
    strings:
        $oa = "/OpenAction" nocase
        $launch = "/Launch" nocase
        $aa = "/AA" nocase
    condition:
        any of them
}

rule PDF_Obfuscated_Stream {
    meta:
        description = "Detects heavily encoded/obfuscated content streams"
        severity = "MEDIUM"
    strings:
        $hex_enc = /\/[A-Za-z]+\s+\d+\s+\d+\s+R\s+>>/ 
        $multi_filter = "/FlateDecode/ASCIIHexDecode"
        $multi_filter2 = "/ASCII85Decode/LZWDecode"
    condition:
        2 of them
}

rule PDF_URI_Suspicious {
    meta:
        description = "Detects suspicious external URI actions"
        severity = "MEDIUM"
    strings:
        $uri = "/URI" nocase
        $http = "http://" nocase
        $https = "https://" nocase
        $ftp = "ftp://" nocase
        $smb = "\\\\\\\\[0-9]" // UNC path (potential SMB hash capture)
    condition:
        $uri and (1 of ($http, $https, $ftp, $smb))
}

rule PDF_Heap_Spray_Pattern {
    meta:
        description = "Detects heap spray shellcode patterns in PDF streams"
        severity = "CRITICAL"
        cve_refs = "Generic heap spray technique"
    strings:
        $spray1 = { 90 90 90 90 90 90 90 90 }  // NOP sled
        $spray2 = "%u0c0c%u0c0c" nocase        // Heap spray Unicode
        $spray3 = "0x0c0c0c0c"                  // Common spray address
    condition:
        any of them
}

rule DOCX_VBA_Macro_Present {
    meta:
        description = "Detects VBA macro project in Office document"
        severity = "HIGH"
    strings:
        $vba_sig = { 41 74 74 72 69 62 75 74 65 56 42 }  // "AttributeVB" binary sig
        $vba_file = "vbaProject.bin" nocase
        $module_sig = { D0 CF 11 E0 A1 B1 1A E1 }         // OLE2 compound doc magic
    condition:
        any of them
}

rule DOCX_External_Template_Injection {
    meta:
        description = "Detects remote template injection (T1221)"
        severity = "HIGH"
        mitre_att = "T1221"
    strings:
        $rel_type = "attachedTemplate" nocase
        $target_mode = "TargetMode=\"External\"" nocase
        $http = "http://" nocase
        $https = "https://" nocase
    condition:
        $rel_type and $target_mode and ($http or $https)
}

rule DOCX_DDE_Injection {
    meta:
        description = "Detects Dynamic Data Exchange (DDE) field abuse"
        severity = "HIGH"
        mitre_att = "T1559.002"
    strings:
        $dde1 = "DDEAUTO" nocase
        $dde2 = "DDE " nocase
        $cmd = "cmd" nocase
        $powershell = "powershell" nocase
        $wscript = "wscript" nocase
    condition:
        ($dde1 or $dde2) and (1 of ($cmd, $powershell, $wscript))
}

rule DOCX_Macro_Auto_Execute {
    meta:
        description = "Detects auto-execute macro triggers"
        severity = "CRITICAL"
    strings:
        $auto_open = "AutoOpen" nocase
        $auto_close = "AutoClose" nocase
        $auto_exec = "AutoExec" nocase
        $workbook_open = "Workbook_Open" nocase
        $doc_open = "Document_Open" nocase
    condition:
        any of them
}

rule DOCX_OLE_Object_Embedded {
    meta:
        description = "Detects embedded OLE/ActiveX objects"
        severity = "MEDIUM"
    strings:
        $ole1 = "oleObject" nocase
        $ole2 = "activeX" nocase
        $prog_id = "ProgID=" nocase
        $clsid = "classid=\"clsid:" nocase
    condition:
        2 of them
}

rule Generic_Suspicious_PowerShell {
    meta:
        description = "Detects PowerShell download/exec patterns in any document"
        severity = "CRITICAL"
    strings:
        $ps_download = "DownloadString(" nocase
        $ps_download2 = "DownloadFile(" nocase
        $ps_exec = "IEX(" nocase
        $ps_bypass = "-ExecutionPolicy Bypass" nocase
        $ps_encoded = "-EncodedCommand" nocase
        $ps_hidden = "-WindowStyle Hidden" nocase
    condition:
        2 of them
}

rule Generic_Base64_Shellcode {
    meta:
        description = "Detects Base64-encoded executable payloads"
        severity = "HIGH"
    strings:
        // Common base64 encoding of "MZ" (PE header) = "TVo"
        $pe_b64 = "TVoAAA" nocase
        $pe_b64_2 = "TVqQAAMA" nocase
        // ELF header base64 = "f0VM"
        $elf_b64 = "f0VMRg" nocase
    condition:
        any of them
}

rule Generic_URL_Obfuscation {
    meta:
        description = "Detects obfuscated URLs using hex/unicode encoding"
        severity = "MEDIUM"
    strings:
        $hex_url = /\x68\x74\x74\x70/  // "http" in hex
        $concat_url = /[\"']\s*\+\s*[\"']/  // String concatenation
        $char_code = "fromCharCode(" nocase
    condition:
        2 of them
}
