import os
import json
import re
import logging
from typing import List, Dict, Any, Tuple
from .models import ExtensionInfo, AnalysisFinding, FindingSeverity, ScanResult

logger = logging.getLogger("shadowblocker.scanner")

# Definitions of High-Risk Permissions
CRITICAL_PERMISSIONS = {
    "cookies": "Allows the extension to read, modify, and listen for cookie changes for any site, leading to session hijacking.",
    "webRequest": "Allows intercepting, blocking, or modifying active network requests, enabling traffic sniffing.",
    "webRequestBlocking": "Allows blocking network requests, often used by malicious extensions to prevent security software or block updates.",
    "declarativeNetRequest": "Allows blocking or modifying network requests statically; can be abused for tracking or ad-injection.",
    "declarativeNetRequestBlocking": "Enables blocking network requests, posing a high risk of intercepting credentials.",
    "debugger": "Allows attaching to browser tabs as a debugger, giving full access to JS execution, private APIs, and rendering.",
    "proxy": "Allows routing browser traffic through a custom proxy server, enabling man-in-the-middle attacks."
}

WARNING_PERMISSIONS = {
    "tabs": "Allows accessing the URL, title, and favicon of active and historical browser tabs, compromising browsing history.",
    "activeTab": "Allows temporary access to the active tab's content; relatively safe but can be abused on interaction.",
    "storage": "Allows the extension to store data locally; can be used to store harvested logs before exfiltration.",
    "webNavigation": "Allows listening to browser navigation events, compiling detailed web browsing trails.",
    "management": "Allows managing installed extensions and apps, potentially disabling security extensions.",
    "clipboardRead": "Allows reading data from the OS clipboard, potentially capturing passwords or copied credentials.",
    "clipboardWrite": "Allows modifying clipboard contents, enabling clipboard-hijacking (e.g., swapping crypto addresses).",
    "geolocation": "Allows accessing the user's physical location.",
    "desktopCapture": "Allows capturing screen, window, or tab contents.",
    "pageCapture": "Allows saving any web page as an MHTML archive, potentially capturing forms and private data."
}

# Regex Signatures for Static Analysis
SIGNATURES = [
    # Keylogging
    {
        "id": "keylogging_event",
        "name": "Keylogging Event Listener",
        "pattern": r"addEventListener\s*\(\s*['\"]key(down|up|press)['\"]",
        "severity": FindingSeverity.CRITICAL,
        "description": "Intercepts user keyboard inputs (keydown, keyup, keypress), a classic keylogger mechanism."
    },
    {
        "id": "keylogging_onkey",
        "name": "Direct Keypress Handler",
        "pattern": r"\.onkey(down|up|press)\s*=",
        "severity": FindingSeverity.CRITICAL,
        "description": "Directly assigns a keypress handler to capture keystrokes."
    },
    
    # Cookie/Session Harvesting
    {
        "id": "cookie_harvest_getall",
        "name": "Cookie Harvesting API",
        "pattern": r"chrome\.cookies\.getAll\b",
        "severity": FindingSeverity.CRITICAL,
        "description": "Queries all browser cookies, enabling comprehensive session or account hijacking."
    },
    {
        "id": "cookie_harvest_get",
        "name": "Cookie Query API",
        "pattern": r"chrome\.cookies\.get\b",
        "severity": FindingSeverity.WARNING,
        "description": "Queries individual cookies, potentially accessing sensitive session tokens."
    },
    {
        "id": "cookie_document",
        "name": "Document Cookie Access",
        "pattern": r"document\.cookie\b",
        "severity": FindingSeverity.WARNING,
        "description": "Reads or writes webpage cookies directly, enabling session extraction."
    },
    {
        "id": "session_harvest_localstorage",
        "name": "localStorage Dump Loop",
        "pattern": r"localStorage\.key\s*\(|Object\.keys\s*\(\s*localStorage\s*\)|for\s*\(\s*(var|let|const)?\s*\w+\s+in\s+localStorage\b",
        "severity": FindingSeverity.WARNING,
        "description": "Iterates through all localStorage entries, characteristic of local session and token harvesting."
    },
    {
        "id": "session_harvest_sessionstorage",
        "name": "sessionStorage Dump Loop",
        "pattern": r"sessionStorage\.key\s*\(|Object\.keys\s*\(\s*sessionStorage\s*\)|for\s*\(\s*(var|let|const)?\s*\w+\s+in\s+sessionStorage\b",
        "severity": FindingSeverity.WARNING,
        "description": "Iterates through all sessionStorage entries to harvest temporary authentication states."
    },

    # Network Exfiltration
    {
        "id": "exfil_raw_ip",
        "name": "Exfiltration to Raw IP",
        "pattern": r"(fetch|XMLHttpRequest|open|socket|ws|wss).+https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "severity": FindingSeverity.CRITICAL,
        "description": "Performs network requests to a raw IP address rather than a domain name, bypassing DNS-based safety lists."
    },
    {
        "id": "exfil_raw_ip_string",
        "name": "Hardcoded Raw IP String",
        "pattern": r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "severity": FindingSeverity.WARNING,
        "description": "Contains hardcoded HTTP reference pointing to a raw IP address."
    },
    {
        "id": "exfil_obscure_tld",
        "name": "Exfiltration to Obscure TLD",
        "pattern": r"https?://[a-zA-Z0-9.-]+\.(xyz|top|tk|ru|cc|click|pw|info)\b",
        "severity": FindingSeverity.WARNING,
        "description": "References a domain with a low-cost or high-risk top-level domain (e.g. .xyz, .top, .ru), often used for malicious hosting."
    },

    # Obfuscation and Dynamic Execution
    {
        "id": "obfuscation_packer",
        "name": "Packed Script Obfuscation",
        "pattern": r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)",
        "severity": FindingSeverity.CRITICAL,
        "description": "Uses Dean Edwards JavaScript Packer or similar packing tool to hide malicious logic from static analysis."
    },
    {
        "id": "obfuscation_hex_array",
        "name": "Hexadecimal Variable Array",
        "pattern": r"\b_0x[a-f0-9]{4,6}\b",
        "severity": FindingSeverity.WARNING,
        "description": "Detects machine-generated hexadecimal naming arrays typical of JS obfuscator.io outputs."
    },
    {
        "id": "obfuscation_eval_atob",
        "name": "Base64 Dynamic Execution",
        "pattern": r"eval\s*\(\s*atob\s*\(|eval\s*\(\s*window\[['\"]atob['\"]\]",
        "severity": FindingSeverity.CRITICAL,
        "description": "Decodes a Base64 string and executes it dynamically using eval, a key method for concealing malware loaders."
    },
    {
        "id": "obfuscation_fromcharcode",
        "name": "Dynamic Character Decoding",
        "pattern": r"String\.fromCharCode\b",
        "severity": FindingSeverity.WARNING,
        "description": "Uses ASCII character conversions dynamically to evade simple static word indexing scans."
    },
    {
        "id": "obfuscation_eval",
        "name": "Dynamic Code Execution (eval)",
        "pattern": r"\beval\s*\(",
        "severity": FindingSeverity.WARNING,
        "description": "Executes dynamic strings as code. Highly discouraged in secure extensions due to XSS and injection vulnerabilities."
    },
    {
        "id": "obfuscation_function",
        "name": "Dynamic Function Creation",
        "pattern": r"\bnew\s+Function\s*\(",
        "severity": FindingSeverity.WARNING,
        "description": "Creates functions dynamically from strings, bypassing typical static code reviews."
    }
]

class Scanner:
    """Core analysis engine that parses manifests and scans JavaScript files."""
    
    @staticmethod
    def parse_manifest(extension_path: str) -> Tuple[Dict[str, Any], List[AnalysisFinding]]:
        """
        Parses manifest.json and flags high-risk permissions.
        Returns a tuple of (raw_manifest_dict, list_of_findings).
        """
        manifest_path = os.path.join(extension_path, "manifest.json")
        findings = []
        manifest_data = {}

        if not os.path.isfile(manifest_path):
            return manifest_data, [AnalysisFinding(
                finding_type="error",
                name="Manifest Missing",
                description="manifest.json could not be found in this directory.",
                severity=FindingSeverity.CRITICAL
            )]

        try:
            with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                manifest_data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse manifest at {manifest_path}: {e}")
            return manifest_data, [AnalysisFinding(
                finding_type="error",
                name="Manifest Corrupted",
                description=f"manifest.json contains invalid JSON: {str(e)}",
                severity=FindingSeverity.CRITICAL
            )]

        # Read permissions
        permissions = manifest_data.get("permissions", [])
        host_permissions = manifest_data.get("host_permissions", [])
        
        # Combine both for scanning (Manifest V2 vs V3 consistency)
        all_perms = set()
        if isinstance(permissions, list):
            all_perms.update([p for p in permissions if isinstance(p, str)])
        if isinstance(host_permissions, list):
            all_perms.update([hp for hp in host_permissions if isinstance(hp, str)])

        # Also search for wildcard host permissions in the regular permissions list (MV2 style)
        for perm in all_perms:
            # Check critical permissions
            if perm in CRITICAL_PERMISSIONS:
                findings.append(AnalysisFinding(
                    finding_type="permission",
                    name=f"Critical Permission: '{perm}'",
                    description=CRITICAL_PERMISSIONS[perm],
                    severity=FindingSeverity.CRITICAL
                ))
            elif perm == "<all_urls>" or perm == "*://*/*":
                findings.append(AnalysisFinding(
                    finding_type="permission",
                    name="Critical Host Permission: Broad Wildcard",
                    description="Allows the extension to read and intercept traffic on all websites.",
                    severity=FindingSeverity.CRITICAL
                ))
            # Check warning permissions
            elif perm in WARNING_PERMISSIONS:
                findings.append(AnalysisFinding(
                    finding_type="permission",
                    name=f"Warning Permission: '{perm}'",
                    description=WARNING_PERMISSIONS[perm],
                    severity=FindingSeverity.WARNING
                ))
        # Check content script wildcards
        content_scripts = manifest_data.get("content_scripts", [])
        if isinstance(content_scripts, list):
            for cs in content_scripts:
                if isinstance(cs, dict):
                    matches = cs.get("matches", [])
                    if isinstance(matches, list):
                        for match in matches:
                            if match in ["<all_urls>", "*://*/*", "*://*"]:
                                findings.append(AnalysisFinding(
                                    finding_type="permission",
                                    name="Critical Content Script Wildcard",
                                    description=f"Content script is matched to execute broadly on '{match}'. This allows raw DOM scraping or active keyboard capture injection on all websites.",
                                    severity=FindingSeverity.CRITICAL
                                ))

        return manifest_data, findings

    @staticmethod
    def get_extension_files(extension_path: str, manifest: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """
        Retrieves files explicitly declared in manifest and all JavaScript files recursively.
        Returns a tuple of (explicit_js_files, all_js_files).
        """
        explicit_files = []
        
        # Parse background scripts
        bg = manifest.get("background", {})
        if isinstance(bg, dict):
            # Manifest V2 background scripts
            scripts = bg.get("scripts", [])
            if isinstance(scripts, list):
                explicit_files.extend(scripts)
            # Manifest V3 service worker
            sw = bg.get("service_worker")
            if sw:
                explicit_files.append(sw)
        
        # Parse content scripts
        content_scripts = manifest.get("content_scripts", [])
        if isinstance(content_scripts, list):
            for cs in content_scripts:
                if isinstance(cs, dict):
                    js_files = cs.get("js", [])
                    if isinstance(js_files, list):
                        explicit_files.extend(js_files)

        # Normalize relative paths from manifest
        explicit_normalized = []
        for f in explicit_files:
            if isinstance(f, str):
                # Clean query strings if any
                clean_path = f.split("?")[0]
                full_path = os.path.join(extension_path, clean_path)
                if os.path.isfile(full_path):
                    explicit_normalized.append(os.path.normpath(full_path))

        # Scan folder for ALL javascript files recursively (extremely forensic!)
        all_js_files = []
        for root, _, files in os.walk(extension_path):
            for file in files:
                if file.lower().endswith(".js"):
                    all_js_files.append(os.path.normpath(os.path.join(root, file)))

        return list(set(explicit_normalized)), list(set(all_js_files))

    @staticmethod
    def scan_js_file(file_path: str, root_path: str) -> List[AnalysisFinding]:
        """Scans a single JavaScript file against signatures line-by-line and as a whole."""
        findings = []
        relative_path = os.path.relpath(file_path, root_path)

        if not os.path.isfile(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Error reading script {file_path}: {e}")
            return findings

        # 1. Full-file / Multi-line Signatures (e.g. Dean Edwards packed scripts)
        for sig in SIGNATURES:
            # Check if this signature should be run on the whole content
            # These are usually obfuscation checks that are easier to match across lines or have multi-line structure
            if sig["id"] in ["obfuscation_packer", "obfuscation_eval_atob", "obfuscation_hex_array"]:
                match = re.search(sig["pattern"], content, re.MULTILINE | re.DOTALL)
                if match:
                    # Find approximate line number
                    matched_text = match.group(0)
                    char_index = content.find(matched_text)
                    line_num = content.count("\n", 0, char_index) + 1
                    
                    # Extract the snippet (up to 4 lines)
                    lines = content.split("\n")
                    snippet_lines = lines[max(0, line_num-1): min(len(lines), line_num+3)]
                    snippet = "\n".join(snippet_lines)

                    findings.append(AnalysisFinding(
                        finding_type="signature",
                        name=sig["name"],
                        description=sig["description"],
                        severity=sig["severity"],
                        file_path=relative_path,
                        line_number=line_num,
                        snippet=snippet
                    ))

        # 2. Line-by-Line Signatures
        lines = content.split("\n")
        for line_idx, line in enumerate(lines):
            # Skip comments to avoid false positives on commented-out code
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            for sig in SIGNATURES:
                # Obfuscation packer has already been run on the whole file
                if sig["id"] in ["obfuscation_packer", "obfuscation_eval_atob", "obfuscation_hex_array"]:
                    continue
                
                # Run pattern search
                match = re.search(sig["pattern"], line)
                if match:
                    # Check if we already flagged this exact line for this signature (avoid duplicates)
                    if not any(f.line_number == line_idx + 1 and f.name == sig["name"] and f.file_path == relative_path for f in findings):
                        # Extract context snippet (the line itself, cleaned)
                        findings.append(AnalysisFinding(
                            finding_type="signature",
                            name=sig["name"],
                            description=sig["description"],
                            severity=sig["severity"],
                            file_path=relative_path,
                            line_number=line_idx + 1,
                            snippet=line.strip()
                        ))

        return findings

    @classmethod
    def analyze_extension(cls, extension_path: str, browser_name: str, ext_id: str = "Unknown") -> ScanResult:
        """Runs the complete forensic audit on the specified extension directory."""
        # 1. Parse manifest
        manifest_data, manifest_findings = cls.parse_manifest(extension_path)
        
        ext_name = manifest_data.get("name", os.path.basename(extension_path))
        ext_ver = manifest_data.get("version", "1.0.0")
        ext_desc = manifest_data.get("description", "No description provided.")
        manifest_ver = manifest_data.get("manifest_version", 2)
        
        # Read explicit lists of permissions
        perms = manifest_data.get("permissions", [])
        if not isinstance(perms, list):
            perms = []
        host_perms = manifest_data.get("host_permissions", [])
        if not isinstance(host_perms, list):
            host_perms = []

        # 2. Get scripts to scan
        explicit_js, all_js = cls.get_extension_files(extension_path, manifest_data)
        
        # Make lists of relative paths for ExtensionInfo
        bg_scripts = []
        bg = manifest_data.get("background", {})
        if isinstance(bg, dict):
            scripts = bg.get("scripts", [])
            if isinstance(scripts, list):
                bg_scripts.extend(scripts)
            sw = bg.get("service_worker")
            if sw:
                bg_scripts.append(sw)

        content_scripts = []
        cs_list = manifest_data.get("content_scripts", [])
        if isinstance(cs_list, list):
            for cs in cs_list:
                if isinstance(cs, dict):
                    js_files = cs.get("js", [])
                    if isinstance(js_files, list):
                        content_scripts.extend(js_files)

        extension = ExtensionInfo(
            ext_id=ext_id,
            name=ext_name,
            version=ext_ver,
            description=ext_desc,
            path=extension_path,
            browser=browser_name,
            manifest_version=manifest_ver,
            permissions=[str(p) for p in perms],
            host_permissions=[str(hp) for hp in host_perms],
            background_scripts=[str(b) for b in bg_scripts],
            content_scripts=[str(c) for c in content_scripts]
        )

        # 3. Scan JavaScript files for threat signatures
        js_findings = []
        for file_path in all_js:
            js_findings.extend(cls.scan_js_file(file_path, extension_path))

        all_findings = manifest_findings + js_findings

        # 4. Calculate Risk Metrics
        risk_score, risk_level = cls.calculate_risk(all_findings)

        return ScanResult(
            extension=extension,
            findings=all_findings,
            risk_score=risk_score,
            risk_level=risk_level
        )

    @staticmethod
    def calculate_risk(findings: List[AnalysisFinding]) -> Tuple[float, str]:
        """
        Calculates numerical risk score (0-100) and risk level (Safe, Warning, Critical).
        Formula:
          - Permissions Cap: 40 points
            - Critical: +15 points each
            - Warning: +5 points each
          - Static Analysis Cap: 60 points
            - Critical Findings (Keylogger/Exfil/Heavy Packer): +30 points each
            - Warning Findings (eval/obscure TLD/localStorage dump): +15 points each
          - Score = min(100, perm_points + static_points)
        
        Forced Upgrades:
          - Force CRITICAL if:
            - Presence of Keylogging AND Network Exfiltration (any)
            - Presence of Cookie Harvesting AND Network Exfiltration (any)
            - Presence of any Critical Signature (e.g. Obfuscation Packer, Base64 eval)
          - Force WARNING if:
            - Any Warning permission or Warning static signature is present (and not Critical)
        """
        perm_score = 0
        static_score = 0
        
        has_keylogger = False
        has_cookie_harvester = False
        has_exfiltration = False
        has_critical_signature = False
        has_warning_elements = False
        
        for f in findings:
            if f.finding_type == "permission":
                if f.severity == FindingSeverity.CRITICAL:
                    perm_score += 15
                    has_warning_elements = True
                elif f.severity == FindingSeverity.WARNING:
                    perm_score += 5
                    has_warning_elements = True
            elif f.finding_type == "signature":
                has_warning_elements = True
                if f.severity == FindingSeverity.CRITICAL:
                    static_score += 30
                    
                    # Track specific malicious capabilities
                    if "Keylogging" in f.name or "Keypress" in f.name:
                        has_keylogger = True
                    if "Cookie Harvesting" in f.name:
                        has_cookie_harvester = True
                    if "Exfiltration to Raw IP" in f.name:
                        has_exfiltration = True
                    if "Packer" in f.name or "Base64" in f.name:
                        has_critical_signature = True
                elif f.severity == FindingSeverity.WARNING:
                    static_score += 15
                    if "Obscure TLD" in f.name or "Hardcoded Raw IP" in f.name:
                        has_exfiltration = True

        # Apply caps
        perm_score = min(40, perm_score)
        static_score = min(60, static_score)
        
        risk_score = float(perm_score + static_score)
        
        # Risk classification
        if risk_score > 65:
            risk_level = "Critical"
        elif risk_score > 20:
            risk_level = "Warning"
        else:
            risk_level = "Safe"

        # Force escalations based on dynamic analysis heuristics
        if (has_keylogger and has_exfiltration) or (has_cookie_harvester and has_exfiltration) or has_critical_signature:
            risk_level = "Critical"
            risk_score = max(risk_score, 75.0)  # Force score to at least 75 for critical alert
        elif has_warning_elements and risk_level == "Safe":
            risk_level = "Warning"
            risk_score = max(risk_score, 25.0)

        return min(100.0, risk_score), risk_level
