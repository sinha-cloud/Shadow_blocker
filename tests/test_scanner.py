import unittest
import os
import sys

# Ensure shadowblocker package is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shadowblocker.scanner import Scanner, WARNING_PERMISSIONS, CRITICAL_PERMISSIONS
from shadowblocker.models import FindingSeverity, ScanResult

class TestScanner(unittest.TestCase):
    
    def setUp(self):
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.safe_ext_path = os.path.join(self.base_dir, "test_extensions", "safe_extension")
        self.suspicious_ext_path = os.path.join(self.base_dir, "test_extensions", "suspicious_extension")

    def test_safe_extension_analysis(self):
        """Test that the mock safe extension is successfully verified as Safe."""
        self.assertTrue(os.path.isdir(self.safe_ext_path), "Safe extension directory must exist.")
        
        result = Scanner.analyze_extension(self.safe_ext_path, "Chrome", "safe-test-id")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.extension.name, "Sleek Note Taker")
        self.assertEqual(result.extension.browser, "Chrome")
        self.assertEqual(result.extension.id, "safe-test-id")
        
        # Verify permissions flagged (storage and alarms are normal/warning, not critical)
        flagged_perms = [f.name for f in result.findings if f.finding_type == "permission"]
        self.assertIn("Warning Permission: 'storage'", flagged_perms)
        
        # Verify no critical JS signatures matched
        js_findings = [f for f in result.findings if f.finding_type == "signature"]
        self.assertEqual(len(js_findings), 0, f"Expected 0 JS static analysis flags, found: {[f.name for f in js_findings]}")
        
        # Verify risk level is Safe/Warning (storage is Warning permission, so base score is low)
        self.assertEqual(result.risk_level, "Warning") # Forced warning due to warning permissions (storage)
        self.assertLessEqual(result.risk_score, 25.0)

    def test_suspicious_extension_analysis(self):
        """Test that the mock suspicious extension triggers critical alerts."""
        self.assertTrue(os.path.isdir(self.suspicious_ext_path), "Suspicious extension directory must exist.")
        
        result = Scanner.analyze_extension(self.suspicious_ext_path, "Chrome", "suspicious-test-id")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.extension.name, "Super AdBlocker Pro Max")
        
        # Verify critical permissions found
        flagged_perms = [f.name for f in result.findings if f.finding_type == "permission"]
        self.assertIn("Critical Permission: 'cookies'", flagged_perms)
        self.assertIn("Critical Permission: 'webRequest'", flagged_perms)
        
        # Verify static JS findings
        js_findings = [f.name for f in result.findings if f.finding_type == "signature"]
        self.assertTrue(any("Keylogging" in name for name in js_findings), "Expected keylogging signature match.")
        self.assertTrue(any("Cookie Harvesting" in name for name in js_findings), "Expected cookie harvesting signature match.")
        self.assertTrue(any("Exfiltration" in name for name in js_findings), "Expected exfiltration signature match.")
        self.assertTrue(any("Base64" in name or "Packed" in name or "eval" in name for name in js_findings), "Expected obfuscation signature match.")
        
        # Verify risk score & level are Critical
        self.assertEqual(result.risk_level, "Critical")
        self.assertGreaterEqual(result.risk_score, 75.0)

    def test_js_line_by_line_matching(self):
        """Tests manual regex matching on single snippets of JS code."""
        # Simple test mock code
        keylogger_code = "window.addEventListener('keydown', function(e) { log(e.key); });"
        safe_code = "console.log('No keyloggers here');"
        
        # Create temp file for custom scanning
        temp_file = os.path.join(self.base_dir, "temp_test_script.js")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(keylogger_code + "\n" + safe_code)
            
        try:
            findings = Scanner.scan_js_file(temp_file, self.base_dir)
            flag_names = [f.name for f in findings]
            self.assertIn("Keylogging Event Listener", flag_names)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].line_number, 1)
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_new_signatures(self):
        """Tests newly added signatures: sessionStorage, hex array, and hardcoded raw IP."""
        test_script = (
            "let val = sessionStorage.getItem('token');\n"
            "const host = 'http://185.220.101.4/logs';\n"
            "const _0x1a2b = ['a', 'b', 'c'];\n"
            "console.log(String.fromCharCode(72));"
        )
        temp_file = os.path.join(self.base_dir, "temp_test_signatures.js")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(test_script)

        try:
            findings = Scanner.scan_js_file(temp_file, self.base_dir)
            flag_ids = [f.name for f in findings]
            
            # Check for hardcoded raw IP
            self.assertTrue(any("Hardcoded Raw IP" in name for name in flag_ids))
            # Check for hex array
            self.assertTrue(any("Hexadecimal Variable Array" in name for name in flag_ids))
            # Check for String.fromCharCode
            self.assertTrue(any("Dynamic Character Decoding" in name for name in flag_ids))
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

if __name__ == "__main__":
    unittest.main()
