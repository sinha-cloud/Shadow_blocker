from enum import Enum
from typing import List, Optional, Dict, Any
import os

class FindingSeverity(Enum):
    SAFE = "Safe"
    WARNING = "Warning"
    CRITICAL = "Critical"

class AnalysisFinding:
    """Represents a specific flag triggered during static analysis or manifest parsing."""
    def __init__(
        self,
        finding_type: str,  # 'permission' or 'signature'
        name: str,
        description: str,
        severity: FindingSeverity,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        snippet: Optional[str] = None
    ):
        self.finding_type = finding_type
        self.name = name
        self.description = description
        self.severity = severity
        self.file_path = file_path
        self.line_number = line_number
        self.snippet = snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet
        }

class ExtensionInfo:
    """Represents raw metadata parsed from an extension directory and manifest.json."""
    def __init__(
        self,
        ext_id: str,
        name: str,
        version: str,
        description: str,
        path: str,
        browser: str,
        manifest_version: int,
        permissions: List[str],
        host_permissions: List[str],
        background_scripts: List[str],
        content_scripts: List[str]
    ):
        self.id = ext_id
        self.name = name
        self.version = version
        self.description = description
        self.path = os.path.normpath(path)
        self.browser = browser
        self.manifest_version = manifest_version
        self.permissions = permissions
        self.host_permissions = host_permissions
        self.background_scripts = background_scripts
        self.content_scripts = content_scripts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "path": self.path,
            "browser": self.browser,
            "manifest_version": self.manifest_version,
            "permissions": self.permissions,
            "host_permissions": self.host_permissions,
            "background_scripts": self.background_scripts,
            "content_scripts": self.content_scripts
        }

class ScanResult:
    """Combines an extension's metadata with findings and calculated risk metrics."""
    def __init__(
        self,
        extension: ExtensionInfo,
        findings: List[AnalysisFinding],
        risk_score: float,
        risk_level: str
    ):
        self.extension = extension
        self.findings = findings
        self.risk_score = risk_score
        self.risk_level = risk_level  # 'Safe', 'Warning', 'Critical'

    def to_dict(self) -> Dict[str, Any]:
        return {
            "extension": self.extension.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level
        }
