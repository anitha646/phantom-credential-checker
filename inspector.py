"""
Module 1: Document Inspector
Detects banking details, credentials, and sensitive information in documents.
"""

import re
import os
from typing import Dict, List, Any


class DocumentInspector:
    """Inspects documents for sensitive information."""
    
    # Regex patterns for sensitive data detection
    PATTERNS = {
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'account_number': r'\b(?:[Aa]ccount\s*(?:[Nn]umber|[Nn]o\.?|#)?|[Aa][Cc][Cc][Tt]\s*#?)\s*:?\s*(\d{8,17})\b',
        'routing_number': r'\b(?:[Rr]outing\s*(?:[Nn]umber|[Nn]o\.?|#)?|[Rr][Tt][Gg]\s*#?|[Rr]oute\s*:?)\s*:?\s*(\d{9})\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'password': r'\b(?:[Pp]assword|[Pp]ass|[Pp]wd)\s*:?\s*([^\s]+)\b',
        'api_key': r'\b(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?\b',
    }
    
    def __init__(self):
        self.findings = []
    
    def inspect_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Inspect text content for sensitive information.
        
        Args:
            text: The text content to inspect
            
        Returns:
            List of findings with type, value, and position
        """
        if not isinstance(text, str):
            text = str(text)
            
        findings = []
        
        for pattern_name, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                finding = {
                    'type': pattern_name,
                    'value': match.group(0),
                    'position': match.span(),
                    'severity': self._get_severity(pattern_name)
                }
                findings.append(finding)
        
        return findings
    
    def inspect_file(self, file_path: str) -> Dict[str, Any]:
        """
        Inspect a file for sensitive information.
        
        Args:
            file_path: Path to the file to inspect
            
        Returns:
            Dictionary with file info and findings
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            findings = self.inspect_text(content)
            
            return {
                'file': os.path.basename(file_path),
                'path': file_path,
                'findings': findings,
                'total_findings': len(findings),
                'content_preview': content[:500]  # First 500 chars
            }
        except Exception as e:
            return {
                'file': os.path.basename(file_path) if file_path else 'unknown',
                'error': str(e),
                'findings': []
            }
    
    def _get_severity(self, pattern_type: str) -> str:
        """Determine severity level based on pattern type."""
        high_severity = ['credit_card', 'ssn', 'password', 'api_key']
        medium_severity = ['account_number', 'routing_number']
        
        if pattern_type in high_severity:
            return 'HIGH'
        elif pattern_type in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Get a summary of findings by type.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary with counts by type
        """
        summary = {}
        for finding in findings:
            finding_type = finding['type']
            summary[finding_type] = summary.get(finding_type, 0) + 1
        
        return summary


def inspect_browser_storage(browser: str = "chrome") -> List[Dict[str, Any]]:
    """
    Inspect browser local storage for potential credentials.
    Note: This is a simplified version for demo purposes.
    
    Args:
        browser: Browser name (chrome, firefox, etc.)
        
    Returns:
        List of potential storage locations
    """
    storage_paths = {
        'chrome': os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/Local Storage"),
        'firefox': os.path.expanduser("~/Library/Application Support/Firefox/Profiles"),
    }
    
    path = storage_paths.get(browser.lower(), "")
    
    if os.path.exists(path):
        try:
            files = os.listdir(path)
            return [{
                'browser': browser,
                'storage_path': path,
                'files_found': len(files),
                'note': 'Browser storage detected (read-only scan)'
            }]
        except Exception as e:
            return [{'error': str(e), 'browser': browser}]
    else:
        return [{'browser': browser, 'status': 'not_found'}]


if __name__ == "__main__":
    # Test the inspector
    inspector = DocumentInspector()
    
    test_text = """
    Account Number: 123456789012
    Routing Number: 021000021
    Credit Card: 4532-1234-5678-9010
    Password: MySecretPass123
    Email: user@example.com
    """
    
    findings = inspector.inspect_text(test_text)
    print(f"Found {len(findings)} sensitive items:")
    for finding in findings:
        print(f"  - {finding['type']}: {finding['value']} (Severity: {finding['severity']})")
