"""
Module 4: Phantom Redactor
Automatically redacts sensitive information from documents.
"""

import re
from typing import Dict, List, Tuple
from inspector import DocumentInspector


class PhantomRedactor:
    """Automatically redacts sensitive data from documents."""
    
    REDACTION_MARKERS = {
        'credit_card': '[REDACTED-CREDIT-CARD]',
        'ssn': '[REDACTED-SSN]',
        'account_number': '[REDACTED-ACCOUNT]',
        'routing_number': '[REDACTED-ROUTING]',
        'email': '[REDACTED-EMAIL]',
        'password': '[REDACTED-PASSWORD]',
        'api_key': '[REDACTED-API-KEY]',
    }
    
    def __init__(self):
        self.inspector = DocumentInspector()
        self.redaction_log = []
    
    def redact_text(self, text: str, preserve_format: bool = True) -> Tuple[str, List[Dict]]:
        """
        Redact sensitive information from text.
        
        Args:
            text: The text to redact
            preserve_format: Whether to preserve text length with asterisks
            
        Returns:
            Tuple of (redacted_text, redaction_log)
        """
        # Find all sensitive information
        findings = self.inspector.inspect_text(text)
        
        # Sort findings by position (reverse order to maintain positions)
        findings_sorted = sorted(findings, key=lambda x: x['position'][0], reverse=True)
        
        redacted_text = text
        redaction_log = []
        
        for finding in findings_sorted:
            start, end = finding['position']
            original_value = finding['value']
            finding_type = finding['type']
            
            # Choose redaction marker
            if preserve_format:
                # Keep first few chars visible, mask the rest
                if len(original_value) > 4:
                    visible_chars = 2
                    redacted_value = original_value[:visible_chars] + '*' * (len(original_value) - visible_chars)
                else:
                    redacted_value = '*' * len(original_value)
            else:
                redacted_value = self.REDACTION_MARKERS.get(finding_type, '[REDACTED]')
            
            # Replace in text
            redacted_text = redacted_text[:start] + redacted_value + redacted_text[end:]
            
            # Log the redaction
            redaction_log.append({
                'type': finding_type,
                'original': original_value,
                'redacted': redacted_value,
                'position': finding['position'],
                'severity': finding['severity']
            })
        
        return redacted_text, redaction_log
    
    def redact_document(self, content: str) -> Dict:
        """
        Redact a complete document and return both versions.
        
        Args:
            content: The document content
            
        Returns:
            Dictionary with original, redacted, and metadata
        """
        redacted_text, redaction_log = self.redact_text(content)
        
        return {
            'original': content,
            'redacted': redacted_text,
            'redaction_count': len(redaction_log),
            'redaction_log': redaction_log,
            'summary': self._create_summary(redaction_log)
        }
    
    def _create_summary(self, redaction_log: List[Dict]) -> Dict:
        """Create a summary of redactions."""
        summary = {
            'total_redactions': len(redaction_log),
            'by_type': {},
            'by_severity': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        }
        
        for redaction in redaction_log:
            # Count by type
            r_type = redaction['type']
            summary['by_type'][r_type] = summary['by_type'].get(r_type, 0) + 1
            
            # Count by severity
            severity = redaction['severity']
            summary['by_severity'][severity] += 1
        
        return summary
    
    def create_safe_version(self, content: str) -> str:
        """
        Create a completely safe version with all sensitive data removed.
        
        Args:
            content: The original content
            
        Returns:
            Safe version of the content
        """
        redacted_text, _ = self.redact_text(content, preserve_format=False)
        return redacted_text
    
    def get_redaction_report(self, content: str) -> Dict:
        """
        Generate a detailed redaction report.
        
        Args:
            content: The content to analyze
            
        Returns:
            Detailed report of what was redacted
        """
        result = self.redact_document(content)
        
        report = {
            'document_length': len(content),
            'redacted_length': len(result['redacted']),
            'total_findings': result['redaction_count'],
            'summary': result['summary'],
            'details': []
        }
        
        for redaction in result['redaction_log']:
            report['details'].append({
                'type': redaction['type'],
                'severity': redaction['severity'],
                'preview': redaction['original'][:10] + '...' if len(redaction['original']) > 10 else redaction['original'],
                'action': 'REDACTED'
            })
        
        return report


if __name__ == "__main__":
    # Test the redactor
    redactor = PhantomRedactor()
    
    test_document = """
    CONFIDENTIAL BANKING INFORMATION
    
    Customer: John Doe
    Email: john.doe@example.com
    Account Number: 123456789012
    Routing Number: 021000021
    Credit Card: 4532-1234-5678-9010
    
    Online Banking Credentials:
    Username: johndoe
    Password: MySecretPass123
    
    API Key: FAKE_STRIPE_KEY_REDACTED_FOR_SECURITY
    """
    
    print("Original Document:")
    print(test_document)
    print("\n" + "="*60 + "\n")
    
    result = redactor.redact_document(test_document)
    
    print("Redacted Document:")
    print(result['redacted'])
    print("\n" + "="*60 + "\n")
    
    print("Redaction Summary:")
    print(f"Total Redactions: {result['summary']['total_redactions']}")
    print(f"By Type: {result['summary']['by_type']}")
    print(f"By Severity: {result['summary']['by_severity']}")
    print("\n" + "="*60 + "\n")
    
    print("Safe Version (Full Redaction):")
    print(redactor.create_safe_version(test_document))
