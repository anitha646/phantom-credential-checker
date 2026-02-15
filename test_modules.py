import unittest
import os
from inspector import DocumentInspector
from breach_checker import BreachChecker
from suggester import PasswordSuggester
from phantom_redactor import PhantomRedactor
from archestra import archestra

class TestPhantomModules(unittest.TestCase):
    def setUp(self):
        self.inspector = DocumentInspector()
        self.breach_checker = BreachChecker()
        self.suggester = PasswordSuggester()
        self.redactor = PhantomRedactor()

    def test_inspector_detection(self):
        """Test if the inspector can detect various sensitive items."""
        test_text = "Account: 123456789, Route: 987654321, Card: 1111-2222-3333-4444, Pass: Secret123"
        findings = self.inspector.inspect_text(test_text)
        
        types_found = [f['type'] for f in findings]
        self.assertIn('account_number', types_found)
        self.assertIn('routing_number', types_found)
        self.assertIn('credit_card', types_found)
        self.assertIn('password', types_found)

    def test_redactor_masking(self):
        """Test if sensitive data is correctly masked/redacted."""
        test_text = "Password: MySecret123"
        redacted, _ = self.redactor.redact_text(test_text, preserve_format=True)
        # The whole "Password: MySecret123" is matched and redacted
        self.assertIn("Pa*****************", redacted)
        self.assertNotIn("MySecret123", redacted)

    def test_password_strength(self):
        """Test password strength analysis."""
        weak_pwd = "password123"
        strong_pwd = "X9$mK#pL2@qR5nT8vW"
        
        weak_analysis = self.suggester.analyze_strength(weak_pwd)
        strong_analysis = self.suggester.analyze_strength(strong_pwd)
        
        self.assertLess(weak_analysis['score'], 2)
        self.assertEqual(strong_analysis['score'], 4)

    def test_archestra_interception(self):
        """Test the Archestra interception flow."""
        test_doc = "Confidential Account: 123456789"
        result = archestra.process_with_trace(test_doc)
        
        self.assertTrue(result['interception_successful'])
        self.assertEqual(len(result['trace_steps']), 4)
        # Should be masked since preserve_format is True by default
        self.assertIn("Ac****************", result['redacted_content'])

if __name__ == '__main__':
    unittest.main()
