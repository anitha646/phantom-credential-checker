"""
Module 2: Breach Checker
Checks passwords against Have I Been Pwned database using k-anonymity.
"""

import requests
import hashlib
from typing import Tuple, Optional


class BreachChecker:
    """Checks passwords against breach databases."""
    
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Phantom-Credential-Checker-Demo'
        })
    
    def check_password(self, password: str) -> Tuple[bool, int, Optional[str]]:
        """
        Check if a password has been breached using Have I Been Pwned API.
        Uses k-anonymity model (only sends first 5 chars of SHA-1 hash).
        
        Args:
            password: The password to check
            
        Returns:
            Tuple of (is_breached, breach_count, error_message)
        """
        try:
            # Generate SHA-1 hash of password
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query API with first 5 characters
            response = self.session.get(f"{self.HIBP_API_URL}{prefix}", timeout=5)
            
            if response.status_code != 200:
                return False, 0, f"API error: {response.status_code}"
            
            # Parse response
            hashes = response.text.splitlines()
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    return True, int(count), None
            
            # Not found in breaches
            return False, 0, None
            
        except requests.RequestException as e:
            return False, 0, f"Network error: {str(e)}"
        except Exception as e:
            return False, 0, f"Error: {str(e)}"
    
    def analyze_password_strength(self, password: str) -> dict:
        """
        Analyze password and check for breaches.
        
        Args:
            password: The password to analyze
            
        Returns:
            Dictionary with breach status and recommendations
        """
        is_breached, count, error = self.check_password(password)
        
        result = {
            'password_length': len(password),
            'is_breached': is_breached,
            'breach_count': count,
            'error': error
        }
        
        # Add recommendations
        if is_breached:
            if count > 100000:
                result['risk_level'] = 'CRITICAL'
                result['recommendation'] = 'This password has been seen in over 100k breaches. Change immediately!'
            elif count > 10000:
                result['risk_level'] = 'HIGH'
                result['recommendation'] = 'This password has been breached many times. Change it soon.'
            else:
                result['risk_level'] = 'MEDIUM'
                result['recommendation'] = 'This password has been found in breaches. Consider changing it.'
        else:
            result['risk_level'] = 'LOW'
            result['recommendation'] = 'No breaches found for this password.'
        
        return result
    
    def batch_check(self, passwords: list) -> list:
        """
        Check multiple passwords for breaches.
        
        Args:
            passwords: List of passwords to check
            
        Returns:
            List of results for each password
        """
        results = []
        for pwd in passwords:
            is_breached, count, error = self.check_password(pwd)
            results.append({
                'password': pwd[:3] + '*' * (len(pwd) - 3),  # Mask password
                'is_breached': is_breached,
                'breach_count': count,
                'error': error
            })
        
        return results


if __name__ == "__main__":
    # Test the breach checker
    checker = BreachChecker()
    
    test_passwords = [
        "password123",  # Very common, will be breached
        "MySecretPass123",  # Might be breached
        "X9$mK#pL2@qR5nT8vW",  # Strong, unlikely to be breached
    ]
    
    print("Checking passwords for breaches...\n")
    for pwd in test_passwords:
        result = checker.analyze_password_strength(pwd)
        print(f"Password: {pwd[:3]}{'*' * (len(pwd) - 3)}")
        print(f"  Breached: {result['is_breached']}")
        print(f"  Count: {result['breach_count']}")
        print(f"  Risk: {result['risk_level']}")
        print(f"  Recommendation: {result['recommendation']}\n")
