"""
Module 3: Password Suggester
Analyzes password strength and generates secure password suggestions.
"""

import secrets
import string
from zxcvbn import zxcvbn
from typing import Dict, List


class PasswordSuggester:
    """Analyzes password strength and generates suggestions."""
    
    def __init__(self):
        self.min_length = 12
        self.recommended_length = 16
    
    def analyze_strength(self, password: str) -> Dict:
        """
        Analyze password strength using zxcvbn library.
        
        Args:
            password: The password to analyze
            
        Returns:
            Dictionary with strength score and feedback
        """
        result = zxcvbn(password)
        
        return {
            'score': result['score'],  # 0-4 scale (4 is strongest)
            'strength': self._score_to_label(result['score']),
            'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
            'feedback': result['feedback'],
            'length': len(password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_special': any(c in string.punctuation for c in password),
        }
    
    def _score_to_label(self, score: int) -> str:
        """Convert numeric score to human-readable label."""
        labels = {
            0: 'Very Weak',
            1: 'Weak',
            2: 'Fair',
            3: 'Strong',
            4: 'Very Strong'
        }
        return labels.get(score, 'Unknown')
    
    def generate_password(self, length: int = 16, include_symbols: bool = True) -> str:
        """
        Generate a cryptographically secure random password.
        
        Args:
            length: Length of the password (default 16)
            include_symbols: Whether to include special characters
            
        Returns:
            Generated password string
        """
        if length < self.min_length:
            length = self.min_length
        
        # Build character set
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += string.punctuation
        
        # Generate password ensuring it has all required character types
        while True:
            password = ''.join(secrets.choice(chars) for _ in range(length))
            
            # Verify it meets complexity requirements
            if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                (not include_symbols or any(c in string.punctuation for c in password))):
                return password
    
    def generate_passphrase(self, word_count: int = 4) -> str:
        """
        Generate a memorable passphrase using random words.
        
        Args:
            word_count: Number of words in the passphrase
            
        Returns:
            Generated passphrase
        """
        # Simple word list for demo (in production, use a larger dictionary)
        words = [
            'correct', 'horse', 'battery', 'staple', 'mountain', 'river',
            'sunset', 'ocean', 'forest', 'thunder', 'crystal', 'phoenix',
            'dragon', 'wizard', 'castle', 'knight', 'galaxy', 'nebula',
            'quantum', 'cipher', 'enigma', 'paradox', 'zenith', 'aurora'
        ]
        
        selected_words = [secrets.choice(words) for _ in range(word_count)]
        
        # Add random numbers and capitalize
        passphrase = '-'.join(word.capitalize() for word in selected_words)
        passphrase += str(secrets.randbelow(1000))
        
        return passphrase
    
    def suggest_improvements(self, password: str) -> List[str]:
        """
        Suggest improvements for a weak password.
        
        Args:
            password: The password to analyze
            
        Returns:
            List of improvement suggestions
        """
        analysis = self.analyze_strength(password)
        suggestions = []
        
        if analysis['score'] < 3:
            if analysis['length'] < self.min_length:
                suggestions.append(f"Increase length to at least {self.min_length} characters")
            
            if not analysis['has_uppercase']:
                suggestions.append("Add uppercase letters")
            
            if not analysis['has_lowercase']:
                suggestions.append("Add lowercase letters")
            
            if not analysis['has_digits']:
                suggestions.append("Add numbers")
            
            if not analysis['has_special']:
                suggestions.append("Add special characters (!@#$%^&*)")
            
            # Add zxcvbn feedback
            if analysis['feedback']['warning']:
                suggestions.append(f"Warning: {analysis['feedback']['warning']}")
            
            for suggestion in analysis['feedback']['suggestions']:
                suggestions.append(suggestion)
        
        return suggestions
    
    def get_recommendation(self, password: str) -> Dict:
        """
        Get comprehensive recommendation for a password.
        
        Args:
            password: The password to evaluate
            
        Returns:
            Dictionary with analysis and suggestions
        """
        analysis = self.analyze_strength(password)
        improvements = self.suggest_improvements(password)
        
        recommendation = {
            'current_password': {
                'strength': analysis['strength'],
                'score': analysis['score'],
                'crack_time': analysis['crack_time'],
            },
            'needs_improvement': analysis['score'] < 3,
            'suggestions': improvements,
            'alternative_passwords': []
        }
        
        # Generate alternatives if password is weak
        if analysis['score'] < 3:
            recommendation['alternative_passwords'] = [
                {
                    'type': 'random',
                    'password': self.generate_password(16),
                    'description': '16-character random password'
                },
                {
                    'type': 'passphrase',
                    'password': self.generate_passphrase(4),
                    'description': 'Memorable passphrase'
                },
                {
                    'type': 'long_random',
                    'password': self.generate_password(20),
                    'description': '20-character maximum security'
                }
            ]
        
        return recommendation


if __name__ == "__main__":
    # Test the suggester
    suggester = PasswordSuggester()
    
    test_passwords = [
        "password123",
        "MySecretPass123",
        "X9$mK#pL2@qR5nT8vW"
    ]
    
    print("Password Strength Analysis:\n")
    for pwd in test_passwords:
        print(f"Password: {pwd}")
        analysis = suggester.analyze_strength(pwd)
        print(f"  Strength: {analysis['strength']} (Score: {analysis['score']}/4)")
        print(f"  Crack Time: {analysis['crack_time']}")
        
        if analysis['score'] < 3:
            print(f"  Suggestions:")
            for suggestion in suggester.suggest_improvements(pwd):
                print(f"    - {suggestion}")
        print()
    
    print("\nGenerated Secure Passwords:")
    print(f"  Random: {suggester.generate_password(16)}")
    print(f"  Passphrase: {suggester.generate_passphrase(4)}")
