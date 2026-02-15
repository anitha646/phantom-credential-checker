# Phantom Credential Checker 🔒

A high-performance security agent designed to audit documents for sensitive information and verify password security. Powered by **Archestra Interception**, it ensures that sensitive data is automatically redacted before it ever reaches the agent layer.

## 🚀 Key Features

- **Archestra Trace Workflow**: Agent reads PDF → Archestra intercepts → Phantom redacts → Agent sees only safe data.
- **Automatic Redaction**: Detects and masks banking details, credentials, and PII in real-time.
- **AI-Powered Chat Interface**: Modern, interactive UI with side-by-side document comparison.
- **Password Breach Detection**: Integration with Have I Been Pwned API using k-anonymity for privacy.
- **Visual Trace Panels**: Step-by-step visualization of the security interception process.

## 🛠️ Technology Stack

- **Backend**: Python, Flask, zxcvbn, requests
- **Frontend**: Vanilla JS, Modern CSS (Glassmorphism, Gradients)
- **Security Middleware**: Archestra Interceptor, Phantom Redactor

## 📦 Installation

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🚦 Usage

1. Start the Flask server:
   ```bash
   python app.py
   ```
2. Open your browser and navigate to `http://localhost:5000`.
3. Upload a document (e.g., `sample_document.txt`) or paste text into the chat.
4. Watch the **Archestra Trace** visualization and review the sanitized results.

## 🧪 Testing

Run the unit test suite to verify all core modules:
```bash
python test_modules.py
```

## 🛡️ Security Note

This is a demonstration project. In production environments, ensure you implement full encryption at rest/transit and use secure vaulting for any temporary credential handling.
