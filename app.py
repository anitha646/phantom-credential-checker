"""
Flask MCP Server - Main Application
Integrates all modules with Archestra interception middleware.
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import traceback

from archestra import archestra
from inspector import DocumentInspector
from breach_checker import BreachChecker
from suggester import PasswordSuggester
from phantom_redactor import PhantomRedactor

app = Flask(__name__)
CORS(app)  # Enable CORS for development

# Initialize modules
inspector = DocumentInspector()
breach_checker = BreachChecker()
suggester = PasswordSuggester()
redactor = PhantomRedactor()


@app.route('/')
def index():
    """Serve the main web interface."""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze_document():
    """
    Analyze a document with Archestra trace.
    Returns: {original, redacted, safe_data, trace_steps, analysis}
    """
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({'error': 'No content provided'}), 400
        
        content = data['content']
        
        # Ensure content is a string
        if not isinstance(content, str):
            # If it's a dict or list, the user might be accidentally sending parsed JSON
            # For this demo, we'll convert it to a string to be helpful
            content = str(content)
        
        # Process through Archestra interceptor
        trace_result = archestra.process_with_trace(content)
        
        # Analyze the SAFE (redacted) data for additional insights
        safe_findings = inspector.inspect_text(trace_result['safe_data'])
        
        # Extract any passwords from redaction log to check breaches
        breach_results = []
        for redaction in trace_result['redaction_details']:
            if redaction['type'] == 'password':
                pwd = redaction['original']
                breach_analysis = breach_checker.analyze_password_strength(pwd)
                strength_analysis = suggester.analyze_strength(pwd)
                
                breach_results.append({
                    'password_masked': pwd[:2] + '*' * (len(pwd) - 2),
                    'breach_status': breach_analysis,
                    'strength': strength_analysis,
                    'suggestions': suggester.suggest_improvements(pwd)
                })
        
        # Generate password suggestions if weak passwords found
        suggestions = []
        if breach_results:
            suggestions = [
                {
                    'type': 'random',
                    'password': suggester.generate_password(16),
                    'description': '16-character random password'
                },
                {
                    'type': 'passphrase',
                    'password': suggester.generate_passphrase(4),
                    'description': 'Memorable passphrase'
                }
            ]
        
        return jsonify({
            'success': True,
            'trace_id': trace_result['trace_id'],
            'original_content': trace_result['original_content'],
            'redacted_content': trace_result['redacted_content'],
            'safe_data': trace_result['safe_data'],
            'trace_steps': trace_result['trace_steps'],
            'redaction_summary': trace_result['redaction_summary'],
            'redaction_details': trace_result['redaction_details'],
            'breach_analysis': breach_results,
            'password_suggestions': suggestions,
            'interception_successful': trace_result['interception_successful']
        })
        
    except Exception as e:
        app.logger.error(f"Error in analyze_document: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e),
            'trace': traceback.format_exc()
        }), 500


@app.route('/api/check-breach', methods=['POST'])
def check_breach():
    """Check a single password for breaches."""
    try:
        data = request.get_json()
        
        if not data or 'password' not in data:
            return jsonify({'error': 'No password provided'}), 400
        
        password = data['password']
        
        # Check breach
        breach_analysis = breach_checker.analyze_password_strength(password)
        
        # Analyze strength
        strength_analysis = suggester.analyze_strength(password)
        
        # Get recommendations
        recommendation = suggester.get_recommendation(password)
        
        return jsonify({
            'success': True,
            'breach_status': breach_analysis,
            'strength_analysis': strength_analysis,
            'recommendation': recommendation
        })
        
    except Exception as e:
        app.logger.error(f"Error in check_breach: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/trace', methods=['GET'])
def get_trace_history():
    """Get Archestra trace history."""
    try:
        limit = request.args.get('limit', 10, type=int)
        traces = archestra.get_trace_history(limit)
        stats = archestra.get_statistics()
        
        return jsonify({
            'success': True,
            'traces': traces,
            'statistics': stats
        })
        
    except Exception as e:
        app.logger.error(f"Error in get_trace_history: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/trace/<trace_id>', methods=['GET'])
def get_trace_detail(trace_id):
    """Get details of a specific trace."""
    try:
        trace = archestra.get_trace_by_id(trace_id)
        
        if trace:
            return jsonify({
                'success': True,
                'trace': trace
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Trace not found'
            }), 404
            
    except Exception as e:
        app.logger.error(f"Error in get_trace_detail: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'Phantom Credential Checker',
        'archestra_active': True,
        'modules': {
            'inspector': True,
            'breach_checker': True,
            'suggester': True,
            'redactor': True,
            'archestra': True
        }
    })


if __name__ == '__main__':
    print("=" * 60)
    print("PHANTOM CREDENTIAL CHECKER - MCP SERVER")
    print("=" * 60)
    print("\n[OK] Archestra Interceptor: ACTIVE")
    print("[OK] Phantom Redactor: ACTIVE")
    print("[OK] Breach Checker: ACTIVE")
    print("[OK] Password Suggester: ACTIVE")
    print("\nServer starting on http://localhost:5000")
    print("=" * 60)
    print("\nAvailable Endpoints:")
    print("  GET  /              - Web Interface")
    print("  POST /api/analyze   - Analyze Document")
    print("  POST /api/check-breach - Check Password")
    print("  GET  /api/trace     - Trace History")
    print("  GET  /api/health    - Health Check")
    print("\n" + "=" * 60 + "\n")
    
    app.run(debug=True, port=5000, host='0.0.0.0')
