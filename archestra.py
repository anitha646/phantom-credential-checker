"""
Module 5: Archestra Interceptor
Middleware layer that intercepts document reads and automatically invokes redaction.
"""

import time
from typing import Dict, List, Callable, Any
from functools import wraps
from phantom_redactor import PhantomRedactor


class ArchestraInterceptor:
    """
    Archestra middleware that intercepts all document processing.
    Ensures sensitive data is redacted before reaching the agent.
    """
    
    def __init__(self):
        self.redactor = PhantomRedactor()
        self.trace_log = []
        self.interception_count = 0
    
    def intercept(self, func: Callable) -> Callable:
        """
        Decorator that intercepts function calls and applies redaction.
        
        Usage:
            @archestra.intercept
            def process_document(content):
                # This function will receive redacted content
                return analysis
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Start trace
            trace_id = self._start_trace()
            
            # Extract content from arguments (assume first arg or 'content' kwarg)
            content = args[0] if args else kwargs.get('content', '')
            
            # Step 1: Agent attempts to read
            self._log_trace(trace_id, 'AGENT_READ', 'Agent attempting to read document', {
                'content_length': len(content),
                'timestamp': time.time()
            })
            
            # Step 2: Archestra intercepts
            self._log_trace(trace_id, 'ARCHESTRA_INTERCEPT', 'Archestra intercepted the read operation', {
                'interception_count': self.interception_count,
                'timestamp': time.time()
            })
            
            # Step 3: Phantom redacts
            redaction_result = self.redactor.redact_document(content)
            self._log_trace(trace_id, 'PHANTOM_REDACT', 'Phantom redacted sensitive data', {
                'redactions': redaction_result['redaction_count'],
                'summary': redaction_result['summary'],
                'timestamp': time.time()
            })
            
            # Step 4: Agent receives safe data
            safe_content = redaction_result['redacted']
            self._log_trace(trace_id, 'SAFE_DATA_DELIVERED', 'Agent received sanitized data', {
                'safe_content_length': len(safe_content),
                'timestamp': time.time()
            })
            
            # Call original function with redacted content
            if args:
                args = (safe_content,) + args[1:]
            else:
                kwargs['content'] = safe_content
            
            result = func(*args, **kwargs)
            
            # Complete trace
            self._complete_trace(trace_id)
            
            return result
        
        return wrapper
    
    def process_with_trace(self, content: str) -> Dict[str, Any]:
        """
        Process content and return complete trace information.
        
        Args:
            content: The content to process
            
        Returns:
            Dictionary with original, redacted, trace steps, and metadata
        """
        trace_id = self._start_trace()
        
        # Step 1: Agent reads
        step1 = {
            'step': 1,
            'name': 'Agent Reads Document',
            'description': 'Agent attempts to read the uploaded document',
            'status': 'completed',
            'data': {
                'content_preview': content[:100] + '...' if len(content) > 100 else content,
                'length': len(content)
            },
            'timestamp': time.time()
        }
        self._log_trace(trace_id, 'AGENT_READ', step1['description'], step1['data'])
        
        # Step 2: Archestra intercepts
        step2 = {
            'step': 2,
            'name': 'Archestra Intercepts',
            'description': 'Archestra middleware intercepts the read operation',
            'status': 'completed',
            'data': {
                'action': 'INTERCEPT',
                'reason': 'Automatic security scan triggered'
            },
            'timestamp': time.time()
        }
        self._log_trace(trace_id, 'ARCHESTRA_INTERCEPT', step2['description'], step2['data'])
        
        # Step 3: Phantom redacts
        redaction_result = self.redactor.redact_document(content)
        step3 = {
            'step': 3,
            'name': 'Phantom Redacts',
            'description': 'Phantom automatically redacts sensitive information',
            'status': 'completed',
            'data': {
                'redactions_made': redaction_result['redaction_count'],
                'summary': redaction_result['summary'],
                'redaction_log': redaction_result['redaction_log']
            },
            'timestamp': time.time()
        }
        self._log_trace(trace_id, 'PHANTOM_REDACT', step3['description'], step3['data'])
        
        # Step 4: Agent receives safe data
        step4 = {
            'step': 4,
            'name': 'Agent Sees Safe Data',
            'description': 'Agent receives only the sanitized, safe version',
            'status': 'completed',
            'data': {
                'safe_content_preview': redaction_result['redacted'][:100] + '...' if len(redaction_result['redacted']) > 100 else redaction_result['redacted'],
                'length': len(redaction_result['redacted'])
            },
            'timestamp': time.time()
        }
        self._log_trace(trace_id, 'SAFE_DATA_DELIVERED', step4['description'], step4['data'])
        
        self._complete_trace(trace_id)
        
        return {
            'trace_id': trace_id,
            'original_content': content,
            'redacted_content': redaction_result['redacted'],
            'safe_data': redaction_result['redacted'],
            'redaction_summary': redaction_result['summary'],
            'redaction_details': redaction_result['redaction_log'],
            'trace_steps': [step1, step2, step3, step4],
            'interception_successful': True
        }
    
    def _start_trace(self) -> str:
        """Start a new trace and return trace ID."""
        self.interception_count += 1
        trace_id = f"TRACE-{self.interception_count:04d}"
        
        self.trace_log.append({
            'trace_id': trace_id,
            'start_time': time.time(),
            'events': [],
            'status': 'in_progress'
        })
        
        return trace_id
    
    def _log_trace(self, trace_id: str, event_type: str, description: str, data: Dict):
        """Log an event in the trace."""
        for trace in self.trace_log:
            if trace['trace_id'] == trace_id:
                trace['events'].append({
                    'type': event_type,
                    'description': description,
                    'data': data,
                    'timestamp': time.time()
                })
                break
    
    def _complete_trace(self, trace_id: str):
        """Mark a trace as completed."""
        for trace in self.trace_log:
            if trace['trace_id'] == trace_id:
                trace['status'] = 'completed'
                trace['end_time'] = time.time()
                trace['duration'] = trace['end_time'] - trace['start_time']
                break
    
    def get_trace_history(self, limit: int = 10) -> List[Dict]:
        """
        Get recent trace history.
        
        Args:
            limit: Maximum number of traces to return
            
        Returns:
            List of recent traces
        """
        return self.trace_log[-limit:]
    
    def get_trace_by_id(self, trace_id: str) -> Dict:
        """Get a specific trace by ID."""
        for trace in self.trace_log:
            if trace['trace_id'] == trace_id:
                return trace
        return None
    
    def get_statistics(self) -> Dict:
        """Get interception statistics."""
        total_redactions = 0
        total_duration = 0
        
        for trace in self.trace_log:
            if trace['status'] == 'completed':
                total_duration += trace.get('duration', 0)
                for event in trace['events']:
                    if event['type'] == 'PHANTOM_REDACT':
                        total_redactions += event['data'].get('redactions', 0)
        
        return {
            'total_interceptions': self.interception_count,
            'total_redactions': total_redactions,
            'average_duration': total_duration / len(self.trace_log) if self.trace_log else 0,
            'traces_completed': sum(1 for t in self.trace_log if t['status'] == 'completed')
        }


# Global instance
archestra = ArchestraInterceptor()


if __name__ == "__main__":
    # Test the interceptor
    print("Testing Archestra Interceptor\n")
    print("=" * 60)
    
    test_document = """
    CONFIDENTIAL BANKING INFORMATION
    
    Account Number: 123456789012
    Routing Number: 021000021
    Password: MySecretPass123
    Email: user@example.com
    """
    
    # Process with trace
    result = archestra.process_with_trace(test_document)
    
    print(f"\nTrace ID: {result['trace_id']}")
    print(f"Interception Successful: {result['interception_successful']}")
    print(f"\nRedaction Summary:")
    print(f"  Total Redactions: {result['redaction_summary']['total_redactions']}")
    print(f"  By Type: {result['redaction_summary']['by_type']}")
    
    print(f"\nTrace Steps:")
    for step in result['trace_steps']:
        print(f"\n  Step {step['step']}: {step['name']}")
        print(f"    Description: {step['description']}")
        print(f"    Status: {step['status']}")
    
    print("\n" + "=" * 60)
    print("\nOriginal Content:")
    print(result['original_content'])
    
    print("\n" + "=" * 60)
    print("\nSafe Data (What Agent Sees):")
    print(result['safe_data'])
    
    print("\n" + "=" * 60)
    print("\nStatistics:")
    stats = archestra.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
