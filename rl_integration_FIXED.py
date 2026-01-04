# RL Integration for Honeypot - PERSISTENT VERSION
import pickle
import numpy as np
import random
import sys
import os

# Add /app/data to path so we can import ai_mimic
sys.path.append('/app')
from ai_mimic import AIMimicEngine

class RLEnhancedHoneypot:
    def __init__(self):
        self.ai_engine = AIMimicEngine()
        self.q_table = self.load_rl_model()
        self.engagement_tracker = {}
        
        self.actions = [
            {'name': 'LOW', 'delay': 1, 'status': 200},
            {'name': 'MEDIUM', 'delay': 3, 'status': 404},
            {'name': 'HIGH', 'delay': 5, 'status': 403},
            {'name': 'CRITICAL', 'delay': 8, 'status': 500}
        ]
        print(f"🤖 RL Agent initialized with {len(self.q_table)} states")
    
    def load_rl_model(self):
        """Load from mounted data directory"""
        try:
            model_path = '/app/data/rl_models/final_correct_agent.pkl'
            with open(model_path, 'rb') as f:
                agent = pickle.load(f)
            print(f"✅ Loaded RL model from {model_path}")
            return agent.get('q_table', self.create_default_q_table())
        except Exception as e:
            print(f"⚠️ Could not load RL model: {e}")
            return self.create_default_q_table()
    
    def create_default_q_table(self):
        return {
            'LOW_NEW': np.array([10.0, 0.0, 0.0, 0.0]),
            'LOW_ENGAGED': np.array([10.0, 0.0, 0.0, 0.0]),
            'MEDIUM_NEW': np.array([0.0, 10.0, 0.0, 0.0]),
            'MEDIUM_ENGAGED': np.array([0.0, 10.0, 0.0, 0.0]),
            'HIGH_NEW': np.array([0.0, 0.0, 10.0, 0.0]),
            'HIGH_ENGAGED': np.array([0.0, 0.0, 10.0, 0.0]),
            'CRITICAL_NEW': np.array([0.0, 0.0, 0.0, 10.0]),
            'CRITICAL_ENGAGED': np.array([0.0, 0.0, 0.0, 10.0]),
        }
    
    def path_to_state(self, path, engagement):
        path_lower = str(path).lower()
        
        # Check for command injection FIRST (most critical)
        # Command injection indicators
        cmd_injection_indicators = [';', '&', '|', '`', '$', '$(', '${', 'cat+', 'whoami', 
                                   'uname', 'id', 'ls', 'exec=', 'cmd=', 'command=', 'run=', 
                                   'input=', '$(cat', '${cat', '/etc/passwd', '/etc/shadow']
        
        # Check if this is a ping request
        is_ping_request = 'ping?ip=' in path_lower
        
        if any(indicator in path_lower for indicator in cmd_injection_indicators):
            # Has command injection - definitely CRITICAL
            path_type = 'CRITICAL'
        
        # Check for Localhost/internal IP in ping (suspicious but not critical alone)
        elif is_ping_request and any(ip in path_lower for ip in ['127.0.0.1', 'localhost', '192.168.', '10.', '172.']):
            # Ping to internal/Localhost - HIGH threat
            path_type = 'HIGH'
        
        # Check other CRITICAL patterns (not ping-specific)
        elif any(x in path_lower for x in [
            '..', '../', '..\\\\', '..%2f', '....//',
            '/windows/system32',
            'shell.php', 'cmd.jsp', 'wso.php', 'backdoor',
            '.jsp?', '.php?cmd=', '.asp?exec=',
            'php://', 'data://', 'expect://',
            "' or '1'='1", 'or 1=1', 'union select',
            'sleep(', 'benchmark(', 'waitfor delay',
            '--', '#', '/*', '*/'
        ]):
            path_type = 'CRITICAL'
        
        # HIGH threats (admin pages, etc.)
        elif any(x in path_lower for x in [
            'admin', 'administrator', 'login', 'auth',
            'dashboard', 'control', 'console',
            'index.php', 'login.php', 'auth.php', 'session',
            'upload', 'export', 'import', 'backup',
            'config', 'setup', 'install', 'upgrade',
            '/cgi-bin/', '/boaform/', '/formLogin', '/login.cgi'
        ]):
            path_type = 'HIGH'
        
        # MEDIUM threats (suspicious but not critical)
        elif any(x in path_lower for x in [
            'test', 'debug', 'phpinfo', 'info.php',
            'wp-admin', 'wp-login', 'joomla/administrator',
            'cgi-bin/test.cgi', 'api/', 'v1/', 'v2/'
        ]):
            path_type = 'MEDIUM'
        
        # DEFAULT: LOW threat
        else:
            path_type = 'LOW'
        
        # Add engagement level
        if engagement <= 2:
            engagement_level = 'NEW'
        else:
            engagement_level = 'ENGAGED'
        
        return f"{path_type}_{engagement_level}"
        
        # CRITICAL
        if any(x in path_lower for x in [
            ';', '&', '|', '`', '$', '$(', '${',
            'cat+', 'whoami', 'uname', 'id', 'ls',
            'exec=', 'cmd=', 'command=', 'run=', 'input=',
            'ping?ip=', 'api/test?input=', '$(cat', '${cat',
            '..', '../', '..\\\\', '..%2f', '....//',
            '/etc/passwd', '/etc/shadow', '/windows/system32',
            'shell.php', 'cmd.jsp', 'wso.php', 'backdoor',
            '.jsp?', '.php?cmd=', '.asp?exec=',
            'php://', 'data://', 'expect://',
            "' or '1'='1", 'or 1=1', 'union select',
            'sleep(', 'benchmark(', 'waitfor delay',
            '--', '#', '/*', '*/'
        ]):
            path_type = 'CRITICAL'
        
        # HIGH
        elif any(x in path_lower for x in [
            'admin', 'administrator', 'login', 'auth',
            'dashboard', 'control', 'console',
            'index.php', 'login.php', 'auth.php', 'session',
            'upload', 'export', 'import', 'backup',
            'config', 'setup', 'install', 'upgrade',
            '/cgi-bin/', '/boaform/', '/formLogin', '/login.cgi'
        ]):
            path_type = 'HIGH'
        
        # MEDIUM
        elif any(x in path_lower for x in [
            'cgi-bin', '.cgi', '.php', '.asp', '.jsp', '.pl', '.py',
            '<script>', 'javascript:', 'onerror=', 'alert(',
            'document.', 'window.', '<img', '<iframe',
            'file://', 'gopher://', 'dict://',
            '169.254.169.254', 'metadata', 'meta-data',
            'wp-admin', 'wp-login', 'wp-content'
        ]) or path_lower.endswith(('.cgi', '.php', '.asp', '.jsp')):
            path_type = 'MEDIUM'
        
        # LOW
        else:
            path_type = 'LOW'
        
        engagement_level = 'NEW' if engagement <= 2 else 'ENGAGED'
        return f"{path_type}_{engagement_level}"
    
    def choose_rl_action(self, state_key):
        if state_key not in self.q_table or random.random() < 0.1:
            if 'CRITICAL' in state_key: return 3
            elif 'HIGH' in state_key: return 2
            elif 'MEDIUM' in state_key: return 1
            else: return 0
        else:
            return np.argmax(self.q_table[state_key])
    
    def process_attack(self, attack_data):
        source_ip = attack_data.get('source_ip', 'unknown')
        self.engagement_tracker[source_ip] = self.engagement_tracker.get(source_ip, 0) + 1
        engagement = self.engagement_tracker[source_ip]
        
        ai_response = self.ai_engine.analyze_attack(attack_data)
        ai_threat = ai_response['threat_level']
        
        path = attack_data.get('path', '')
        state_key = self.path_to_state(path, engagement)
        rl_action_idx = self.choose_rl_action(state_key)
        rl_threat = self.actions[rl_action_idx]['name']
        
        threat_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        final_threat = ai_threat if threat_order[ai_threat] >= threat_order[rl_threat] else rl_threat
        
        response = self.ai_engine.generate_response(final_threat)
        response['rl_response'] = {
            'state': state_key,
            'rl_recommendation': rl_threat,
            'ai_recommendation': ai_threat,
            'final_decision': final_threat,
            'engagement_count': engagement,
            'source_ip': source_ip
        }
        
        return response

if __name__ == "__main__":
    print("🧪 Testing RL Integration")
    hp = RLEnhancedHoneypot()
    test = {'source_ip': 'test', 'path': '/admin', 'method': 'GET'}
    result = hp.process_attack(test)
    print(f"✅ Test result: {result.get('rl_response', {})}")
