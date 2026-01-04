from flask import Flask, request, Response, jsonify
import os, requests, json, datetime, sys, time

sys.path.append('/app/data')

try:
    from rl_integration_FIXED import RLEnhancedHoneypot
    enhanced_honeypot = RLEnhancedHoneypot()
    RL_AVAILABLE = True
except Exception as e:
    print(f"❌ Could not load RL integration: {e}")
    RL_AVAILABLE = False
    enhanced_honeypot = None

app = Flask(__name__)

def log_attack(req):
    attack_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'source_ip': req.remote_addr,
        'method': req.method,
        'path': req.path,
        'user_agent': req.headers.get('User-Agent'),
        'headers': dict(req.headers),
        'data': req.get_data().decode() if req.get_data() else None,
        'query_params': dict(request.args)
    }
    
    print(f"🚨 ATTACK: {attack_data['source_ip']} -> {attack_data['method']} {attack_data['path']}")
    
    with open('/app/data/attack_logs.json', 'a') as f:
        f.write(json.dumps(attack_data) + '\n')
    
    return attack_data

def get_recent_attacks(n=20):
    try:
        with open('/app/data/attack_logs.json', 'r') as f:
            lines = f.readlines()
            recent = [json.loads(line) for line in lines[-n:]]
            return recent
    except:
        return []

# 🎯 API ROUTES - SPECIFIC FIRST
@app.route('/api/metrics')
def api_metrics():
    if RL_AVAILABLE and enhanced_honeypot and hasattr(enhanced_honeypot, 'ai_engine'):
        stats = enhanced_honeypot.ai_engine.get_attack_stats()
        return jsonify(stats)
    return jsonify({"total_attacks": 0, "threat_distribution": {"LOW": 0}})

@app.route('/api/live_attacks')
def api_live_attacks():
    attacks = get_recent_attacks(20)
    return jsonify(attacks)

# 🚨 HONEYPOT CATCH-ALL - EXCLUDE API PATHS
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
@app.route('/', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
def honeypot_catch_all(path=''):
    # 🛡️ BLOCK API PATHS EXPLICITLY
    if request.path.startswith('/api'):
        return jsonify({"error": "API endpoint - use specific routes"}), 404
    
    attack_data = log_attack(request)
    
    if RL_AVAILABLE and enhanced_honeypot:
        response = enhanced_honeypot.process_attack(attack_data)
        rl_analysis = response.get('rl_response', {})
        threat_level = rl_analysis.get('final_decision', 'LOW')
        
        print(f"🤖 RL Decision: {threat_level}")
        
        with open('/app/data/rl_decisions.json', 'a') as f:
            f.write(json.dumps({
                'timestamp': datetime.datetime.now().isoformat(),
                'attack_data': attack_data,
                'final_decision': threat_level,
            }) + '\n')
        
        delay = response.get('delay', 0)
        if delay > 0:
            print(f"⏳ Applying delay: {delay}s")
            time.sleep(delay)
        
        return Response(
            response.get('response_body', ''),
            status=response.get('status_code', 200),
            headers=response.get('headers', {})
        )
    return "RL Honeypot Active", 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    print("="*60)
    print("🚀 Cyber Honeycomb RL-Enhanced Proxy + FLUTTER API")
    print(f"📍 Port: {port}")
    print(f"📱 Flutter APIs: /api/metrics, /api/live_attacks")
    print(f"🤖 RL Available: {RL_AVAILABLE}")
    print("="*60)
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
