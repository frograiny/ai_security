"""ai_waf_shield/dashboard.py

Built-in lightweight HTML dashboard.
"""
from flask import jsonify

HTML_DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
    <title>AI WAF Dashboard</title>
    <style>
        body { font-family: -apple-system, system-ui, sans-serif; background: #0f172a; color: #fff; margin: 0; padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card { background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }
        .value { font-size: 2em; font-weight: bold; color: #38bdf8; }
        .blocked { color: #f43f5e; }
        .title { color: #94a3b8; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }
        #logs { font-family: monospace; font-size: 0.9em; max-height: 300px; overflow-y: auto; background: #000; padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>🛡️ AI WAF Shield</h1>
    <div class="grid">
        <div class="card">
            <div class="title">Total Requests</div>
            <div class="value" id="req-count">0</div>
        </div>
        <div class="card">
            <div class="title">Threats Blocked</div>
            <div class="value blocked" id="block-count">0</div>
        </div>
        <div class="card">
            <div class="title">Block Rate</div>
            <div class="value" id="block-rate">0%</div>
        </div>
    </div>
    
    <h2>Attack Distribution</h2>
    <div class="card" id="attack-dist">No attacks yet</div>

    <script>
        function updateStats() {
            fetch('/ai-waf/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('req-count').innerText = data.traffic.total_requests;
                    document.getElementById('block-count').innerText = data.traffic.total_blocked;
                    document.getElementById('block-rate').innerText = data.traffic.block_rate;
                    
                    const dist = data.traffic.blocks_by_type;
                    if (Object.keys(dist).length > 0) {
                        let html = '<ul>';
                        for (let [type, count] of Object.entries(dist)) {
                            html += `<li><b>${type}:</b> ${count}</li>`;
                        }
                        html += '</ul>';
                        document.getElementById('attack-dist').innerHTML = html;
                    }
                });
        }
        setInterval(updateStats, 2000);
        updateStats();
    </script>
</body>
</html>
"""

def register_dashboard(app):
    @app.route(app.waf_stats_path if hasattr(app, 'waf_stats_path') else '/ai-waf/dashboard')
    def waf_dashboard():
        return HTML_DASHBOARD
        
    @app.route('/ai-waf/stats')
    def waf_stats():
        return jsonify(app.waf_stats)
