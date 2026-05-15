"""
WEB VISUALIZER — AI Security Suite Dashboard
=============================================
Giao diện trực quan hóa cho:
  - Module 1 (AI Vulnerability Scanner): nhập URL → quét → hiển thị lỗ hổng
  - Module 2 (AI WAF Shield): nhập URL → bảo vệ → hiển thị log truy cập
  - Module 3 (AI Hacker Brain): nhập URL → tấn công AI → hiển thị kết quả
  - So sánh: đánh giá chéo kết quả M1 vs M2 vs M3

Chạy:
    python web_visualizer.py
    → Truy cập http://localhost:8080
"""

from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
import subprocess
import sys
import os
import json
import threading
import time
import re
import glob
from datetime import datetime
from collections import deque

app = Flask(__name__, static_folder='web_visualizer_static')
CORS(app)

# ===== STATE =====
scanner_state = {
    'status': 'idle',       # idle | scanning | done | error
    'target': '',
    'progress': '',
    'vulnerabilities': [],
    'summary': {},
    'report_file': '',
    'logs': deque(maxlen=500),
    'process': None,
}

waf_state = {
    'status': 'idle',       # idle | running | error
    'target': '',
    'logs': deque(maxlen=1000),
    'process': None,
    'webtest_process': None,
    'stats': {
        'total_requests': 0,
        'total_blocked': 0,
        'total_allowed': 0,
        'block_rate': '0%',
    },
}

hacker_state = {
    'status': 'idle',       # idle | attacking | done | error
    'target': '',
    'vulnerabilities': [],
    'summary': {},
    'report_file': '',
    'logs': deque(maxlen=500),
    'process': None,
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ===== HELPERS =====
def parse_waf_log_line(line):
    """Parse a single WAF log line into structured data."""
    clean = re.sub(r'\x1b\[[0-9;]*m', '', line)  # strip ANSI colors
    
    entry = {
        'timestamp': '',
        'type': 'info',   # normal | blocked | suspicious | rate_limited | blacklisted
        'message': clean.strip(),
        'details': {},
    }
    
    # Extract timestamp
    ts_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)', clean)
    if ts_match:
        entry['timestamp'] = ts_match.group(1)
    
    # Classify
    if '[RULE-BLOCKED]' in clean or '[AI-BLOCKED]' in clean:
        entry['type'] = 'blocked'
        m = re.search(r'\[(?:RULE|AI)-BLOCKED\]\s+(\S+)\s+\|\s+([\d.]+%)', clean)
        if m:
            entry['details'] = {'attack_type': m.group(1), 'confidence': m.group(2)}
    elif '[BLACKLISTED]' in clean:
        entry['type'] = 'blacklisted'
    elif '[RATE LIMITED]' in clean:
        entry['type'] = 'rate_limited'
    elif '[SUSPICIOUS]' in clean:
        entry['type'] = 'suspicious'
        m = re.search(r'\[SUSPICIOUS\]\s+(\S+)\s+\(([\d.]+%)\)', clean)
        if m:
            entry['details'] = {'attack_type': m.group(1), 'confidence': m.group(2)}
    elif 'Status=200' in clean or ('GET' in clean and '200' in clean):
        entry['type'] = 'normal'
    elif '403' in clean or '429' in clean:
        entry['type'] = 'blocked'
    
    return entry


def run_scanner_process(target_url):
    """Run M1 scanner as subprocess and capture output."""
    global scanner_state
    scanner_state['status'] = 'scanning'
    scanner_state['target'] = target_url
    scanner_state['vulnerabilities'] = []
    scanner_state['summary'] = {}
    scanner_state['logs'].clear()
    
    try:
        cmd = [sys.executable, '-u', 'modul1_scanner.py', '--target', target_url, '--report']
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=BASE_DIR,
        )
        scanner_state['process'] = proc
        
        for line in proc.stdout:
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
            if clean:
                scanner_state['logs'].append(clean)
            
            # Auto-answer prompts
            if 'Bạn có muốn quét lại' in line or 'muốn quét' in line:
                try:
                    proc.stdin.write('n\n')
                    proc.stdin.flush()
                except:
                    pass
        
        proc.wait()
        
        # Find latest report
        reports = sorted(glob.glob(os.path.join(BASE_DIR, 'scan_report_*.json')))
        if reports:
            latest = reports[-1]
            scanner_state['report_file'] = latest
            with open(latest, 'r', encoding='utf-8') as f:
                data = json.load(f)
            scanner_state['vulnerabilities'] = data.get('vulnerabilities', [])
            scanner_state['summary'] = {
                'target': data.get('target', target_url),
                'scan_time': data.get('scan_time', ''),
                'duration': data.get('duration_seconds', 0),
                'total_endpoints': data.get('total_endpoints', 0),
                'total_payloads': data.get('total_payloads_sent', 0),
                'total_vulns': data.get('total_vulnerabilities', 0),
                'adversarial': data.get('adversarial_analysis', {}),
            }
        
        scanner_state['status'] = 'done'
        
    except Exception as e:
        scanner_state['status'] = 'error'
        scanner_state['logs'].append(f'ERROR: {str(e)}')


def run_waf_process(target_url):
    """Run M2 WAF as subprocess and stream logs."""
    global waf_state
    waf_state['status'] = 'running'
    waf_state['target'] = target_url
    waf_state['logs'].clear()
    waf_state['stats'] = {
        'total_requests': 0,
        'total_blocked': 0,
        'total_allowed': 0,
        'block_rate': '0%',
    }
    
    try:
        cmd = [sys.executable, '-u', 'modul2_waf.py', '--target', target_url]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            cwd=BASE_DIR,
        )
        waf_state['process'] = proc
        
        for line in proc.stdout:
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
            if not clean:
                continue
            
            entry = parse_waf_log_line(line)
            waf_state['logs'].append(entry)
            
            # Update stats
            if entry['type'] in ('blocked', 'blacklisted', 'rate_limited'):
                waf_state['stats']['total_blocked'] += 1
                waf_state['stats']['total_requests'] += 1
            elif entry['type'] == 'normal':
                waf_state['stats']['total_allowed'] += 1
                waf_state['stats']['total_requests'] += 1
            elif entry['type'] == 'suspicious':
                waf_state['stats']['total_allowed'] += 1
                waf_state['stats']['total_requests'] += 1
            
            total = waf_state['stats']['total_requests']
            blocked = waf_state['stats']['total_blocked']
            waf_state['stats']['block_rate'] = f"{(blocked/total*100):.1f}%" if total > 0 else "0%"
        
        proc.wait()
        waf_state['status'] = 'idle'
        
    except Exception as e:
        waf_state['status'] = 'error'
        waf_state['logs'].append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'blocked',
            'message': f'ERROR: {str(e)}',
            'details': {},
        })


def run_hacker_process(target_url):
    """Run M3 hacker brain as subprocess and capture output."""
    global hacker_state
    hacker_state['status'] = 'attacking'
    hacker_state['target'] = target_url
    hacker_state['vulnerabilities'] = []
    hacker_state['summary'] = {}
    hacker_state['logs'].clear()
    
    try:
        cmd = [sys.executable, '-u', 'modul3.py', 'audit', target_url]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=BASE_DIR,
        )
        hacker_state['process'] = proc
        
        for line in proc.stdout:
            clean = re.sub(r'\\x1b\\[[0-9;]*m', '', line).strip()
            if clean:
                hacker_state['logs'].append(clean)
        
        proc.wait()
        
        # Find latest M3 report
        reports = sorted(glob.glob(os.path.join(BASE_DIR, 'scan_report_m3_*.json')))
        if reports:
            latest = reports[-1]
            hacker_state['report_file'] = latest
            with open(latest, 'r', encoding='utf-8') as f:
                data = json.load(f)
            hacker_state['vulnerabilities'] = data.get('findings', [])
            hacker_state['summary'] = {
                'target': data.get('target', target_url),
                'scan_time': data.get('scan_time_seconds', 0),
                'total_endpoints': data.get('endpoints_found', 0),
                'total_payloads': data.get('payloads_sent', 0),
                'total_vulns': data.get('vulnerabilities_found', 0),
                'chain_attempts': data.get('chain_attempts', 0),
                'chain_success': data.get('chain_success', 0),
            }
        
        hacker_state['status'] = 'done'
        
    except Exception as e:
        hacker_state['status'] = 'error'
        hacker_state['logs'].append(f'ERROR: {str(e)}')


# ===== API ROUTES =====
@app.route('/')
def index():
    return send_from_directory('web_visualizer_static', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('web_visualizer_static', path)


# --- Scanner API ---
@app.route('/api/scanner/start', methods=['POST'])
def scanner_start():
    data = request.get_json()
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    if not target.startswith('http'):
        target = 'http://' + target
    
    if scanner_state['status'] == 'scanning':
        return jsonify({'error': 'Scanner already running'}), 409
    
    t = threading.Thread(target=run_scanner_process, args=(target,), daemon=True)
    t.start()
    return jsonify({'status': 'started', 'target': target})


@app.route('/api/scanner/status')
def scanner_status():
    return jsonify({
        'status': scanner_state['status'],
        'target': scanner_state['target'],
        'logs': list(scanner_state['logs'])[-30:],
        'summary': scanner_state['summary'],
        'vuln_count': len(scanner_state['vulnerabilities']),
    })


@app.route('/api/scanner/results')
def scanner_results():
    # De-duplicate vulnerabilities
    seen = set()
    unique_vulns = []
    for v in scanner_state['vulnerabilities']:
        key = f"{v.get('endpoint','')}|{v.get('attack_type','')}|{v.get('payload','')}"
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    
    return jsonify({
        'vulnerabilities': unique_vulns,
        'summary': scanner_state['summary'],
    })


@app.route('/api/scanner/stop', methods=['POST'])
def scanner_stop():
    if scanner_state['process']:
        try:
            scanner_state['process'].terminate()
        except:
            pass
    scanner_state['status'] = 'idle'
    return jsonify({'status': 'stopped'})


# --- Load existing scan reports ---
@app.route('/api/scanner/reports')
def scanner_reports():
    reports = sorted(glob.glob(os.path.join(BASE_DIR, 'scan_report_*.json')), reverse=True)
    result = []
    for r in reports[:10]:
        try:
            with open(r, 'r', encoding='utf-8') as f:
                data = json.load(f)
            result.append({
                'file': os.path.basename(r),
                'target': data.get('target', ''),
                'scan_time': data.get('scan_time', ''),
                'total_vulns': data.get('total_vulnerabilities', 0),
            })
        except:
            pass
    return jsonify(result)


@app.route('/api/scanner/load/<filename>')
def scanner_load_report(filename):
    filepath = os.path.join(BASE_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'Report not found'}), 404
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    scanner_state['vulnerabilities'] = data.get('vulnerabilities', [])
    scanner_state['summary'] = {
        'target': data.get('target', ''),
        'scan_time': data.get('scan_time', ''),
        'duration': data.get('duration_seconds', 0),
        'total_endpoints': data.get('total_endpoints', 0),
        'total_payloads': data.get('total_payloads_sent', 0),
        'total_vulns': data.get('total_vulnerabilities', 0),
        'adversarial': data.get('adversarial_analysis', {}),
    }
    scanner_state['status'] = 'done'
    return jsonify({'status': 'loaded', 'total_vulns': data.get('total_vulnerabilities', 0)})


# --- WAF API ---
@app.route('/api/waf/start', methods=['POST'])
def waf_start():
    data = request.get_json()
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    if not target.startswith('http'):
        target = 'http://' + target
    
    if waf_state['status'] == 'running':
        return jsonify({'error': 'WAF already running'}), 409
    
    t = threading.Thread(target=run_waf_process, args=(target,), daemon=True)
    t.start()
    return jsonify({'status': 'started', 'target': target})


@app.route('/api/waf/status')
def waf_status():
    recent_logs = list(waf_state['logs'])[-50:]
    return jsonify({
        'status': waf_state['status'],
        'target': waf_state['target'],
        'stats': waf_state['stats'],
        'logs': recent_logs,
    })


@app.route('/api/waf/stop', methods=['POST'])
def waf_stop():
    if waf_state['process']:
        try:
            waf_state['process'].terminate()
        except:
            pass
    waf_state['status'] = 'idle'
    return jsonify({'status': 'stopped'})


# --- Load existing WAF log file ---
@app.route('/api/waf/load-log')
def waf_load_log():
    log_path = os.path.join(BASE_DIR, 'shield_protection.log')
    if not os.path.exists(log_path):
        return jsonify({'error': 'No log file found'}), 404
    
    entries = []
    stats = {'total_requests': 0, 'total_blocked': 0, 'total_allowed': 0, 'block_rate': '0%'}
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            entry = parse_waf_log_line(line)
            if entry['type'] in ('blocked', 'blacklisted', 'rate_limited'):
                stats['total_blocked'] += 1
                stats['total_requests'] += 1
                entries.append(entry)
            elif entry['type'] == 'normal':
                stats['total_allowed'] += 1
                stats['total_requests'] += 1
                entries.append(entry)
            elif entry['type'] == 'suspicious':
                stats['total_allowed'] += 1
                stats['total_requests'] += 1
                entries.append(entry)
    
    total = stats['total_requests']
    blocked = stats['total_blocked']
    stats['block_rate'] = f"{(blocked/total*100):.1f}%" if total > 0 else "0%"
    
    # Keep last 200 entries
    waf_state['logs'] = deque(entries[-200:], maxlen=1000)
    waf_state['stats'] = stats
    waf_state['status'] = 'loaded'
    
    return jsonify({'status': 'loaded', 'stats': stats, 'log_count': len(entries)})


# --- Hacker Brain (M3) API ---
@app.route('/api/hacker/start', methods=['POST'])
def hacker_start():
    data = request.get_json()
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    if not target.startswith('http'):
        target = 'http://' + target
    
    if hacker_state['status'] == 'attacking':
        return jsonify({'error': 'Hacker Brain already running'}), 409
    
    t = threading.Thread(target=run_hacker_process, args=(target,), daemon=True)
    t.start()
    return jsonify({'status': 'started', 'target': target})


@app.route('/api/hacker/status')
def hacker_status():
    return jsonify({
        'status': hacker_state['status'],
        'target': hacker_state['target'],
        'logs': list(hacker_state['logs'])[-30:],
        'summary': hacker_state['summary'],
        'vuln_count': len(hacker_state['vulnerabilities']),
    })


@app.route('/api/hacker/results')
def hacker_results():
    return jsonify({
        'vulnerabilities': hacker_state['vulnerabilities'],
        'summary': hacker_state['summary'],
    })


@app.route('/api/hacker/stop', methods=['POST'])
def hacker_stop():
    if hacker_state['process']:
        try:
            hacker_state['process'].terminate()
        except:
            pass
    hacker_state['status'] = 'idle'
    return jsonify({'status': 'stopped'})


@app.route('/api/hacker/reports')
def hacker_reports():
    reports = sorted(glob.glob(os.path.join(BASE_DIR, 'scan_report_m3_*.json')), reverse=True)
    result = []
    for r in reports[:10]:
        try:
            with open(r, 'r', encoding='utf-8') as f:
                data = json.load(f)
            result.append({
                'file': os.path.basename(r),
                'target': data.get('target', ''),
                'total_vulns': data.get('vulnerabilities_found', 0),
            })
        except:
            pass
    return jsonify(result)


@app.route('/api/hacker/load/<filename>')
def hacker_load_report(filename):
    filepath = os.path.join(BASE_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'Report not found'}), 404
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    hacker_state['vulnerabilities'] = data.get('findings', [])
    hacker_state['summary'] = {
        'target': data.get('target', ''),
        'scan_time': data.get('scan_time_seconds', 0),
        'total_endpoints': data.get('endpoints_found', 0),
        'total_payloads': data.get('payloads_sent', 0),
        'total_vulns': data.get('vulnerabilities_found', 0),
        'chain_attempts': data.get('chain_attempts', 0),
        'chain_success': data.get('chain_success', 0),
    }
    hacker_state['status'] = 'done'
    return jsonify({'status': 'loaded', 'total_vulns': data.get('vulnerabilities_found', 0)})


# --- Comparison API ---
@app.route('/api/comparison')
def comparison_data():
    """Aggregate M1, M2, M3 data for cross-module comparison."""
    m1_vulns = scanner_state.get('vulnerabilities', [])
    m3_vulns = hacker_state.get('vulnerabilities', [])
    m2_stats = waf_state.get('stats', {})
    
    # Count vuln types for M1
    m1_types = {}
    for v in m1_vulns:
        t = v.get('attack_type', 'Unknown')
        m1_types[t] = m1_types.get(t, 0) + 1
    
    # Count vuln types for M3
    m3_types = {}
    for v in m3_vulns:
        t = v.get('attack_type', 'Unknown')
        if t.startswith('\u26d3 '): t = t[2:]  # strip chain prefix
        m3_types[t] = m3_types.get(t, 0) + 1
    
    # All unique types
    all_types = sorted(set(list(m1_types.keys()) + list(m3_types.keys())))
    
    return jsonify({
        'm1': {
            'status': scanner_state['status'],
            'target': scanner_state.get('target', ''),
            'total_vulns': len(m1_vulns),
            'total_payloads': scanner_state.get('summary', {}).get('total_payloads', 0),
            'total_endpoints': scanner_state.get('summary', {}).get('total_endpoints', 0),
            'duration': scanner_state.get('summary', {}).get('duration', 0),
            'vuln_types': m1_types,
            'approach': 'Rule-based + AI Confidence (White-box)',
        },
        'm2': {
            'status': waf_state['status'],
            'total_requests': m2_stats.get('total_requests', 0),
            'total_blocked': m2_stats.get('total_blocked', 0),
            'total_allowed': m2_stats.get('total_allowed', 0),
            'block_rate': m2_stats.get('block_rate', '0%'),
            'approach': 'Bi-LSTM + Rule Engine (Defense)',
        },
        'm3': {
            'status': hacker_state['status'],
            'target': hacker_state.get('target', ''),
            'total_vulns': len(m3_vulns),
            'total_payloads': hacker_state.get('summary', {}).get('total_payloads', 0),
            'total_endpoints': hacker_state.get('summary', {}).get('total_endpoints', 0),
            'duration': hacker_state.get('summary', {}).get('scan_time', 0),
            'chain_attempts': hacker_state.get('summary', {}).get('chain_attempts', 0),
            'chain_success': hacker_state.get('summary', {}).get('chain_success', 0),
            'vuln_types': m3_types,
            'approach': 'LLM-Generated Payloads (Black-box)',
        },
        'comparison': {
            'all_attack_types': all_types,
            'm1_only': [t for t in m1_types if t not in m3_types],
            'm3_only': [t for t in m3_types if t not in m1_types],
            'both': [t for t in all_types if t in m1_types and t in m3_types],
        },
    })


# ===== STARTUP =====
if __name__ == '__main__':
    print("=" * 60)
    print("[*] AI SECURITY SUITE -- Web Visualizer")
    print("=" * 60)
    print("[*] Dashboard : http://localhost:8080")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
