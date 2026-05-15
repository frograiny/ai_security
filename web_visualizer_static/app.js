// ===== AI Security Suite — Web Visualizer =====
const API = '';
let scannerPoll = null;
let wafPoll = null;
let hackerPoll = null;

// ===== SCANNER (M1) =====
async function startScanner() {
    const url = document.getElementById('scanner-url').value.trim();
    if (!url) { alert('Vui lòng nhập URL mục tiêu!'); return; }
    
    try {
        const res = await fetch(`${API}/api/scanner/start`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: url })
        });
        const data = await res.json();
        if (!res.ok) { alert(data.error); return; }
        
        document.getElementById('btn-scan').classList.add('hidden');
        document.getElementById('btn-scan-stop').classList.remove('hidden');
        document.getElementById('scanner-progress').classList.remove('hidden');
        document.getElementById('scan-target-display').textContent = url;
        document.getElementById('scanner-stats').classList.add('hidden');
        document.getElementById('vuln-section').classList.add('hidden');
        
        updateBadge('scanner', 'scanning');
        scannerPoll = setInterval(pollScanner, 2000);
    } catch(e) { alert('Lỗi kết nối: ' + e.message); }
}

async function stopScanner() {
    await fetch(`${API}/api/scanner/stop`, { method: 'POST' });
    clearInterval(scannerPoll);
    document.getElementById('btn-scan').classList.remove('hidden');
    document.getElementById('btn-scan-stop').classList.add('hidden');
    document.getElementById('scanner-progress').classList.add('hidden');
    updateBadge('scanner', 'idle');
}

async function pollScanner() {
    try {
        const res = await fetch(`${API}/api/scanner/status`);
        const data = await res.json();
        
        const logEl = document.getElementById('scanner-log');
        logEl.innerHTML = data.logs.map(l => `<div>${escapeHtml(l)}</div>`).join('');
        logEl.scrollTop = logEl.scrollHeight;
        
        if (data.status === 'done' || data.status === 'error') {
            clearInterval(scannerPoll);
            document.getElementById('btn-scan').classList.remove('hidden');
            document.getElementById('btn-scan-stop').classList.add('hidden');
            document.getElementById('scanner-progress').classList.add('hidden');
            
            if (data.status === 'done') {
                updateBadge('scanner', 'done');
                loadScanResults();
            } else {
                updateBadge('scanner', 'error');
            }
        }
    } catch(e) { console.error(e); }
}

async function loadScanResults() {
    try {
        const res = await fetch(`${API}/api/scanner/results`);
        const data = await res.json();
        
        const s = data.summary;
        if (s && s.total_endpoints !== undefined) {
            document.getElementById('stat-endpoints').textContent = s.total_endpoints || 0;
            document.getElementById('stat-payloads').textContent = s.total_payloads || 0;
            document.getElementById('stat-vulns').textContent = s.total_vulns || 0;
            document.getElementById('stat-duration').textContent = s.duration ? `${Math.round(s.duration)}s` : '—';
            document.getElementById('scanner-stats').classList.remove('hidden');
        }
        
        renderVulnerabilities(data.vulnerabilities || []);
        loadComparison();
    } catch(e) { console.error(e); }
}

function renderVulnerabilities(vulns) {
    if (!vulns.length) {
        document.getElementById('vuln-section').classList.add('hidden');
        return;
    }
    document.getElementById('vuln-section').classList.remove('hidden');
    
    const types = {};
    vulns.forEach(v => {
        const t = v.attack_type || 'Unknown';
        types[t] = (types[t] || 0) + 1;
    });
    
    const filtersEl = document.getElementById('vuln-filters');
    let filterHtml = `<button class="filter-btn active" onclick="filterVulns(this, 'all')">Tất cả <span class="count">(${vulns.length})</span></button>`;
    Object.entries(types).sort((a,b) => b[1] - a[1]).forEach(([type, count]) => {
        filterHtml += `<button class="filter-btn" onclick="filterVulns(this, '${type}')">${type} <span class="count">(${count})</span></button>`;
    });
    filtersEl.innerHTML = filterHtml;
    
    window._vulns = vulns;
    renderVulnCards(vulns, 'vuln-list', '');
}

function renderVulnCards(vulns, listId, extraClass) {
    const listEl = document.getElementById(listId);
    listEl.innerHTML = vulns.map(v => {
        const type = v.attack_type || 'Unknown';
        const badgeClass = getBadgeClass(type);
        const conf = v.ai_confidence ? `${v.ai_confidence.toFixed(1)}%` : (v.severity || '—');
        const payload = v.payload || '';
        const endpoint = v.endpoint || v.path || '';
        const param = v.param || '';
        const method = v.method || 'GET';
        const evidence = Array.isArray(v.evidence) ? v.evidence.join(', ') : (v.evidence || '');
        
        return `<div class="vuln-card ${extraClass}" onclick="this.classList.toggle('expanded')">
            <div class="vuln-card-header">
                <div class="vuln-type">
                    <span class="vuln-type-badge ${badgeClass}">${escapeHtml(type)}</span>
                    <span style="color:var(--text-tertiary);font-size:.68rem">${method}</span>
                </div>
                <span class="vuln-confidence">${conf}</span>
            </div>
            <div class="vuln-endpoint">${escapeHtml(endpoint)}${param ? '?' + escapeHtml(param) + '=...' : ''}</div>
            ${payload ? `<div class="vuln-payload">💉 ${escapeHtml(truncate(payload, 100))}</div>` : ''}
            ${evidence ? `<div class="vuln-evidence">📋 ${escapeHtml(truncate(evidence, 100))}</div>` : ''}
            <div class="vuln-details">
                <div style="font-size:.68rem;color:var(--text-secondary)">
                    <div><strong>Payload:</strong> ${escapeHtml(payload)}</div>
                    ${v.context ? `<div><strong>Context:</strong> ${escapeHtml(v.context)}</div>` : ''}
                    ${v.status_code ? `<div><strong>Status:</strong> ${v.status_code}</div>` : ''}
                </div>
            </div>
        </div>`;
    }).join('');
}

function filterVulns(btn, type) {
    document.querySelectorAll('#vuln-filters .filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    if (type === 'all') {
        renderVulnCards(window._vulns, 'vuln-list', '');
    } else {
        renderVulnCards(window._vulns.filter(v => v.attack_type === type), 'vuln-list', '');
    }
}

function getBadgeClass(type) {
    const t = (type || '').toLowerCase();
    if (t.includes('sql')) return 'sqli';
    if (t.includes('xss')) return 'xss';
    if (t.includes('cmd') || t.includes('command')) return 'cmdi';
    if (t.includes('path') || t.includes('traversal')) return 'path';
    if (t.includes('ssrf')) return 'ssrf';
    return 'other';
}

// ===== LOAD REPORT =====
async function loadReports() {
    try {
        const res = await fetch(`${API}/api/scanner/reports`);
        const reports = await res.json();
        const sel = document.getElementById('report-select');
        sel.innerHTML = '<option value="">-- Chọn --</option>';
        reports.forEach(r => {
            const opt = document.createElement('option');
            opt.value = r.file;
            opt.textContent = `${r.file} (${r.total_vulns} vulns)`;
            sel.appendChild(opt);
        });
    } catch(e) { console.error(e); }
}

async function loadReport() {
    const sel = document.getElementById('report-select');
    const file = sel.value;
    if (!file) return;
    
    try {
        const res = await fetch(`${API}/api/scanner/load/${file}`);
        const data = await res.json();
        if (data.status === 'loaded') {
            updateBadge('scanner', 'done');
            loadScanResults();
        }
    } catch(e) { alert('Lỗi tải báo cáo: ' + e.message); }
}

// ===== WAF (M2) =====
async function startWaf() {
    const url = document.getElementById('waf-url').value.trim();
    if (!url) { alert('Vui lòng nhập URL backend cần bảo vệ!'); return; }
    
    try {
        const res = await fetch(`${API}/api/waf/start`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: url })
        });
        const data = await res.json();
        if (!res.ok) { alert(data.error); return; }
        
        document.getElementById('btn-waf').classList.add('hidden');
        document.getElementById('btn-waf-stop').classList.remove('hidden');
        updateBadge('waf', 'running');
        wafPoll = setInterval(pollWaf, 2000);
    } catch(e) { alert('Lỗi kết nối: ' + e.message); }
}

async function stopWaf() {
    await fetch(`${API}/api/waf/stop`, { method: 'POST' });
    clearInterval(wafPoll);
    document.getElementById('btn-waf').classList.remove('hidden');
    document.getElementById('btn-waf-stop').classList.add('hidden');
    updateBadge('waf', 'idle');
}

async function pollWaf() {
    try {
        const res = await fetch(`${API}/api/waf/status`);
        const data = await res.json();
        
        updateWafStats(data.stats);
        renderWafLogs(data.logs || []);
        
        if (data.status !== 'running') {
            clearInterval(wafPoll);
            document.getElementById('btn-waf').classList.remove('hidden');
            document.getElementById('btn-waf-stop').classList.add('hidden');
            updateBadge('waf', 'idle');
        }
    } catch(e) { console.error(e); }
}

async function loadWafLog() {
    try {
        const res = await fetch(`${API}/api/waf/load-log`);
        const data = await res.json();
        if (data.error) { alert(data.error); return; }
        
        updateWafStats(data.stats);
        updateBadge('waf', 'loaded');
        
        const statusRes = await fetch(`${API}/api/waf/status`);
        const statusData = await statusRes.json();
        renderWafLogs(statusData.logs || []);
        loadComparison();
    } catch(e) { alert('Lỗi: ' + e.message); }
}

function updateWafStats(stats) {
    document.getElementById('waf-total-req').textContent = stats.total_requests || 0;
    document.getElementById('waf-allowed').textContent = stats.total_allowed || 0;
    document.getElementById('waf-blocked').textContent = stats.total_blocked || 0;
    document.getElementById('waf-block-rate').textContent = stats.block_rate || '0%';
}

function renderWafLogs(logs) {
    const logEl = document.getElementById('waf-log');
    const wasAtBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 50;
    
    logEl.innerHTML = logs.map(entry => {
        const type = entry.type || 'info';
        const ts = entry.timestamp ? entry.timestamp.split(' ')[1] || '' : '';
        const shortTs = ts.split(',')[0] || '';
        let icon = '📋';
        if (type === 'normal') icon = '✅';
        else if (type === 'blocked') icon = '🚫';
        else if (type === 'rate_limited') icon = '⏱️';
        else if (type === 'blacklisted') icon = '⛔';
        else if (type === 'suspicious') icon = '⚠️';
        
        let msg = entry.message || '';
        if (msg.length > 180) msg = msg.substring(0, 180) + '...';
        
        return `<div class="waf-log-entry log-${type}">
            <span class="log-time">${shortTs}</span>
            <span class="log-status">${icon}</span>
            <span class="log-msg">${escapeHtml(msg)}</span>
        </div>`;
    }).join('');
    
    if (wasAtBottom) logEl.scrollTop = logEl.scrollHeight;
}

// ===== HACKER BRAIN (M3) =====
async function startHacker() {
    const url = document.getElementById('hacker-url').value.trim();
    if (!url) { alert('Vui lòng nhập URL mục tiêu!'); return; }
    
    try {
        const res = await fetch(`${API}/api/hacker/start`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: url })
        });
        const data = await res.json();
        if (!res.ok) { alert(data.error); return; }
        
        document.getElementById('btn-hacker').classList.add('hidden');
        document.getElementById('btn-hacker-stop').classList.remove('hidden');
        document.getElementById('hacker-progress').classList.remove('hidden');
        document.getElementById('hacker-target-display').textContent = url;
        document.getElementById('hacker-stats').classList.add('hidden');
        document.getElementById('hacker-vuln-section').classList.add('hidden');
        
        updateBadge('hacker', 'attacking');
        hackerPoll = setInterval(pollHacker, 3000);
    } catch(e) { alert('Lỗi kết nối: ' + e.message); }
}

async function stopHacker() {
    await fetch(`${API}/api/hacker/stop`, { method: 'POST' });
    clearInterval(hackerPoll);
    document.getElementById('btn-hacker').classList.remove('hidden');
    document.getElementById('btn-hacker-stop').classList.add('hidden');
    document.getElementById('hacker-progress').classList.add('hidden');
    updateBadge('hacker', 'idle');
}

async function pollHacker() {
    try {
        const res = await fetch(`${API}/api/hacker/status`);
        const data = await res.json();
        
        const logEl = document.getElementById('hacker-log');
        logEl.innerHTML = data.logs.map(l => `<div>${escapeHtml(l)}</div>`).join('');
        logEl.scrollTop = logEl.scrollHeight;
        
        if (data.status === 'done' || data.status === 'error') {
            clearInterval(hackerPoll);
            document.getElementById('btn-hacker').classList.remove('hidden');
            document.getElementById('btn-hacker-stop').classList.add('hidden');
            document.getElementById('hacker-progress').classList.add('hidden');
            
            if (data.status === 'done') {
                updateBadge('hacker', 'done');
                loadHackerResults();
            } else {
                updateBadge('hacker', 'error');
            }
        }
    } catch(e) { console.error(e); }
}

async function loadHackerResults() {
    try {
        const res = await fetch(`${API}/api/hacker/results`);
        const data = await res.json();
        
        const s = data.summary;
        if (s) {
            document.getElementById('hacker-endpoints').textContent = s.total_endpoints || 0;
            document.getElementById('hacker-payloads').textContent = s.total_payloads || 0;
            document.getElementById('hacker-vulns').textContent = s.total_vulns || 0;
            document.getElementById('hacker-chains').textContent = `${s.chain_success || 0}/${s.chain_attempts || 0}`;
            document.getElementById('hacker-stats').classList.remove('hidden');
        }
        
        const vulns = data.vulnerabilities || [];
        if (vulns.length > 0) {
            document.getElementById('hacker-vuln-section').classList.remove('hidden');
            renderVulnCards(vulns, 'hacker-vuln-list', 'hacker-card');
        } else {
            document.getElementById('hacker-vuln-section').classList.add('hidden');
        }
        
        loadComparison();
    } catch(e) { console.error(e); }
}

async function loadHackerReports() {
    try {
        const res = await fetch(`${API}/api/hacker/reports`);
        const reports = await res.json();
        const sel = document.getElementById('hacker-report-select');
        sel.innerHTML = '<option value="">-- Chọn --</option>';
        reports.forEach(r => {
            const opt = document.createElement('option');
            opt.value = r.file;
            opt.textContent = `${r.file} (${r.total_vulns} vulns)`;
            sel.appendChild(opt);
        });
    } catch(e) { console.error(e); }
}

async function loadHackerReport() {
    const sel = document.getElementById('hacker-report-select');
    const file = sel.value;
    if (!file) return;
    
    try {
        const res = await fetch(`${API}/api/hacker/load/${file}`);
        const data = await res.json();
        if (data.status === 'loaded') {
            updateBadge('hacker', 'done');
            loadHackerResults();
        }
    } catch(e) { alert('Lỗi tải báo cáo: ' + e.message); }
}

// ===== COMPARISON =====
async function loadComparison() {
    try {
        const res = await fetch(`${API}/api/comparison`);
        const data = await res.json();
        
        // M1
        const m1 = data.m1;
        document.getElementById('cmp-m1-status').textContent = m1.status === 'done' ? '✅ Hoàn tất' : m1.status;
        document.getElementById('cmp-m1-vulns').textContent = m1.total_vulns;
        document.getElementById('cmp-m1-payloads').textContent = m1.total_payloads;
        document.getElementById('cmp-m1-endpoints').textContent = m1.total_endpoints;
        document.getElementById('cmp-m1-duration').textContent = m1.duration ? `${Math.round(m1.duration)}s` : '—';
        
        // M2
        const m2 = data.m2;
        document.getElementById('cmp-m2-status').textContent = (m2.status === 'loaded' || m2.status === 'running') ? '✅ Active' : m2.status;
        document.getElementById('cmp-m2-total').textContent = m2.total_requests;
        document.getElementById('cmp-m2-blocked').textContent = m2.total_blocked;
        document.getElementById('cmp-m2-allowed').textContent = m2.total_allowed;
        document.getElementById('cmp-m2-rate').textContent = m2.block_rate;
        
        // M3
        const m3 = data.m3;
        document.getElementById('cmp-m3-status').textContent = m3.status === 'done' ? '✅ Hoàn tất' : m3.status;
        document.getElementById('cmp-m3-vulns').textContent = m3.total_vulns;
        document.getElementById('cmp-m3-payloads').textContent = m3.total_payloads;
        document.getElementById('cmp-m3-chains').textContent = `${m3.chain_success}/${m3.chain_attempts}`;
        document.getElementById('cmp-m3-duration').textContent = m3.duration ? `${Math.round(m3.duration)}s` : '—';
        
        // Matrix
        const cmp = data.comparison;
        const tbody = document.getElementById('matrix-tbody');
        
        if (cmp.all_attack_types.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="matrix-empty">Tải dữ liệu M1/M3 để so sánh</td></tr>';
            return;
        }
        
        tbody.innerHTML = cmp.all_attack_types.map(type => {
            const m1Count = (m1.vuln_types[type] || 0);
            const m3Count = (m3.vuln_types[type] || 0);
            const m1Cell = m1Count > 0 ? `<span class="matrix-found">${m1Count} found</span>` : `<span class="matrix-not-found">—</span>`;
            const m3Cell = m3Count > 0 ? `<span class="matrix-found">${m3Count} found</span>` : `<span class="matrix-not-found">—</span>`;
            
            let evalHtml;
            if (m1Count > 0 && m3Count > 0) {
                evalHtml = `<span class="matrix-eval both">Cả 2 phát hiện</span>`;
            } else if (m1Count > 0) {
                evalHtml = `<span class="matrix-eval m1-only">Chỉ M1</span>`;
            } else {
                evalHtml = `<span class="matrix-eval m3-only">Chỉ M3</span>`;
            }
            
            return `<tr><td><strong>${escapeHtml(type)}</strong></td><td>${m1Cell}</td><td>${m3Cell}</td><td>${evalHtml}</td></tr>`;
        }).join('');
        
    } catch(e) { console.error(e); }
}

// ===== HELPERS =====
function updateBadge(module, status) {
    const badgeId = module === 'scanner' ? 'badge-scanner' : module === 'waf' ? 'badge-waf' : 'badge-hacker';
    const badge = document.getElementById(badgeId);
    badge.className = 'badge';
    
    const prefix = module === 'scanner' ? 'M1' : module === 'waf' ? 'M2' : 'M3';
    
    const labels = {
        idle: `${prefix}: Idle`,
        scanning: `${prefix}: Đang quét...`,
        running: `${prefix}: Đang bảo vệ`,
        attacking: `${prefix}: Đang tấn công...`,
        done: `${prefix}: Hoàn tất ✓`,
        loaded: `${prefix}: Loaded ✓`,
        error: `${prefix}: Lỗi ✗`,
    };
    
    badge.innerHTML = `<span class="badge-dot"></span>${labels[status] || status}`;
    
    if (status === 'scanning' || status === 'running') badge.classList.add('active');
    else if (status === 'attacking') badge.classList.add('hacker-active');
    else if (status === 'done' || status === 'loaded') badge.classList.add('done');
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
    loadReports();
    loadHackerReports();
    loadComparison();
});
