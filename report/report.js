/* ===== AI SECURITY REPORT — Interactive Logic ===== */

document.addEventListener('DOMContentLoaded', () => {
  initScrollReveal();
  initArchDiagram();
  initDefenseLayers();
  initPayloadDemo();
  initBarAnimations();
  initMutationDemo();
  initCountUp();
});

/* ===== 1. Scroll Reveal ===== */
function initScrollReveal() {
  const sections = document.querySelectorAll('.section');
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.classList.add('visible');
      }
    });
  }, { threshold: 0.1 });
  sections.forEach(s => obs.observe(s));
}

/* ===== 2. Architecture Diagram — Click nodes to show detail ===== */
function initArchDiagram() {
  const nodes = document.querySelectorAll('.arch-node');
  const detailPanel = document.getElementById('node-detail');
  if (!detailPanel) return;

  const details = {
    'scanner': {
      title: '⚔️ Module 1 — AI Vulnerability Scanner',
      html: `
        <p><strong>Vai trò:</strong> Red Team — Hacker tự động quét lỗ hổng</p>
        <ul>
          <li>Kho payload: <strong>10 danh mục</strong> (SQLi, XSS, CMDi, SSTI, NoSQLi, XXE, SSRF, PathTraversal, CSRF, JWTAuth)</li>
          <li>Thuật toán: <strong>Greedy Hill Climbing</strong> — 15 vòng mutation tối đa</li>
          <li>Đa luồng: <strong>ThreadPoolExecutor (4 workers)</strong></li>
          <li>Engine: AI Bi-LSTM Oracle + Rule-Based Signatures</li>
        </ul>
        <div class="code-block" style="margin-top:12px">
          <span class="comment"># Quy trình tấn công</span><br>
          Payload gốc → Oracle Check (≥75%?) → Mutation Loop → Fire → Log
        </div>`
    },
    'waf': {
      title: '🛡️ Module 2 — AI WAF Shield',
      html: `
        <p><strong>Vai trò:</strong> Blue Team — Tường lửa AI đa tầng</p>
        <ul>
          <li><strong>L1:</strong> IP Blacklist — Auto-ban sau 5 lần bị detect/60s</li>
          <li><strong>L2:</strong> Rate Limiter — 100 req/min → 10 req/min khi bị flag</li>
          <li><strong>L2.5:</strong> Canonicalization — Recursive URL decode + HTML unescape</li>
          <li><strong>L3:</strong> Rule-Based Regex — 15 pattern, chặn signature rõ ràng</li>
          <li><strong>L4:</strong> AI Bi-LSTM — 97.43% accuracy, Dual-Threshold (90% Block / 75% Monitor)</li>
        </ul>
        <p style="margin-top:8px;color:var(--accent-green)"><strong>Server:</strong> Waitress WSGI (production-grade, multi-threaded)</p>`
    },
    'hacker': {
      title: '🧠 Module 3 — AI Hacker Brain (Qwen3-32B)',
      html: `
        <p><strong>Vai trò:</strong> Tấn công AI nâng cao bằng LLM</p>
        <ul>
          <li><strong>Context-Aware:</strong> Đọc HTML nguồn → suy luận endpoint ẩn → sinh payload phù hợp</li>
          <li><strong>Exploit Chaining:</strong> Xâu chuỗi nhiều lỗ hổng (VD: .env → API Key → Payment endpoint)</li>
          <li><strong>Black-box WAF Attack:</strong> Chỉ đọc HTTP status (200/403/429) để quyết định mutation</li>
          <li><strong>Surface Probes:</strong> Dò .env, .git/config, swagger.json, /actuator, /debug</li>
          <li><strong>Online Learning:</strong> Fine-tune Bi-LSTM từ False Positive data</li>
        </ul>`
    },
    'backend': {
      title: '🎯 Vulnerable Backend (webtest.py)',
      html: `
        <p><strong>Vai trò:</strong> Ứng dụng web mục tiêu chứa lỗ hổng</p>
        <ul>
          <li><strong>11 endpoints</strong> có lỗ hổng được cài sẵn</li>
          <li>SQLi: /search-user — Truy vấn SQL trực tiếp</li>
          <li>XSS: /feedback — Phản hồi unescaped</li>
          <li>CMDi: /ping — OS command execution</li>
          <li>SSTI: /ssti — Template injection ({{7*7}} → 49)</li>
          <li>NoSQLi: /nosqli — MongoDB operator injection</li>
          <li>PathTraversal: /view-doc — File traversal</li>
        </ul>
        <p style="margin-top:8px;color:var(--accent-red)"><strong>Điểm an toàn khi không có WAF: 18/100</strong></p>`
    },
    'dashboard': {
      title: '📊 Web Dashboard (Visualizer)',
      html: `
        <p><strong>Vai trò:</strong> Trực quan hóa toàn bộ hệ thống</p>
        <ul>
          <li>Điều khiển cả 3 module từ 1 giao diện</li>
          <li>So sánh chéo M1 vs M2 vs M3</li>
          <li>Real-time log polling</li>
          <li>Port: 8080</li>
        </ul>`
    }
  };

  nodes.forEach(node => {
    node.addEventListener('click', () => {
      const key = node.dataset.key;
      nodes.forEach(n => n.classList.remove('active'));
      node.classList.add('active');

      if (details[key]) {
        detailPanel.innerHTML = `<h4 style="margin-bottom:12px">${details[key].title}</h4>${details[key].html}`;
        detailPanel.classList.add('show');
      }

      // Animate SVG connectors
      document.querySelectorAll('.diagram-svg line, .diagram-svg path').forEach(l => {
        l.classList.remove('active-line');
      });
      const related = document.querySelectorAll(`.conn-${key}`);
      related.forEach(l => l.classList.add('active-line'));
    });
  });
}

/* ===== 3. Defense Layers — Click to expand ===== */
function initDefenseLayers() {
  const layers = document.querySelectorAll('.defense-layer');
  const infoBox = document.getElementById('layer-info');
  if (!infoBox) return;

  const info = {
    'l1': '<strong>L1: IP Blacklist</strong> — IP bị ban 10 phút sau 5 lần detect trong 60 giây. Chặn ngay từ cửa, không cần phân tích payload.',
    'l2': '<strong>L2: Rate Limiter</strong> — Giới hạn 100 req/min. Khi IP bị flag: giảm xuống 10 req/min. Vượt ngưỡng → HTTP 429.',
    'l25': '<strong>L2.5: Canonicalization</strong> — Recursive URL decode (tối đa 5 vòng) + HTML entity decode + Null byte strip. Triệt tiêu encoding tricks.',
    'l3': '<strong>L3: Rule-Based Regex</strong> — 15 pattern cứng cho SQLi, XSS, CMDi, SSRF, SSTI, NoSQLi, XXE, JWTAuth. Confidence 99.9%, chặn cứng.',
    'l4': '<strong>L4: AI Bi-LSTM Deep Scan</strong> — Mạng neural 97.43% accuracy. Dual-Threshold: ≥90% Block | 75-89% Monitor | <50% Allow.'
  };

  layers.forEach(layer => {
    layer.addEventListener('click', () => {
      layers.forEach(l => l.classList.remove('active'));
      layer.classList.add('active');
      const key = layer.dataset.layer;
      if (info[key]) {
        infoBox.innerHTML = info[key];
        infoBox.classList.add('show');
      }
    });
  });
}

/* ===== 4. Payload Flow Demo ===== */
function initPayloadDemo() {
  const btn = document.getElementById('btn-fire-payload');
  if (!btn) return;

  const scenarios = [
    {
      payload: "' OR '1'='1",
      label: 'SQLi',
      blockedAt: 'L3',
      steps: [
        { node: 'flow-l1', status: 'pass', text: '✓ IP OK' },
        { node: 'flow-l2', status: 'pass', text: '✓ Rate OK' },
        { node: 'flow-l25', status: 'pass', text: '✓ Decoded' },
        { node: 'flow-l3', status: 'block', text: '✗ Regex match!' },
      ]
    },
    {
      payload: "&lt;script&gt;alert(1)&lt;/script&gt;",
      label: 'XSS (encoded)',
      blockedAt: 'L3',
      steps: [
        { node: 'flow-l1', status: 'pass', text: '✓ IP OK' },
        { node: 'flow-l2', status: 'pass', text: '✓ Rate OK' },
        { node: 'flow-l25', status: 'decode', text: '→ <script>alert(1)' },
        { node: 'flow-l3', status: 'block', text: '✗ Regex match!' },
      ]
    },
    {
      payload: "{{7*7}}",
      label: 'SSTI',
      blockedAt: 'L4',
      steps: [
        { node: 'flow-l1', status: 'pass', text: '✓ IP OK' },
        { node: 'flow-l2', status: 'pass', text: '✓ Rate OK' },
        { node: 'flow-l25', status: 'pass', text: '✓ Clean' },
        { node: 'flow-l3', status: 'pass', text: '✓ No regex' },
        { node: 'flow-l4', status: 'block', text: '✗ AI: SSTI 98.3%' },
      ]
    }
  ];

  let idx = 0;
  const statusEl = document.getElementById('flow-status');
  const payloadEl = document.getElementById('flow-payload-text');

  btn.addEventListener('click', () => {
    const sc = scenarios[idx % scenarios.length];
    idx++;
    btn.disabled = true;

    if (payloadEl) payloadEl.textContent = sc.payload;
    if (statusEl) statusEl.textContent = '⏳ Đang xử lý...';

    // Reset all nodes
    document.querySelectorAll('.flow-node').forEach(n => {
      n.style.borderColor = 'var(--border)';
      n.querySelector('.flow-result')?.remove();
    });

    let delay = 0;
    sc.steps.forEach((step, i) => {
      delay += 600;
      setTimeout(() => {
        const node = document.getElementById(step.node);
        if (!node) return;

        if (step.status === 'pass' || step.status === 'decode') {
          node.style.borderColor = 'var(--accent-green)';
        } else if (step.status === 'block') {
          node.style.borderColor = 'var(--accent-red)';
          node.classList.add('scan-pulse');
        }

        const result = document.createElement('div');
        result.className = 'flow-result';
        result.style.cssText = 'font-size:11px;margin-top:6px;font-family:var(--font-mono);';
        result.style.color = step.status === 'block' ? 'var(--accent-red)' : 'var(--accent-green)';
        result.textContent = step.text;
        node.appendChild(result);

        if (i === sc.steps.length - 1) {
          setTimeout(() => {
            if (statusEl) {
              if (step.status === 'block') {
                statusEl.innerHTML = `🛡️ <strong style="color:var(--accent-blue)">BLOCKED</strong> tại ${sc.blockedAt} — Payload: <code>${sc.label}</code>`;
              } else {
                statusEl.innerHTML = `⚠️ <strong style="color:var(--accent-red)">PASSED</strong> — Vulnerability detected!`;
              }
            }
            btn.disabled = false;
            setTimeout(() => {
              document.querySelectorAll('.flow-node').forEach(n => n.classList.remove('scan-pulse'));
            }, 2000);
          }, 300);
        }
      }, delay);
    });
  });
}

/* ===== 5. Bar Chart Animation on Scroll ===== */
function initBarAnimations() {
  const bars = document.querySelectorAll('.bar-fill');
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        const target = e.target.dataset.width;
        e.target.style.width = target;
        obs.unobserve(e.target);
      }
    });
  }, { threshold: 0.3 });
  bars.forEach(b => {
    b.style.width = '0';
    obs.observe(b);
  });
}

/* ===== 6. Mutation Strategy Demo ===== */
function initMutationDemo() {
  const btns = document.querySelectorAll('.mutation-btn');
  const output = document.getElementById('mutation-output');
  if (!output || btns.length === 0) return;

  const mutations = {
    'original': {
      payload: "<script>alert('XSS')</script>",
      confidence: 100,
      result: 'BLOCKED (L3 Regex + AI 100%)'
    },
    'html_entity': {
      payload: "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;",
      confidence: 65.5,
      result: 'BLOCKED — Canonicalization decode → L3 Regex chặn lại'
    },
    'url_encode': {
      payload: "%3Cscript%3Ealert(%27XSS%27)%3C%2Fscript%3E",
      confidence: 84.8,
      result: 'BLOCKED — URL decode → <script> → L3 Regex match'
    },
    'case_swap': {
      payload: "<ScRiPt>alert('XSS')</sCrIpT>",
      confidence: 91.3,
      result: 'BLOCKED — Regex case-insensitive match'
    },
    'whitespace': {
      payload: "<script\t>alert(\t'XSS')\n</script\t>",
      confidence: 94.9,
      result: 'BLOCKED — AI vẫn nhận diện cấu trúc script'
    }
  };

  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      btns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const key = btn.dataset.mutation;
      const m = mutations[key];
      if (!m) return;

      const confColor = m.confidence > 90 ? 'var(--accent-red)' :
                         m.confidence > 75 ? 'var(--accent-orange)' :
                         m.confidence > 50 ? 'var(--accent-yellow)' : 'var(--accent-green)';

      output.innerHTML = `
        <div style="margin-bottom:12px">
          <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">Payload sau mutation</div>
          <div class="code-block">${escapeHtml(m.payload)}</div>
        </div>
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
          <span style="font-size:13px;color:var(--text-muted)">AI Confidence:</span>
          <div style="flex:1;height:8px;background:var(--bg-accent);border-radius:4px;overflow:hidden">
            <div style="width:${m.confidence}%;height:100%;background:${confColor};border-radius:4px;transition:width 0.6s"></div>
          </div>
          <span style="font-family:var(--font-mono);font-weight:700;color:${confColor}">${m.confidence}%</span>
        </div>
        <div style="font-size:13px;color:var(--accent-blue);font-weight:600">→ ${m.result}</div>
      `;
    });
  });
}

/* ===== 7. Count-Up Animation ===== */
function initCountUp() {
  const counters = document.querySelectorAll('[data-count]');
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        const target = parseFloat(e.target.dataset.count);
        const suffix = e.target.dataset.suffix || '';
        const duration = 1500;
        const start = performance.now();

        function update(now) {
          const elapsed = now - start;
          const progress = Math.min(elapsed / duration, 1);
          const eased = 1 - Math.pow(1 - progress, 3);
          const current = target * eased;

          if (Number.isInteger(target)) {
            e.target.textContent = Math.round(current) + suffix;
          } else {
            e.target.textContent = current.toFixed(2) + suffix;
          }

          if (progress < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
        obs.unobserve(e.target);
      }
    });
  }, { threshold: 0.5 });
  counters.forEach(c => obs.observe(c));
}

/* ===== Helpers ===== */
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
