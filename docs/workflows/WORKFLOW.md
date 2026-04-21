# AI WAF Security Scanner - Workflow Analysis

## 📋 Project Overview

**ai_security** là một project kết hợp **Active Vulnerability Scanning** + **AI-based Web Application Firewall (WAF)** để phát hiện và chặn các cuộc tấn công vào web applications.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│           AI SECURITY SCANNER WORKFLOW                          │
└─────────────────────────────────────────────────────────────────┘

[PHASE 1: DATA & MODEL PREPARATION]
├─ WebPayloads Dataset (WEB_APPLICATION_PAYLOADS.jsonl)
│  └─ Chứa các payload tấn công thực tế (SQL Injection, XSS, CSRF, etc.)
├─ Deep Learning Model (deep_learning_agent_core.keras)
│  └─ Model TensorFlow được train trên dữ liệu payload
└─ Environment Setup
   ├─ TensorFlow/Keras
   ├─ scikit-learn
   ├─ numpy, pandas
   └─ Flask, Flask-CORS

[PHASE 2: ACTIVE ATTACKING MODULE (modul1_scanner.py)]
├─ Quét web target một cách chủ động
├─ Giả lập các cuộc tấn công (Injection, XSS, CSRF, etc.)
├─ Gửi malicious payloads đến target
├─ Phân tích response để phát hiện lỗ hổng
└─ Tạo báo cáo chi tiết (--report flag)

[PHASE 3: AI-WAF SHIELD MODULE (modul2_waf.py)]
├─ Flask API Server (Backend Protection)
├─ LRU Cache Layer (TTL = 5 phút, dung lượng = 1000 entry)
├─ Threat Detection System
│  ├─ AI Model (TensorFlow)
│  ├─ Threshold: 75% (confidence score)
│  └─ Token MAX_LEN: 150 (sequence padding)
├─ Request Validation & Blocking
├─ Advanced Logging System
│  ├─ stdout logging
│  └─ shield_protection.log file
└─ Performance Optimization
   ├─ Request Timeout: 10s
   ├─ Max Retries: 3
   └─ Payload Cache Hit/Miss tracking

[PHASE 4: FRONTEND INTERFACE (ai_waf_scanner.html)]
├─ Web Dashboard (HTML)
├─ Real-time Monitoring
├─ Vite Dev Server (port 5173)
└─ Connected to AI-WAF Shield via CORS
```

---

## 🔄 Main Workflow Loop

```
┌──────────────────────────────────────────────────────────────────┐
│                    EXECUTION FLOW                                │
└──────────────────────────────────────────────────────────────────┘

1. TARGET INITIALIZATION
   └─ Specify target URL: http://localhost:5173

2. ACTIVE SCANNING (Module 1)
   ├─ Extract forms từ web target
   ├─ Parse HTML structure
   ├─ Generate payloads từ database
   ├─ Send requests với malicious data
   └─ Collect responses

3. THREAT ANALYSIS
   ├─ Preprocess payload (tokenization, padding)
   ├─ Feed vào TensorFlow Model
   ├─ Get threat prediction score (0-100)
   └─ Compare vs Threshold (75%)

4. WAF PROTECTION (Module 2)
   ├─ Incoming Request
   ├─ Check Cache (LRU)
   │  ├─ Cache HIT: Return cached result
   │  └─ Cache MISS: Proceed to analysis
   ├─ AI Model Prediction
   ├─ Decision: ALLOW / BLOCK
   └─ Log result + cache score

5. REPORTING & MONITORING
   ├─ Generate scan report
   ├─ Log protection events
   ├─ Update dashboard
   └─ Track metrics (hits, misses, blocked requests)
```

---

## 📁 File Structure & Purpose

| File | Purpose |
|------|---------|
| `modul1_scanner.py` | Active vulnerability scanner - tấn công web target |
| `modul2_waf.py` | AI-WAF Shield - bảo vệ web application |
| `ai_waf_scanner.html` | Frontend dashboard for monitoring |
| `projectai.ipynb` | Jupyter notebook (training/experimentation) |
| `webtest.py` | utility script for web testing |
| `data/WEB_APPLICATION_PAYLOADS.jsonl` | Attack payload database |
| `model/deep_learning_agent_core.keras` | Trained TensorFlow model |
| `requirements.txt` | Python dependencies |

---

## 🚀 Usage

### 1. Start Active Scanner
```bash
python modul1_scanner.py --target http://localhost:5173
python modul1_scanner.py --target http://localhost:5173 --report
```

### 2. Run AI-WAF Shield
```bash
python modul2_waf.py
```
- Flask server starts at configurable port
- Protected URL: `http://localhost:5173`
- Incoming requests analyzed by AI model
- Results cached for performance

### 3. Access Dashboard
```
http://localhost:<PORT>/dashboard
```
- Real-time threat monitoring
- Request history
- Blocked attempts visualization

---

## 🧠 AI Model Details

| Config | Value |
|--------|-------|
| Framework | TensorFlow/Keras |
| Max Token Length | 150 |
| Threat Threshold | 75% |
| Cache TTL | 300 seconds (5 min) |
| Max Cache Size | 1000 entries |
| Request Timeout | 10 seconds |

**Model Input**: Tokenized payload (max 150 tokens)  
**Model Output**: Threat score (0-100)  
**Decision Rule**: score ≥ 75 → BLOCK, score < 75 → ALLOW

---

## 🔐 Attack Vectors Detected

Based on payload database:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Command Injection
- Path Traversal
- XXE (XML External Entity)
- LDAP Injection
- OS Command Injection
- Template Injection
- ... (see WEB_APPLICATION_PAYLOADS.jsonl)

---

## 📊 Performance & Caching

- **LRU Cache**: Memoization of previous analysis results
- **Cache Hit**: Returns result in ~1ms without re-analysis
- **Cache Miss**: Full AI model inference (~100-500ms)
- **TTL Expiry**: Old results auto-purged after 5 minutes
- **Retry Logic**: Max 3 retries for failed backend requests

---

## 📝 Logging

### Module 1 (Scanner)
- Scanner logs: `[SCANNER]` prefix
- Attack attempts: Request/Response pairs
- Findings: Detected vulnerabilities

### Module 2 (WAF)
- Protection logs: `[AI-WAF-SHIELD]` prefix
- File: `shield_protection.log`
- Blocked requests: Threat details + decision
- Cache stats: Hits/Misses tracking

---

## 🔧 Configuration

**Model Directory**: `./model/` (contains .keras file)

**WAF Configuration** (modul2_waf.py):
```python
MODEL_DIR = "/path/to/model"
MAX_LEN = 150
REAL_WEB_URL = "http://localhost:5173"
THRESHOLD = 75.0
CACHE_TTL = 300
MAX_CACHE_SIZE = 1000
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3
```

---

## 📦 Dependencies

```
flask
flask-cors
scikit-learn
pandas
numpy
tensorflow
requests
ipykernel
```

Install: `pip install -r requirements.txt`

---

## 🎯 Workflow Summary

1. **Data Preparation** → Payloads + AI Model ready
2. **Active Scanning** → Module 1 tests vulnerabilities
3. **Threat Analysis** → AI predicts threat level
4. **Protection** → Module 2 blocks malicious requests
5. **Monitoring** → Dashboard displays security status
6. **Logging** → Full audit trail maintained

**Goal**: Detect vulnerabilities while running, learn attack patterns, and automatically block them in real-time.
