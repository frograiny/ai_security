---
tags: [architecture, diagram]
aliases: [Kiến trúc, Architecture]
---

# 🏗️ Kiến Trúc Hệ Thống

> Hệ thống được thiết kế theo mô hình **modular** với 5 tầng rõ ràng, cho phép từng thành phần chạy độc lập hoặc phối hợp.

---

## Sơ đồ Kiến trúc Tổng thể

```mermaid
graph TD
    User((User / Attacker)) --> WAF["🛡️ AI WAF Shield<br/>Port 5000"]
    
    subgraph "Blue Team — Phòng thủ"
        WAF --> L1["L1: IP Blacklist"]
        L1 --> L2["L2: Rate Limiter"]
        L2 --> L25["L2.5: Canonicalization"]
        L25 --> L3["L3: Rule-based Regex"]
        L3 --> L4["L4: Bi-LSTM Deep Scan"]
    end
    
    L4 --> Backend["🎯 Vulnerable Backend<br/>Port 5170"]
    
    subgraph "Red Team — Tấn công"
        Scanner["🗡️ AI Scanner<br/>Module 1"] --> Mutation["Adversarial Mutator<br/>Greedy Hill Climbing"]
        Mutation --> WAF
        HackerBrain["🧠 Hacker Brain<br/>Groq / Qwen3"] --> Scanner
    end
    
    subgraph "Learning Loop"
        Backend --> FP["📝 False Positive Report"]
        FP --> Retrain["🔄 Online Retraining"]
        Retrain --> L4
    end
    
    style WAF fill:#48bb78,stroke:#333,color:#fff
    style Scanner fill:#f56565,stroke:#333,color:#fff
    style HackerBrain fill:#ed8936,stroke:#333,color:#fff
    style Backend fill:#667eea,stroke:#333,color:#fff
```

---

## 5 Tầng Kiến trúc

### Tầng 1: Dữ liệu (`data/`)
- Chứa dataset payload được gán nhãn (SQLi, XSS, CMDi, Path Traversal, SSRF...)
- Nguồn: Kaggle + tự sinh thêm (65,643 mẫu)
- Vai trò: Cung cấp kiến thức domain cho AI

### Tầng 2: Huấn luyện (`projectai.ipynb`)
- Tiền xử lý: Tokenizer → Padding → Bi-LSTM
- Output: `model/deep_learning_agent_core.keras` + `tokenizer.pkl` + `label_encoder.pkl`
- Split: 70% Train / 15% Val / 15% Test

### Tầng 3: Scanner chủ động (`modul1_scanner.py`)
- Crawl → Attack → Analyze → Report
- Kết hợp AI classification + Rule-based detection
- Adversarial Mutation Engine (6 strategies + 2 risky)

### Tầng 4: WAF Runtime (`modul2_waf.py`)
- Reverse Proxy trước backend thật
- 5 lớp phòng thủ tuần tự (Defense-in-Depth)
- Production-ready: Waitress WSGI đa luồng

### Tầng 5: Giao diện
- `ai_waf_scanner.html` — Operator Console cho Scanner
- `waf-dashboard/` — React Dashboard cho WAF stats

---

## Luồng Dữ liệu

### 🔧 Luồng Offline (Xây dựng AI)

```mermaid
flowchart LR
    A["📦 Dataset<br/>(data/)"] --> B["📓 Notebook<br/>(projectai.ipynb)"]
    B --> C["🧠 Model Artifacts<br/>(model/)"]
    C --> D["Module 1 + Module 2<br/>sử dụng chung"]
```

### 🔍 Luồng Scan (Red Team)

```mermaid
flowchart LR
    A["Nhập Target URL"] --> B["Crawl HTML<br/>tìm form/input"]
    B --> C["Gửi Payload<br/>(10 loại × N mẫu)"]
    C --> D["Phân tích Response<br/>Regex + AI"]
    D --> E["Tổng hợp Score<br/>JSON / Markdown Report"]
```

### 🛡️ Luồng WAF (Blue Team)

```mermaid
flowchart LR
    A["Request vào"] --> B["L1: Blacklist?"]
    B --> C["L2: Rate Limit?"]
    C --> D["L2.5: Canonicalize"]
    D --> E["L3: Regex Scan"]
    E --> F["L4: AI Scan"]
    F --> G{"Conf ≥ 90%?"}
    G -- "Có" --> H["🚫 403 Block"]
    G -- "75-89%" --> I["⚠️ Monitor + Flag IP"]
    G -- "< 75%" --> J["✅ Proxy → Backend"]
```

---

## Mối Liên kết giữa các Module

```mermaid
graph LR
    subgraph "Module 1 — Scanner"
        M1[modul1_scanner.py]
    end
    subgraph "Module 2 — WAF"
        M2[modul2_waf.py]
    end
    subgraph "Module 3 — Hacker Brain"
        M3[modul3.py]
    end
    subgraph "Target"
        WT["webtest.py<br/>:5170"]
    end
    subgraph "AI Core"
        MDL["deep_learning_agent_core.keras"]
        TKN[tokenizer.pkl]
        LBL[label_encoder.pkl]
    end
    
    M1 -- "Tấn công thử" --> M2
    M2 -- "Proxy an toàn" --> WT
    M3 -- "Sinh payload thông minh" --> M1
    M1 -.-> MDL
    M2 -.-> MDL
    M1 -.-> TKN
    M2 -.-> TKN
```

> [!important] Chung Model AI
> Cả Module 1 (Scanner) và Module 2 (WAF) **đều dùng chung** model Bi-LSTM. Đây là thiết kế **white-box** có chủ ý — Scanner biết chính xác WAF dùng model gì, nên có thể test **worst-case robustness**.

---

## Port Map

| Thành phần | Port | Mô tả |
|------------|------|-------|
| Web Testbed | `5170` | Backend vulnerable |
| AI WAF Shield | `5000` | Reverse proxy bảo vệ |
| Scanner API | `5001` | API cho dashboard HTML |
| WAF Dashboard | `5173` | React frontend |

---

**Xem thêm:** [[05-Module-2-WAF]] | [[04-Module-1-Scanner]] | [[06-Module-3-HackerBrain]]
