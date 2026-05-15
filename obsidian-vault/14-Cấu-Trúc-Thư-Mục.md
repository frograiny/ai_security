---
tags: [structure, file-tree]
aliases: [Cấu trúc thư mục, File tree]
---

# 📁 Cấu Trúc Thư Mục

> Bản đồ toàn bộ file và thư mục trong dự án AI Security.

---

## File Tree

```
d:\AI\ai_security\
│
├── 📄 modul1_scanner.py          ← 🗡️ Red Team Scanner (1,548 dòng)
├── 📄 modul2_waf.py              ← 🛡️ Blue Team WAF Shield (923 dòng)
├── 📄 modul3.py                  ← 🧠 Hacker Brain - Groq/Qwen (1,163 dòng)
├── 📄 modul3_retrain.py          ← 🔄 Continual Learning (108 dòng)
├── 📄 webtest.py                 ← 🎯 Web Testbed (345 dòng)
├── 📄 attack_log.py              ← 📝 Attack Logger - SQLite (172 dòng)
├── 📄 datacollect.py             ← 📦 Data collection utilities
├── 📄 run_scanner.py             ← 🚀 Scanner launcher
│
├── 📄 projectai.ipynb            ← 📓 Jupyter Notebook (Training)
├── 📄 ai_waf_scanner.html        ← 🖥️ Scanner Dashboard (HTML)
│
├── 📄 requirements.txt           ← 📋 Python dependencies
├── 📄 .env                       ← 🔑 API keys (GROQ_API_KEY)
├── 📄 .gitignore                 ← Git ignore rules
├── 📄 LICENSE                    ← MIT License
│
├── 📄 README.md                  ← 📖 GitHub README
├── 📄 FINAL_REPORT.md            ← 📊 Báo cáo tổng kết
├── 📄 HUONG_DAN_CHAY_THUC_TE.md  ← 🚀 Hướng dẫn chạy
│
├── 📄 data_new_variants.csv      ← Dataset bổ sung
├── 📄 attack_log.db              ← 💾 SQLite attack log
├── 📄 shield_protection.log      ← 📝 WAF protection log
├── 📄 shield_alerts.log          ← 🚨 WAF alert log
├── 📄 scan_report_*.json         ← 📊 Scan reports (JSON)
├── 📄 scan_report_*.md           ← 📊 Scan reports (Markdown)
│
├── 📂 model/                     ← 🧠 AI Model Artifacts
│   ├── deep_learning_agent_core.keras  (8.6 MB)
│   ├── tokenizer.pkl                   (9 KB)
│   └── label_encoder.pkl              (371 B)
│
├── 📂 data/                      ← 📦 Training Data
│   ├── README.md                 ← Hướng dẫn tải dataset
│   ├── download_datasets.py      ← Script tải tự động
│   ├── fp_reports.json           ← False Positive reports
│   ├── generate_modern_payloads.py
│   ├── new/                      ← Dataset mới
│   └── web_payloads/             ← Web payload dataset
│
├── 📂 docs/                      ← 📚 Documentation
│   ├── THREAT_MODEL.md           ← Mô hình đe doạ
│   ├── development/
│   │   ├── ADVERSARIAL_LOOP_PLAN.md  ← Kế hoạch adversarial
│   │   └── nhat_ky_phat_trien.md     ← Nhật ký phát triển
│   ├── theory/
│   │   └── project_theory_explanation.md  ← Giải thích lý thuyết
│   └── reports/
│       ├── BAO_CAO_AI_SECURITY.md
│       ├── BaoCao_CuoiKy_HeThongBaoMatWeb_BiLSTM.md
│       └── *.docx (báo cáo Word)
│
├── 📂 helpers/                   ← 🔧 Utility Scripts
│   ├── code_map.md               ← Bản đồ cấu trúc code
│   ├── diagnose_data.py          ← Chẩn đoán dataset
│   ├── fix_balance.py            ← Cân bằng dataset
│   └── ...
│
├── 📂 waf-dashboard/             ← 🖥️ React WAF Dashboard
│   └── (React + Vite project)
│
└── 📂 .agents/                   ← 🤖 Gemini Agent Workflows
    └── workflows/
        ├── full_integration_test.md
        ├── modul1_scanner.md
        └── modul2_waf.md
```

---

## Phân loại File theo Vai trò

### 🔴 Core Modules (Chạy trực tiếp)

| File | Vai trò | Xem chi tiết |
|------|---------|-------------|
| `modul1_scanner.py` | Red Team Scanner | [[04-Module-1-Scanner]] |
| `modul2_waf.py` | Blue Team WAF | [[05-Module-2-WAF]] |
| `modul3.py` | Hacker Brain (LLM) | [[06-Module-3-HackerBrain]] |
| `modul3_retrain.py` | Continual Learning | [[08-Continual-Learning]] |
| `webtest.py` | Vulnerable Backend | [[09-Web-Testbed]] |

### 🟡 AI Artifacts (Không chỉnh sửa trực tiếp)

| File | Vai trò | Xem chi tiết |
|------|---------|-------------|
| `model/*.keras` | Trọng số model | [[03-Mô-Hình-AI-BiLSTM]] |
| `model/tokenizer.pkl` | Bộ mã hoá text | [[03-Mô-Hình-AI-BiLSTM]] |
| `model/label_encoder.pkl` | Ánh xạ nhãn | [[03-Mô-Hình-AI-BiLSTM]] |
| `projectai.ipynb` | Notebook huấn luyện | [[03-Mô-Hình-AI-BiLSTM]] |

### 🟢 Support Files

| File | Vai trò |
|------|---------|
| `attack_log.py` | Logger cho Scanner |
| `datacollect.py` | Thu thập dữ liệu |
| `requirements.txt` | Dependencies |
| `.env` | API keys |

### 🔵 Documentation

| File | Nội dung |
|------|---------|
| `README.md` | GitHub landing page |
| `FINAL_REPORT.md` | Báo cáo tổng kết |
| `HUONG_DAN_CHAY_THUC_TE.md` | Hướng dẫn triển khai |
| `docs/THREAT_MODEL.md` | Mô hình đe doạ |

---

**Xem thêm:** [[02-Kiến-Trúc-Hệ-Thống]] | [[01-Tổng-Quan-Dự-Án]]
