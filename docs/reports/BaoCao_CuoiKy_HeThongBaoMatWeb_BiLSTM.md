# BÁO CÁO ĐỒ ÁN MÔN HỌC

**ĐỀ TÀI: NGHIÊN CỨU VÀ TRIỂN KHAI HỆ THỐNG KIỂM THỬ VÀ BẢO VỆ AN NINH WEB TỰ ĐỘNG SỬ DỤNG MÔ HÌNH HỌC SÂU Bi-LSTM VỚI CƠ CHẾ TẤN CÔNG ĐỐI KHÁNG (ADVERSARIAL ATTACK)**

---

**ĐƠN VỊ**: ĐẠI HỌC QUỐC GIA HÀ NỘI – TRƯỜNG ĐẠI HỌC KHOA HỌC TỰ NHIÊN
**KHOA**: TOÁN – CƠ – TIN HỌC
**MÔN HỌC**: MỘT SỐ VẤN ĐỀ CHỌN LỌC CỦA TRÍ TUỆ NHÂN TẠO
**GIẢNG VIÊN HƯỚNG DẪN**: TS. NGUYỄN THỊ BÍCH THỦY
**SINH VIÊN THỰC HIỆN**: ĐINH TRƯỜNG AN, PHẠM HOÀNG ANH
**THỜI GIAN**: THÁNG 04 NĂM 2026

---

## MỤC LỤC

1. [Tổng quan và Đặt vấn đề](#1-tổng-quan-và-đặt-vấn-đề)
2. [Kiến trúc Hệ thống](#2-kiến-trúc-hệ-thống)
3. [Dữ liệu và Tiền xử lý](#3-dữ-liệu-và-tiền-xử-lý)
4. [Mô hình Học sâu Bi-LSTM](#4-mô-hình-học-sâu-bi-lstm)
5. [Kết quả Huấn luyện Mô hình](#5-kết-quả-huấn-luyện-mô-hình)
6. [Kết quả Thực nghiệm Đối kháng (Red Team vs Blue Team)](#6-kết-quả-thực-nghiệm-đối-kháng)
7. [Cơ chế Học trọn đời (Continual Learning)](#7-cơ-chế-học-trọn-đời)
8. [Kết luận và Hướng phát triển](#8-kết-luận-và-hướng-phát-triển)
9. [Tài liệu tham khảo](#9-tài-liệu-tham-khảo)

---

## 1. TỔNG QUAN VÀ ĐẶT VẤN ĐỀ

### 1.1. Bối cảnh Nghiên cứu

Trong kỷ nguyên số, ứng dụng web là cửa ngõ chính của thông tin nhưng cũng là mục tiêu hàng đầu của tội phạm mạng. Các hệ thống tường lửa ứng dụng web (WAF) truyền thống dựa trên luật (Signature-based) đang dần thất thủ trước các kỹ thuật **Obfuscation** (làm mờ mã độc) phức tạp. Việc tích hợp AI vào an ninh mạng là xu hướng tất yếu, nhưng bản thân các mô hình AI cũng có những lỗ hổng tiềm tàng khi đối mặt với **Adversarial Attacks** (tấn công đối kháng).

### 1.2. Bài toán Trọng tâm

Dự án tập trung giải quyết ba trụ cột kỹ thuật:

1. **Nhận diện đa lớp (Multi-class Classification)**: Phân loại chính xác **13 nhãn** dữ liệu (12 loại tấn công + 1 nhãn Normal).
2. **Tự động hóa Kiểm thử (Automated Pentesting)**: Sử dụng AI để tự động dò tìm và khai thác lỗ hổng web.
3. **Phòng thủ Chủ động (Proactive Defense)**: Thiết lập WAF có khả năng tự học từ sai lầm thông qua Continual Learning.

### 1.3. Các Thách thức Kỹ thuật

| Thách thức | Giải pháp |
|---|---|
| Mất cân bằng dữ liệu nghiêm trọng (Normal: 36K vs NoSQLi: 33 mẫu) | Class Weight Smoothing (căn bậc 2) + Augmentation có kiểm soát |
| Hội chứng OOV (Out-of-Vocabulary) với tiếng Việt | Character-level Tokenizer thay vì word-level |
| Bypass WAF bằng Encoding tricks | Recursive Canonicalization (URL decode + HTML unescape lặp) |
| Độ trễ hệ thống khi xử lý real-time | LRU Cache với TTL 300 giây, tối đa 1000 entry |
| False Positive chặn nhầm người dùng | Cơ chế Dual-Threshold (90% Block / 75% Monitor) |

---

## 2. KIẾN TRÚC HỆ THỐNG

Hệ thống được thiết kế theo triết lý **Red Team vs Blue Team**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI SECURITY TESTBED                          │
├──────────────────────┬──────────────────────────────────────────┤
│   RED TEAM           │          BLUE TEAM                       │
│                      │                                          │
│  Module 1: Scanner   │  Module 2: AI WAF Shield                 │
│  (Adversarial Attack)│  (Defense-in-Depth)                      │
│  • Greedy Hill       │  • L1: IP Blacklist                      │
│    Climbing          │  • L2: Rate Limiter                      │
│  • 10 loại payload   │  • L2.5: Canonicalization                │
│  • Multi-threading   │  • L3: Rule-Based Regex                  │
│                      │  • L4: AI Bi-LSTM Deep Scan               │
├──────────────────────┴──────────────────────────────────────────┤
│  Module 3: AI Hacker Brain (Llama 3) + Continual Learning       │
└─────────────────────────────────────────────────────────────────┘
```

**Các module lõi:**

- **Module 1 — AI Scanner (Red Team)**: Sử dụng `ThreadPoolExecutor` (4 luồng) để gửi payload đối kháng vào mục tiêu. Thuật toán Greedy Hill Climbing đột biến payload tối đa 15 vòng.
- **Module 2 — AI WAF Shield (Blue Team)**: Reverse Proxy chạy trên Waitress WSGI, bảo vệ backend bằng 5 tầng phòng thủ.
- **Module 3 — Hacker Brain + Retrain**: LLM Llama 3 sinh payload theo ngữ cảnh; Online Learning fine-tune model với LR = 1e-5.

---

## 3. DỮ LIỆU VÀ TIỀN XỬ LÝ

### 3.1. Nguồn dữ liệu

Dữ liệu được tổng hợp từ nhiều nguồn khác nhau:

| # | Nguồn | Số lượng (thô) | Nhãn |
|---|---|---|---|
| 1 | HttpParamsDataset (payload_train/test/full.csv) | 63,240 | SQLi, XSS, CMDi, Path Traversal, Normal |
| 2 | XSS_dataset.csv (Kaggle) | 13,686 | XSS, Normal |
| 3 | Command Injection.csv (Kaggle) | 2,106 | Command Injection, Normal |
| 4 | Modified_SQL_Dataset.csv | 30,919 | SQLi, Normal |
| 5 | WEB_APPLICATION_PAYLOADS.jsonl | 118 | SSRF, CSRF |
| 6 | OS-Command-Fuzzing.txt (GitHub) | 5,539 | Command Injection |
| 7 | path-traversal.txt + traversal.txt | 206 | Path Traversal |
| 8 | ssrf.txt + SSRF.txt | 448 | SSRF |
| 9 | data_new_variants.csv (tự thu thập) | 9,706 | SSTI, NoSQLi, XXE, JWTAuth |
| 10 | Mẫu bổ sung (Normal VN, Short SQLi, XSS, CSRF) | 3,180 | Đa nhãn |

### 3.2. Quy trình tiền xử lý

```
Dữ liệu thô → Clean Payload (HTML unescape + URL decode)
             → Loại bỏ trùng lặp (51,535 dòng)
             → Cân bằng nhãn (target = 8,000/nhãn, cap Normal = 15,000)
             → Bơm mẫu đặc chủng (Normal VN, Short SQLi, CSRF form)
             → Tổng: 65,643 mẫu | 13 nhãn
```

### 3.3. Phân bổ nhãn sau cân bằng

| Nhãn | Số lượng | Tỷ lệ |
|---|---|---|
| Normal | 17,500 | 26.7% |
| SQLi | 16,780 | 25.6% |
| XSS | 8,240 | 12.6% |
| CMDi | 8,000 | 12.2% |
| Command Injection | 8,000 | 12.2% |
| PathTraversal | 2,574 | 3.9% |
| SSRF | 1,620 | 2.5% |
| Path Traversal | 1,179 | 1.8% |
| JWTAuth | 759 | 1.2% |
| SSTI | 330 | 0.5% |
| XXE | 312 | 0.5% |
| CSRF | 250 | 0.4% |
| NoSQLi | 99 | 0.2% |

### 3.4. Chống rò rỉ dữ liệu (Data Leakage Prevention)

Để đảm bảo tính khách quan của đánh giá, chúng tôi áp dụng quy trình chia dữ liệu nghiêm ngặt:

- **Chia tập trước, fit tokenizer sau**: Tokenizer chỉ được fit trên tập train (70%), tập val (15%) và test (15%) hoàn toàn "mù" vocabulary.
- **Stratified Split**: Sử dụng `stratify=y` để giữ tỷ lệ nhãn đồng đều trên cả 3 tập.
- **Kích thước tập**: Train = 45,950 | Validation = 9,846 | Test = 9,847

---

## 4. MÔ HÌNH HỌC SÂU Bi-LSTM

### 4.1. Tại sao chọn Bi-LSTM?

**Bi-LSTM (Bidirectional Long Short-Term Memory)** cho phép mô hình nhìn thấy cả "quá khứ" và "tương lai" của một ký tự trong chuỗi payload. Điều này quan trọng trong an ninh mạng, nơi một ký tự `;` ở cuối câu có thể thay đổi hoàn toàn ý nghĩa của đoạn mã ở đầu câu (ví dụ: `admin' OR 1=1;--`).

So sánh với các kiến trúc khác:

| Kiến trúc | Ưu điểm | Hạn chế trong bài toán WAF |
|---|---|---|
| CNN | Nhanh, tốt cho đặc trưng cục bộ | Thiếu ngữ cảnh dài hạn |
| RNN | Xử lý chuỗi tuần tự | Vanishing gradient, chỉ nhìn 1 chiều |
| Transformer | Attention toàn cục | Quá nặng cho inference real-time |
| **Bi-LSTM** | **Ngữ cảnh 2 chiều + Gate mechanism** | **Cân bằng giữa hiệu năng và độ chính xác** |

### 4.2. Cấu trúc mạng Neural

```
Input (150 ký tự)
    │
    ▼
┌─────────────────────────────┐
│ Embedding Layer             │  input_dim=10,000 | output_dim=64
│ (Chuyển ký tự → vector 64D)│
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Bidirectional LSTM          │  64 units × 2 chiều = 128 output
│ (return_sequences=True)     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ GlobalMaxPooling1D          │  Lấy đặc trưng nổi bật nhất
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Dense(64, relu)             │  Fully Connected
│ Dropout(0.5)                │  Chống overfitting
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ Dense(13, softmax)          │  Output: 13 nhãn
└─────────────────────────────┘
```

### 4.3. Hyperparameters

| Tham số | Giá trị | Lý do |
|---|---|---|
| MAX_LEN | 150 | Đủ dài cho hầu hết payload, không quá nặng |
| Embedding dim | 64 | Cân bằng biểu diễn và tốc độ |
| LSTM units | 64 (×2 chiều) | Đủ phức tạp cho 13 nhãn |
| Dropout | 0.5 | Chống overfitting mạnh |
| Optimizer | Adam | Hội tụ nhanh, adaptive learning rate |
| Loss | Sparse Categorical Crossentropy | Phù hợp multi-class |
| Batch size | 64 | Tối ưu GPU memory |
| Epochs | 20 (EarlyStopping patience=3) | Tự dừng khi val_loss không giảm |
| Tokenizer | Character-level, OOV token | Xử lý ký tự lạ và tiếng Việt |

### 4.4. Kỹ thuật Class Weight Smoothing

Do dữ liệu mất cân bằng nghiêm trọng, chúng tôi áp dụng **Smoothed Class Weights** bằng căn bậc 2:

```
weight_smoothed = √(weight_balanced)
```

Trọng số một số nhãn tiêu biểu:

| Nhãn | Weight gốc (balanced) | Weight sau smoothing (√) |
|---|---|---|
| Normal | 0.63 | 0.79 |
| SQLi | 0.55 | 0.78 |
| CSRF | 20.22 | 4.49 |
| NoSQLi | 6.66 | 2.58 |
| XXE | 15.30 | 3.91 |

Kỹ thuật này giúp nhãn hiếm (CSRF, NoSQLi) được ưu tiên hơn nhưng không quá mạnh đến mức gây nhiễu cho nhãn phổ biến.

---

## 5. KẾT QUẢ HUẤN LUYỆN MÔ HÌNH

### 5.1. Quá trình huấn luyện (20 Epochs)

| Epoch | Train Accuracy | Train Loss | Val Accuracy | Val Loss |
|---|---|---|---|---|
| 1 | 77.03% | 0.8371 | 90.14% | 0.3236 |
| 5 | 94.43% | 0.2047 | 95.29% | 0.1403 |
| 10 | 96.11% | 0.1200 | 96.66% | 0.1004 |
| 15 | 96.86% | 0.0869 | 96.94% | 0.0921 |
| 20 | 97.36% | 0.0708 | 97.58% | 0.0760 |

**Nhận xét:**
- Mô hình hội tụ nhanh từ epoch 1→5 (77% → 94%).
- Không có dấu hiệu overfitting: val_loss giảm đều, gap train-val nhỏ (< 0.5%).
- EarlyStopping không kích hoạt → mô hình vẫn cải thiện đều đến epoch 20.

### 5.2. Đánh giá trên Test Set (Độc lập)

```
┌────────────────────────────────────────┐
│  TEST ACCURACY:  97.43%                │
│  TEST LOSS:      0.0858                │
│  Test Set Size:  9,847 mẫu             │
└────────────────────────────────────────┘
```

### 5.3. Kiểm thử Payload cụ thể (Inference)

| Payload | Nhãn dự đoán | Confidence |
|---|---|---|
| `admin' OR 1` | SQLi | 99.51% |
| `<img src='x' onerror='alert(1)'>` | XSS | 100.00% |
| `test && cat /etc/passwd` | Command Injection | 99.36% |
| `../../../../etc/shadow` | Path Traversal | 50.67% |
| `http://169.254.169.254/latest/meta-data/` | SSRF | 100.00% |
| `{{7*7}}` | SSTI | 98.30% |
| `{"$gt": ""}` | NoSQLi | 99.94% |
| `<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>` | XXE | 99.96% |
| `eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.` | JWTAuth | 100.00% |
| `Xin chào, tôi muốn tìm tài liệu NCKH` | Normal | 100.00% |
| `https://www.google.com/search?q=cat` | Normal | 100.00% |

**Nhận xét:** Mô hình phân loại chính xác 11/11 payload thử nghiệm. Đặc biệt, các nhãn mới (SSTI, NoSQLi, XXE, JWTAuth) đều đạt confidence > 98% dù dữ liệu train rất ít. Tiếng Việt và URL bình thường được nhận diện đúng là Normal (100%).

---

## 6. KẾT QUẢ THỰC NGHIỆM ĐỐI KHÁNG

### 6.1. Kịch bản thực nghiệm

**Môi trường:**
- Backend: `webtest.py` chạy trên port 5170 (11 endpoint có lỗ hổng)
- WAF: `modul2_waf.py` chạy trên port 5000 (Reverse Proxy)
- Scanner: `modul1_scanner.py` tấn công đa luồng (4 workers)

**Bài kiểm tra 1 — Scanner vs Backend (không có WAF):**

| Metric | Giá trị |
|---|---|
| Endpoints quét | 11 |
| Payloads đã gửi | 1,333 |
| Lỗ hổng phát hiện | **132** |
| Thời gian quét | 1,572 giây (~26 phút) |
| Điểm an toàn | **18/100** |

Chi tiết lỗ hổng phát hiện:

| Loại tấn công | Mức độ | Endpoints bị ảnh hưởng | Số lỗ hổng |
|---|---|---|---|
| SQLi | 🔴 CRITICAL | `/search-user` | 8 |
| XSS | 🟠 HIGH | 9/11 endpoints | 120+ |
| SSTI | 🟠 HIGH | `/ssti` | Phát hiện `49` (7×7) |
| NoSQLi | 🟡 MEDIUM | `/nosqli` | Phát hiện MongoError |

### 6.2. Bài kiểm tra 2 — Scanner vs WAF (có bảo vệ)

Khi bật WAF bảo vệ backend:

| Metric | Không có WAF | Có WAF |
|---|---|---|
| Tấn công thành công | 132 | **0** |
| Rate Limit triggered | — | < 30 giây |
| IP bị Blacklist | — | Có (auto) |
| HTTP Response | 200 OK | **403 Blocked / 429 Rate Limited** |
| Điểm an toàn | 18/100 | **91/100** |

**Phân tích chi tiết:**
- **Rate Limiter**: Do Scanner bắn đa luồng (4 workers), IP `127.0.0.1` ngay lập tức bị đẩy xuống 10 req/phút sau khi bị detect payload đầu tiên.
- **Rule-Based Layer (L3)**: Sau khi WAF canonicalize (giải mã URL + HTML entities), tất cả 78 biến thể mutation đều bị lớp Regex bắt lại.
- **AI Layer (L4)**: Phát hiện các payload gốc với confidence > 90%, trigger Hard Block.

### 6.3. Phân tích Adversarial Mutation

Scanner sử dụng thuật toán **Greedy Hill Climbing** để đột biến payload:

```
Payload gốc: <script>alert('XSS')</script>
  ↓ html_entity mutation
Biến thể 1:  &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;
  → AI confidence giảm: 100% → 65.48%  (giảm 34.52%)
  → Nhưng WAF canonicalize → phát hiện lại bằng Regex
```

| Chiến lược Mutation | Tỷ lệ giảm confidence trung bình | Bypass AI thành công? | Bypass WAF? |
|---|---|---|---|
| html_entity | -34.5% | ❌ (vẫn > 50%) | ❌ (L3 Regex chặn) |
| url_encode | -15.2% | ❌ | ❌ (Canonicalize decode) |
| case_swap | -8.7% | ❌ | ❌ |
| sql_comment | -12.3% | ❌ | ❌ |
| whitespace | -5.1% | ❌ | ❌ |
| concat_split | -3.8% | ❌ | ❌ |

**Kết luận:** Không có chiến lược mutation đơn lẻ nào vượt qua được kiến trúc Defense-in-Depth. Lớp Canonicalization (L2.5) triệt tiêu hiệu quả của encoding tricks, và lớp Rule-Based (L3) đóng vai trò "lưới an toàn" cuối cùng.

### 6.4. Cơ chế Dual-Threshold

| Vùng Confidence | Hành động | Mục đích |
|---|---|---|
| ≥ 90% | 🔴 **BLOCK** (HTTP 403) | Chắc chắn tấn công → chặn cứng |
| 75% – 89% | 🟡 **MONITOR** (Flag IP, Rate Limit) | Nghi ngờ → theo dõi, không chặn nhầm |
| 50% – 74% | 🔵 **LOG** | Ghi nhận để phân tích sau |
| < 50% | ✅ **ALLOW** | Coi là bình thường |

---

## 7. CƠ CHẾ HỌC TRỌN ĐỜI (CONTINUAL LEARNING)

### 7.1. Quy trình

```
Người dùng báo cáo "chặn nhầm" → /api/report_fp
    ↓
Lưu vào fp_reports.json
    ↓
modul3_retrain.py: Load model → Fine-tune với LR=1e-5, 3 epochs
    ↓
Lưu model mới → Backup dữ liệu FP đã xử lý
```

### 7.2. Chống Catastrophic Forgetting

- **Learning Rate cực nhỏ**: 1e-5 (so với 1e-3 khi train ban đầu) → chỉ điều chỉnh nhẹ trọng số.
- **Batch size nhỏ**: 8 mẫu/batch → cập nhật gradient mịn.
- **Epochs ít**: 3 epochs → tránh overfit vào dữ liệu FP mới.

---

## 8. KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

### 8.1. Kết luận

Dự án đã xây dựng thành công một hệ sinh thái an ninh mạng AI hoàn chỉnh với các đóng góp chính:

1. **Mô hình Bi-LSTM** đạt **97.43% accuracy** trên test set độc lập, phân loại được **13 nhãn** tấn công web.
2. **Kiến trúc Defense-in-Depth** (5 tầng) chặn 100% payload tấn công trong thực nghiệm, nâng điểm an toàn từ **18/100 lên 91/100**.
3. **Thuật toán Greedy Hill Climbing** cho phép đánh giá khách quan độ bền vững của mô hình AI trước adversarial attacks.
4. **Cơ chế Continual Learning** cho phép WAF tự tiến hóa mà không mất kiến thức cũ.

### 8.2. Hướng phát triển

1. **Black-box Oracle**: Nâng cấp thuật toán Hill Climbing để đánh giá dựa vào HTTP Status thay vì đọc confidence trực tiếp từ model (White-box → Black-box).
2. **Triển khai Cloud-Native**: Đóng gói hệ thống vào Docker/Kubernetes để scale ngang trên hạ tầng đám mây.
3. **Tích hợp Reinforcement Learning**: Sử dụng tác nhân RL để tự động tìm kiếm chiến thuật tấn công mới.
4. **Threat Intelligence LLM**: Dùng LLM đọc Log WAF để tự động viết báo cáo tình báo hiểm họa theo thời gian thực.

---

## 9. TÀI LIỆU THAM KHẢO

1. Hochreiter, S., & Schmidhuber, J. (1997). Long Short-Term Memory. *Neural Computation*, 9(8), 1735-1780.
2. Goodfellow, I. J., Shlens, J., & Szegedy, C. (2014). Explaining and Harnessing Adversarial Examples. *arXiv:1412.6572*.
3. OWASP Foundation. (2021). OWASP Top Ten Web Application Security Risks.
4. Nguyen, T.B. et al. (2024). AI-based Web Application Firewall: A Survey. *Journal of Network Security*.
5. PayloadsAllTheThings — GitHub Repository: https://github.com/swisskyrepo/PayloadsAllTheThings

---
**HẾT BÁO CÁO**
