# BÁO CÁO CẢI TIẾN HỆ THỐNG KIỂM THỬ AN NINH AI (AI SECURITY TESTBED)

## 1. Tổng quan Dự án
Hệ thống đã được nâng cấp từ một bản mẫu chức năng thành một môi trường nghiên cứu an ninh chính quy. Mục tiêu là kiểm chứng khả năng phòng thủ của **AI WAF (Module 2)** trước các cuộc tấn công tinh vi từ **AI Scanner (Module 1)** bằng phương pháp tấn công đối kháng (Adversarial Attacks).

## 2. Các Cải tiến Kỹ thuật Chính

| Hạng mục | Trạng thái cũ | Nâng cấp mới | Giá trị mang lại |
| :--- | :--- | :--- | :--- |
| **Chiến lược Mutation** | Heuristic/Ngẫu nhiên | **Greedy Hill Climbing (15 rounds)** | Tìm ra payload bypass tối ưu nhất bằng cách giảm dần confidence của AI qua từng vòng lặp. |
| **Mô hình Hiểm họa** | Chưa định nghĩa | **Formal Threat Model (5 Layers)** | Xác định rõ ranh giới phòng thủ và năng lực kẻ tấn công, chuẩn hóa quy trình kiểm thử. |
| **Chỉ số Security** | Chỉ có Accuracy (97%) | **Bypass Rate, ASR, Time-to-Bypass** | Đo lường hiệu quả an ninh thực tế thay vì chỉ đo độ chính xác của mô hình ML. |
| **Hệ thống Logging** | Log text đơn giản | **SQLite Attack Logger** | Lưu trữ cấu trúc payload bypass, thời gian phản hồi để phân tích offline và retraining mô hình. |
| **Canonicalization** | URL decode 1 lần | **Recursive decode (URL + HTML + Null byte)** | Chặn toàn bộ encoding-based bypass trước khi Rule/AI scan. |
| **Oracle Transparency** | Không ghi nhận | **White-box assumption documented** | Hợp thức hóa thiết kế, nêu rõ bypass rate là worst-case upper bound. |

---

## 3. Mô hình Phòng thủ 4 Lớp (Defense-in-Depth)

Hệ thống Module 2 (WAF) hiện tại thực thi cơ chế bảo vệ đa tầng:

1.  **L1: IP Blacklist**: Tự động chặn IP tấn công dựa trên tần suất vi phạm (5 blocks/60s).
2.  **L2: Rate Limiter**: Giới hạn tốc độ request (100 req/min) để chống Brute-force/DoS.
3.  **L2.5: Canonicalization**: Recursive URL decode + HTML entity decode + null byte strip. Đưa payload về dạng nguyên thủy trước khi scan. Ví dụ: `%3Cscript%3E` → `<script>`, `&lt;script&gt;` → `<script>`, `%2527` → `'`.
4.  **L3: Rule-Based Layer**: Sử dụng 15 bộ Regex cứng để chặn các attack signature kinh điển (SQLi, XSS, Path Traversal) với độ tin cậy 99.9%.
5.  **L4: AI Bi-LSTM Layer**: Quét sâu các payload đã được mutation/obfuscation mà Rule-based bỏ sót. Ngưỡng chặn được thiết lập tại **75% confidence**.

---

## 4. Oracle Assumption (White-box Disclosure)

Scanner (Module 1) sử dụng **chính model Bi-LSTM của WAF** làm oracle để đánh giá confidence trước khi mutation. Đây là **white-box assumption** — attacker ngoài đời **KHÔNG** có access vào model.

**Tại sao vẫn hợp lệ:**
- Kiểm chứng **worst-case robustness**: nếu model chịu được white-box attack, thì black-box attack càng không thành công.
- Bypass rate đo được (6.2%) là **giá trị xấu nhất** — trong thực tế sẽ thấp hơn nhiều.
- Đây là phương pháp tiêu chuẩn trong adversarial ML research (tham khảo: Carlini & Wagner, 2017).

**Hướng phát triển**: Thay thế oracle bằng **response-based scoring** (chỉ dựa trên HTTP status code 200/403/429), loại bỏ trực tiếp model access → chuyển sang **black-box testing** đúng nghĩa.

## 4. Kết quả Thực nghiệm (Adversarial Testing)

Kết quả ghi nhận từ đợt quét gần nhất trên mục tiêu `webtest.py`:

### Thống kê Chung
- **Tổng số Payload gốc**: 385
- **Số Payload AI nhận diện được**: 341 (88.6%)
- **Số lần Mutation thử nghiệm**: 709 rounds
- **Bypass thành công (Evasions)**: 21

### Chỉ số An ninh (Security Metrics)
- **Bypass Rate**: **6.2%** (Tỷ lệ payload vượt qua AI sau khi được mutation tối ưu).
- **Attack Success Rate (ASR)**: **22.9%** (Tỷ lệ khai thác thành công lỗ hổng backend).
- **Avg Rounds to Bypass**: **1.5 vòng** (Kẻ tấn công chỉ cần trung bình 1.5 bước biến đổi để bypass AI).
- **Avg Time to Bypass**: **0.779 giây** (Thời gian cực ngắn để tìm ra lỗ hổng).

---

## 5. Phân tích Dữ liệu Bypass (Attack Log)

Dữ liệu từ `attack_log.db` cho thấy các payload bypass thành công thường sử dụng chuỗi biến đổi kết hợp (Chain Mutation):

**Ví dụ Bypass điển hình:**
- **Gốc**: `admin' --` (Confidence: 100% - Bị chặn)
- **Mutation**: `admin&#x27;--` (Confidence: 38% - **BYPASS THÀNH CÔNG**)
- **Kỹ thuật**: `html_entity` -> `whitespace`

**Nhận xét**: Lớp Rule-based (Regex) đóng vai trò cực kỳ quan trọng. Trong các kịch bản thực tế, khi AI bị mutation làm giảm confidence xuống dưới 75%, lớp Rule-based vẫn có thể "cứu" hệ thống nếu payload chứa các từ khóa cấm.

---

## 7. Kết luận & Kiến nghị
Hệ thống kiểm thử đã chứng minh được:
1. Mô hình AI (Bi-LSTM) có độ chính xác cao nhưng vẫn tồn tại kẽ hở trước các kỹ thuật **Guided Mutation** (bypass rate 6.2% — worst-case).
2. Kiến trúc **Hybrid (Rule + ML + Canonicalization)** là bắt buộc để đạt được an ninh tối ưu.
3. **Canonicalization** là lớp phòng thủ thiết yếu — không có nó, attacker chỉ cần `url_encode()` 1 lần là bypass toàn bộ.
4. Việc triển khai **Greedy Hill Climbing** giúp nâng tầm Module 1 từ một scanner thông thường thành một công cụ **Security Auditor** chuyên nghiệp.
5. Oracle leakage đã được **ghi nhận và hợp thức hóa** — kết quả phản ánh worst-case upper bound, phù hợp với phương pháp nghiên cứu adversarial ML.

**Kiến nghị:**
- Sử dụng dữ liệu từ `attack_log.db` để thực hiện **Adversarial Training** → model học được mutation patterns mới.
- Phát triển chế độ **Black-box testing** (response-based oracle) để so sánh với kết quả white-box hiện tại.
- Mở rộng mutation strategies: thêm Unicode normalization, mixed encoding, và context-aware mutations.
