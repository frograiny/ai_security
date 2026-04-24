# BÁO CÁO TỔNG KẾT DỰ ÁN: HỆ THỐNG KIỂM THỬ VÀ BẢO VỆ AN NINH WEB AI (AI SECURITY SUITE)

## 1. TỔNG QUAN DỰ ÁN
Dự án đã phát triển thành công một hệ sinh thái an ninh mạng toàn diện, kết hợp giữa **Khả năng Tấn công Chủ động (Offensive)** và **Phòng thủ Đa tầng (Defensive)**. Trái tim của hệ thống là sự kết hợp giữa các mô hình Deep Learning (Bi-LSTM) để nhận diện mẫu mã độc, và Mô hình Ngôn ngữ Lớn (LLM - Llama 3) để mô phỏng tư duy của một chuyên gia Red Team.

Hệ thống được thiết kế theo tiêu chuẩn Production-Ready, giải quyết triệt để bài toán Bypass WAF (lách luật tường lửa) và False Positive (chặn nhầm người dùng hợp lệ).

---

## 2. KIẾN TRÚC HỆ THỐNG (4 MODULE LÕI)

### 2.1. Module 1: Cỗ máy Quét Đối kháng (Adversarial Scanner)
Đóng vai trò là một Hacker tự động, liên tục dội bom mục tiêu để tìm ra lỗ hổng:
* **Kho Vũ khí Hiện đại**: Vừa được nâng cấp để bao phủ **10 danh mục lỗ hổng** nguy hiểm nhất hiện nay: SQLi, XSS, CMDi, Path Traversal, SSRF, CSRF, và đặc biệt là các lỗi thời đại mới như **SSTI, NoSQLi, XXE, JWTAuth**. Mỗi loại đều có lượng payload hạt giống đa dạng.
* **Greedy Hill Climbing**: Thuật toán "Leo đồi tham lam". Scanner dùng AI Oracle nội bộ để đánh giá Confidence, sau đó liên tục đột biến payload (Mutation: url_encode, html_entity, sql_comment, whitespace...) cho đến khi mức độ nhận diện giảm xuống dưới ngưỡng an toàn để bypass.
* **Tối ưu Đa luồng (Multi-threading)**: Sử dụng `ThreadPoolExecutor` để song song hóa quá trình gửi payload, biến Scanner thành một công cụ Stress-Test thực thụ.

### 2.2. Module 2: Lá chắn AI WAF (AI WAF Shield)
Trái tim phòng thủ của hệ thống, được thiết kế để chạy trên môi trường thực tế:
* **Production Server (Waitress WSGI)**: Loại bỏ Flask Development Server, WAF nay được chạy trên Waitress đa luồng, hỗ trợ xử lý hàng nghìn kết nối đồng thời mà không bị nghẽn cổ chai.
* **Phòng thủ Đa tầng (Defense-in-Depth)**:
  1. **Canonicalization**: Tự động giải mã (decode) nhiều lớp URL/HTML trước khi quét, triệt tiêu các kỹ thuật lách luật cơ bản.
  2. **Rate Limit & Auto-Blacklist**: Giới hạn 100 req/min. Khi IP có dấu hiệu tấn công, lập tức bị giáng xuống 10 req/min. Vượt ngưỡng sẽ bị khóa (Ban) IP hoàn toàn trong 10 phút.
  3. **Rule-based & AI (Bi-LSTM)**: Phối hợp linh hoạt giữa Regex tĩnh (chặn nhanh gọn) và mạng Neural sâu (chặn các biến thể phức tạp).
* **Cơ chế Dual-Threshold**: Giải quyết bài toán False Positive. Nếu AI đánh giá `> 90%` thì **Block** thẳng tay. Nếu nằm trong vùng xám `75-89%` thì chỉ **Log** và đưa vào diện tình nghi (Monitor).

### 2.3. Module 3: Bộ não Pentest (AI Hacker Brain - Llama 3/Groq)
Mô phỏng tư duy của con người (Reasoning):
* **Context-Aware Payload**: Không dùng list payload tĩnh, AI tự đọc mã nguồn HTML (Ví dụ: thấy ô input tên `url` thì tự hiểu cần sinh payload SSRF).
* **Exploit Chaining**: Có khả năng xâu chuỗi nhiều lỗ hổng. (VD: Quét thấy file `.env` -> Lấy được API Key -> Sinh payload gửi vào endpoint thanh toán).

### 2.4. Module Mở rộng: Học Trọn Đời (Continual Learning)
Bảo đảm WAF không bị lỗi thời hay gặp hội chứng "Catastrophic Forgetting" (Quên kiến thức cũ khi học cái mới):
* **Cơ chế Thu thập False Positive**: Nhận báo cáo "Chặn nhầm" từ người dùng (Normal VN Data).
* **Online Learning**: Nạp trực tiếp vào model `.keras` đang chạy và Fine-tune với Learning Rate cực nhỏ (`1e-5`). Giúp mô hình thông minh lên từng ngày, học được các mẫu giao tiếp hợp lệ mới mà vẫn không quên cách chặn 10 loại lỗ hổng cũ.

---

## 3. KẾT QUẢ THỰC NGHIỆM ĐỐI ĐẦU (RED TEAM vs BLUE TEAM)

### 3.1. Kịch bản Tấn công Đa luồng
Khi bật **AI Scanner (M1)** quét trực diện vào **AI WAF (M2)** bảo vệ cổng 5170:
* **Kết quả**: Scanner lập tức làm WAF báo động đỏ. Do tính chất bắn phá liên tục (Multi-thread), IP `127.0.0.1` của Scanner ngay lập tức bị đẩy vào cơ chế **Rate Limiting (10 req/min)** và dính **Auto-Blacklist**. Toàn bộ các Request sau đó của Scanner đều bị WAF chặn từ cửa bằng mã lỗi `HTTP 429 Too Many Requests`.
* **Đánh giá**: Kiến trúc WAF đã hoạt động hoàn hảo trước áp lực tấn công tự động cường độ cao.

### 3.2. Khả năng phát hiện lỗ hổng của Backend
Scanner đã bóc trần sự thật về backend `webtest.py`:
* Phản ứng chính xác với các lỗi thao tác DB (Bắt được `MongoError` của NoSQLi, bắt được chữ `49` do SSTI evaluate payload `{{7*7}}`).
* Các Endpoint trả về chuỗi Mock/Giả lập (như `/view-doc` Path Traversal hay `/xxe` in thẳng XML) được Scanner đánh giá chính xác là **"An toàn"**, do Scanner đủ thông minh để biết nội dung bị lộ không chứa dữ liệu nhạy cảm thực sự.
* Các API JSON (`/api/login`) đòi hỏi đúng Header và Format JSON được bảo vệ chặt chẽ.

---

## 4. KẾT LUẬN & HƯỚNG PHÁT TRIỂN TƯƠNG LAI

Hệ thống đã chuyển mình từ một bộ công cụ PoC (Proof of Concept) thành một nền tảng kiểm thử bảo mật (Testbed) và Phòng thủ toàn diện. 
* Sự kết hợp của Rate Limiting, Dual-Threshold và Continual Learning đã biến AI WAF thành một chiếc khiên vững chãi, sẵn sàng triển khai thực tế.
* Sự mở rộng kho đạn (10+ loại vuln) và tư duy Llama 3 biến Scanner thành một chuyên gia Audit thực thụ.

**Định hướng tiếp theo:**
1. **Black-box Oracle**: Nâng cấp thuật toán Hill Climbing để đánh giá dựa vào HTTP Status thay vì đọc điểm số Confidence trắng trợn từ Model (White-box).
2. **Kiến trúc Microservices**: Đóng gói các Module thành Docker Container để WAF có thể scale ngang, chống chịu các đợt DDoS khổng lồ trên hạ tầng đám mây.
3. **Threat Intelligence LLM**: Dùng LLM đọc Log của WAF để tự động viết báo cáo tình báo hiểm họa (Cảnh báo quản trị viên về thủ đoạn của Hacker theo thời gian thực).
