# 🧠 Adversarial Feedback Loop — Kế Hoạch Thay Đổi

**Ngày:** 22/04/2026  
**File chính bị ảnh hưởng:** `modul1_scanner.py`, `README.md`

---

## 1. Vấn đề hiện tại

```
Scanner (modul1) hiện tại:
  ├─ Đọc payload list tĩnh (ATTACK_PAYLOADS dict)
  ├─ Bắn thẳng vào target (mù, không hỏi model)
  ├─ Phân tích response bằng regex (VULN_SIGNATURES)
  └─ AI engine CHỈ dùng để gắn nhãn sau khi đã bắn

WAF (modul2):
  └─ Dùng CÙNG model Bi-LSTM → dễ dàng chặn 100% payload tĩnh
```

**Kết quả:** Khi scanner đánh vào WAF → bị block toàn bộ → báo cáo 0 lỗ hổng.  
Scanner không có "trí tuệ" thật sự.

---

## 2. Giải pháp: Adversarial Feedback Loop

```
Payload gốc
    │
    ▼
┌─────────────────────────────┐
│  ORACLE CHECK (offline)     │  ← Hỏi model: "payload này bị detect không?"
│  model.predict(payload)     │
│  confidence ≥ 75%?          │
└─────────┬───────────────────┘
          │ CÓ (bị detect)
          ▼
┌─────────────────────────────┐
│  MUTATION ENGINE            │  ← Tạo N biến thể (case mix, encoding, ...)
│  PayloadMutator.mutate_all()│
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│  BATCH ORACLE CHECK         │  ← Hỏi model cả batch mutations
│  model.predict(batch)       │
│  Chọn mutation có conf THẤP │
│  nhất (evasive nhất)        │
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│  BẮN VÀO TARGET            │  ← Gửi cả original + best evasive
│  Ghi log 4 trạng thái:     │
│  • model detect + waf block │
│  • model detect + waf pass  │
│  • model evade + waf block  │  ← MODEL CÓ ĐIỂM YẾU
│  • model evade + waf pass   │  ← BYPASS HOÀN TOÀN
└─────────────────────────────┘
```

---

## 3. Thiết kế ngưỡng (Threshold Design)

| Ngưỡng | Giá trị | Dùng ở đâu | Lý do |
|--------|---------|-------------|-------|
| `ORACLE_THRESHOLD` | 75% | Scanner oracle | Trigger mutation khi model detect payload với conf ≥ 75% |
| `EVASION_THRESHOLD` | 50% | Scanner oracle | Nếu mutation giảm conf xuống < 50% → coi là evasive |
| WAF threshold | 75% | modul2_waf.py | Block request khi conf ≥ 75% |

**Tại sao Oracle và WAF cùng 75%?**  
Đây là **thiết kế có chủ ý**, không phải trùng hợp:
- Oracle mô phỏng chính xác hành vi của WAF — nếu Oracle nói "bị detect" thì WAF cũng sẽ chặn.
- Nếu dùng ngưỡng thấp hơn (ví dụ 50%) cho Oracle → mutation sẽ trigger quá thường xuyên, tốn thời gian cho những payload mà WAF vốn đã không chặn.
- **Mục đích:** Scanner chỉ mutate khi BIẾT CHẮC payload sẽ bị WAF chặn.

**Tại sao Evasion Threshold là 50% chứ không phải 75%?**  
- Nếu mutation chỉ giảm confidence từ 90% → 74% (vẫn trên 50%) thì WAF có thể vẫn chặn bằng cơ chế khác (regex, rate limit).
- Mục tiêu là tìm mutation làm model CỰC KỲ không chắc chắn (< 50%), lúc đó mới có ý nghĩa adversarial thật sự.

---

## 4. Thay đổi cụ thể trong `modul1_scanner.py`

### 4.1 — Thêm constants (đã làm)

```python
# Line ~48-49
ORACLE_THRESHOLD = 75.0
EVASION_THRESHOLD = 50.0
```

### 4.2 — Thêm class `PayloadMutator` (sau `VULN_SIGNATURES`, ~line 191)

```python
class PayloadMutator:
    """Tạo biến thể payload bằng cách thay đổi biểu diễn ký tự.
    
    Lưu ý: Các mutation KHÔNG đảm bảo giữ nguyên tính năng tấn công.
    Mục đích là thay đổi biểu diễn để test khả năng nhận diện của model.
    """
    
    STRATEGIES = {
        'case_swap':      _mutate_case_swap,
        'url_encode':     _mutate_url_encode,
        'html_entity':    _mutate_html_entity,
        'sql_comment':    _mutate_sql_comment,
        'whitespace':     _mutate_whitespace,
        'concat_split':   _mutate_concat_split,
    }
    
    # Risky mutations — có thể gây HTTP error, test riêng trước
    RISKY_STRATEGIES = {
        'double_encode':  _mutate_double_encode,
        'null_byte':      _mutate_null_byte,
    }
```

**6 mutations chính (safe):**

| Strategy | Ví dụ | Áp dụng cho |
|----------|-------|-------------|
| `case_swap` | `<ScRiPt>` thay `<script>` | XSS, SQLi |
| `url_encode` | `%27` thay `'` | Tất cả |
| `html_entity` | `&#60;script&#62;` thay `<script>` | XSS |
| `sql_comment` | `UN/**/ION SE/**/LECT` | SQLi |
| `whitespace` | Tab/newline thay space | SQLi, CMDi |
| `concat_split` | `CHAR(39)` thay `'` | SQLi |

**2 mutations risky (mặc định tắt):**

| Strategy | Ví dụ | Rủi ro |
|----------|-------|--------|
| `double_encode` | `%2527` thay `%27` | Có thể gây HTTP 400 |
| `null_byte` | `pay%00load` | Có thể gây crash |

### 4.3 — Mở rộng class `AIEngine` (~line 222)

Thêm 2 method:

```python
def classify_batch(self, payloads):
    """Phân loại batch payload offline (nhanh hơn 10-50x).
    Returns: list of (label, confidence)
    """
    seqs = self.tokenizer.texts_to_sequences([str(p) for p in payloads])
    pads = pad_sequences(seqs, maxlen=MAX_LEN, padding='post', truncating='post')
    preds = self.model.predict(pads, verbose=0)
    results = []
    for pred in preds:
        idx = np.argmax(pred)
        label = self.label_encoder.inverse_transform([idx])[0]
        conf = float(pred[idx]) * 100
        results.append((label, conf))
    return results

def is_detected(self, payload):
    """Hỏi model: payload này có bị detect không?
    Returns: (bool detected, str label, float confidence)
    """
    label, conf = self.classify(payload)
    detected = (label != 'Normal' and conf >= ORACLE_THRESHOLD)
    return detected, label, conf
```

### 4.4 — Rewrite `run_attacks()` (~line 635)

Flow mới:

```python
def run_attacks(self):
    # Khởi tạo PayloadMutator
    mutator = PayloadMutator()
    
    # Stats cho adversarial analysis
    self.adv_stats = {
        'total_original': 0,
        'model_detected': 0,
        'mutations_tried': 0,
        'evasions_found': 0,
        'mutation_effectiveness': {},  # strategy → số lần giảm conf
    }
    
    for ep in self.endpoints:
        for attack_type, payloads in self._attack_payloads.items():
            for payload in payloads:
                self.adv_stats['total_original'] += 1
                
                # === STEP 1: Oracle check ===
                detected, orig_label, orig_conf = self.ai.is_detected(payload)
                
                best_payload = payload
                best_conf = orig_conf
                best_strategy = 'original'
                model_evaded = False
                
                if detected:
                    self.adv_stats['model_detected'] += 1
                    
                    # === STEP 2: Generate mutations ===
                    mutations = mutator.mutate_all(payload)
                    self.adv_stats['mutations_tried'] += len(mutations)
                    
                    # === STEP 3: Batch oracle check ===
                    if mutations:
                        batch_results = self.ai.classify_batch(
                            [m['payload'] for m in mutations]
                        )
                        
                        # === STEP 4: Pick best evasive ===
                        for i, (mut_label, mut_conf) in enumerate(batch_results):
                            strategy = mutations[i]['strategy']
                            if mut_conf < best_conf:
                                # Track effectiveness
                                self.adv_stats['mutation_effectiveness'].setdefault(strategy, 0)
                                self.adv_stats['mutation_effectiveness'][strategy] += 1
                                
                                best_payload = mutations[i]['payload']
                                best_conf = mut_conf
                                best_strategy = strategy
                        
                        if best_conf < EVASION_THRESHOLD:
                            model_evaded = True
                            self.adv_stats['evasions_found'] += 1
                
                # === STEP 5: Fire vào target ===
                # Bắn payload gốc
                result = self.attack_endpoint(ep, attack_type, payload)
                result['original_confidence'] = orig_conf
                
                # Nếu có mutation tốt hơn → bắn thêm
                if best_strategy != 'original':
                    evasive_result = self.attack_endpoint(ep, attack_type, best_payload)
                    evasive_result['mutation_strategy'] = best_strategy
                    evasive_result['original_confidence'] = orig_conf
                    evasive_result['evasive_confidence'] = best_conf
                    evasive_result['model_evaded'] = model_evaded
                    
                    # Xác định waf_blocked dựa trên status code
                    waf_blocked = (evasive_result.get('status_code') == 403)
                    evasive_result['waf_blocked'] = waf_blocked
                    
                    # === LOG 4 trạng thái ===
                    if model_evaded and not waf_blocked:
                        # FULL BYPASS — insight quan trọng nhất
                        print(f"    🔥 BYPASS [{strategy}] conf {orig_conf:.0f}%→{best_conf:.0f}%")
                    elif model_evaded and waf_blocked:
                        # Model yếu nhưng WAF có rule phụ
                        print(f"    ⚡ MODEL WEAK [{strategy}] evaded model but WAF caught it")
```

### 4.5 — Thêm Adversarial Analysis vào `print_report()` (~line 672)

Thêm section sau phần lỗ hổng:

```
═══ ADVERSARIAL ANALYSIS ═══
  📡 Payloads gốc:        {total_original}
  🔍 Model detected:       {model_detected} ({%})
  🧬 Mutations thử:        {mutations_tried}
  💀 Evasions thành công:   {evasions_found} ({%})
  
  🏆 Top Mutation Strategies:
     1. case_swap:    12 lần hiệu quả
     2. url_encode:    8 lần hiệu quả
     3. sql_comment:   5 lần hiệu quả
  
  📊 Model Robustness: {100 - evasion%}%
  
  ⚠️  INSIGHT:
     • model_evaded + waf_blocked:  {N} (Model có điểm yếu)
     • model_evaded + waf_passed:   {N} (⚠️  BYPASS HOÀN TOÀN)
```

### 4.6 — Cập nhật `save_report()` JSON và MD

Thêm key `adversarial_analysis` vào JSON report:

```json
{
  "adversarial_analysis": {
    "total_original_payloads": 240,
    "model_detected_count": 228,
    "mutations_attempted": 1368,
    "evasions_found": 15,
    "model_robustness_pct": 93.4,
    "mutation_effectiveness": {
      "case_swap": 12,
      "url_encode": 8
    },
    "insight_breakdown": {
      "model_evaded_waf_blocked": 10,
      "model_evaded_waf_passed": 5
    }
  }
}
```

---

## 5. Thay đổi trong `README.md`

Viết lại hoàn chỉnh với:

1. **Giới thiệu dự án** — AI Security WAF + Active Scanner
2. **Kiến trúc hệ thống** — Mermaid diagram
3. **Số liệu model:**
   - 65,643 mẫu training, 13 nhãn
   - Test accuracy: 97.43%, Test loss: 0.0858
   - Proper train/val/test split (70/15/15)
4. **Sơ đồ Adversarial Feedback Loop** — ASCII art (như section 2 trên)
5. **Hướng dẫn sử dụng** — Module 1, 2, webtest
6. **Kết quả test tích hợp** — Bảng so sánh có/không WAF

**Quy tắc docs:**
- KHÔNG claim "giữ nguyên tính năng tấn công" → chỉ nói "thay đổi biểu diễn ký tự"
- Giải thích rõ threshold design (mục 3 ở trên)
- Phân biệt 4 trạng thái log (mục 4.4)

---

## 6. Files KHÔNG thay đổi

| File | Lý do |
|------|-------|
| `projectai.ipynb` | Tokenizer đã save, model OK |
| `modul2_waf.py` | WAF giữ nguyên logic, không sửa |
| `webtest.py` | Vulnerable testbed giữ nguyên |
| `model/*` | Model files giữ nguyên |

---

## 7. Thứ tự thực hiện

```
1. PayloadMutator class          ← Code mutation engine
2. AIEngine.classify_batch()     ← Batch predict
3. AIEngine.is_detected()        ← Oracle wrapper  
4. run_attacks() rewrite         ← Adversarial loop
5. print_report() update         ← Terminal report
6. save_report() update          ← JSON + MD report
7. README.md rewrite             ← Documentation
8. Test thử: scanner vs webtest  ← Verify
9. Test thử: scanner vs WAF      ← Verify insight
10. Git commit + push            ← Deploy
```

---

## 8. Rủi ro và mitigation

| Rủi ro | Mitigation |
|--------|-----------|
| Double encode gây HTTP error | Để riêng trong `RISKY_STRATEGIES`, mặc định tắt |
| Null byte gây crash webtest  | Để riêng trong `RISKY_STRATEGIES`, mặc định tắt |
| Batch predict tốn RAM | Giới hạn batch size = 8 mutations/payload |
| Mutation quá chậm | Mutation là string ops thuần → microseconds |
| Model predict chậm | Batch predict 8 items = ~1 lần predict đơn lẻ |
