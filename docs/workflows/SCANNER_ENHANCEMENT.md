# 🔧 Mở rộng Module 1 Scanner - Thêm hỗ trợ API vào modul1_scanner.py

## 📋 Tóm tắt vấn đề

Hiện tại, Module 1 Scanner chỉ có thể quét các trang HTML **tĩnh** với `<form>` tags truyền thống. 

**Vấn đề:** Frontend SPA (React/Vue/Angular) + Backend API (FastAPI/Node/Django) không có form HTML tĩnh → Scanner không phát hiện được endpoints.

---

## ✅ Giải pháp: Thêm API Scanner vào modul1_scanner.py

**Lợi ích của cách này:**
- ✅ Không tạo file mới phức tạp
- ✅ Giữ nguyên chức năng HTML cũ 100%
- ✅ Dùng chung giao diện web hiện tại
- ✅ Tổ chức code tốt hơn bằng class riêng
- ✅ Dễ debug vì tất cả ở 1 file

---

## 🚀 Hướng dẫn triển khai

### **Bước 1: Thêm class APIScanner vào modul1_scanner.py**

Mở file `modul1_scanner.py` và thêm code dưới (trước class `VulnerabilityScanner`)

**Thêm code này vào modul1_scanner.py (trước định nghĩa `VulnerabilityScanner`):**

```python
# ===== API SCANNER (NEW) =====
class APIScanner:
    """Quét REST API endpoints từ OpenAPI/Swagger docs"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AI-SecurityScanner/1.0 (Module1-API)'
        })
        self.endpoints = []
        self.vulnerabilities = []
        
    def discover_from_swagger(self, doc_path: str = "/openapi.json") -> bool:
        """Tìm endpoints từ OpenAPI/Swagger"""
        try:
            urls_to_try = [
                f"{self.base_url}{doc_path}",
                f"{self.base_url}/openapi.json",
                f"{self.base_url}/docs/openapi.json",
            ]
            
            for url in urls_to_try:
                try:
                    resp = self.session.get(url, timeout=5)
                    if resp.status_code == 200 and 'json' in resp.headers.get('content-type', ''):
                        data = resp.json()
                        self._parse_openapi(data)
                        return True
                except:
                    continue
            return False
        except Exception as e:
            logger.warning(f"⚠️ Không tìm được OpenAPI: {e}")
            return False
    
    def _parse_openapi(self, doc: dict):
        """Parse OpenAPI 3.0 specification"""
        paths = doc.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method not in ['get', 'post', 'put', 'delete', 'patch']:
                    continue
                
                params = details.get('parameters', [])
                for param in params:
                    self.endpoints.append({
                        'url': urljoin(self.base_url, path),
                        'method': method.upper(),
                        'param': param.get('name', ''),
                        'param_in': param.get('in', 'query'),
                        'source': 'swagger'
                    })
                
                # Request body params
                if details.get('requestBody'):
                    self.endpoints.append({
                        'url': urljoin(self.base_url, path),
                        'method': method.upper(),
                        'param': 'body',
                        'param_in': 'body',
                        'source': 'swagger'
                    })
    
    def attack_endpoint(self, endpoint: dict, payload: str, attack_type: str):
        """Gửi payload vào API endpoint"""
        try:
            url = endpoint['url']
            method = endpoint['method']
            param = endpoint['param']
            param_in = endpoint['param_in']
            
            if param_in == 'query':
                resp = self.session.request(method, url, params={param: payload}, timeout=5)
            elif param_in == 'body':
                resp = self.session.request(method, url, json={'query': payload}, timeout=5)
            else:
                resp = self.session.request(method, url, timeout=5)
            
            # Phát hiện lỗ hổng
            is_vuln = self._check_vulnerability(resp, payload, attack_type)
            
            result = {
                'endpoint': url,
                'method': method,
                'param': param,
                'attack_type': attack_type,
                'payload': payload,
                'status_code': resp.status_code,
                'is_vulnerable': is_vuln,
                'evidence': [] if not is_vuln else ['API Response contains vulnerability signature']
            }
            
            if is_vuln:
                self.vulnerabilities.append(result)
            
            return result
        except Exception as e:
            return None
    
    def _check_vulnerability(self, resp, payload, attack_type) -> bool:
        """Kiểm tra xem response có dấu hiệu lỗ hổng"""
        text = resp.text.lower()
        
        if attack_type == "SQLi":
            return any(sig in text for sig in ['syntax error', 'mysql_fetch', 'ora-', 'postgres', 'sql'])
        elif attack_type == "XSS":
            return payload in resp.text and '<script>' in text
        elif attack_type == "Command Injection":
            return any(sig in text for sig in ['root:', 'uid=', 'drwx'])
        
        return False
```

---

### **Bước 2: Cập nhật hàm `create_api_server()` trong modul1_scanner.py**

Thêm route mới cho API mode (ngay dưới route `/api/health`):

```python
    @api.route('/api/scan', methods=['POST'])
    def api_scan():
        """API scan — nhận target URL, chọn mode (HTML hoặc API)"""
        data = flask_request.get_json()
        if not data or 'target' not in data:
            return jsonify({'error': 'Thiếu trường "target" trong request body'}), 400

        target_url = data['target'].strip()
        scan_mode = data.get('mode', 'html')  # html hoặc api
        api_doc_path = data.get('api_doc_path', '/openapi.json')
        
        if not target_url.startswith('http'):
            target_url = 'http://' + target_url

        logger.info(f"🗡️ Scan requested: {target_url} (mode: {scan_mode})")

        try:
            if scan_mode == 'api':
                # ===== Mode API =====
                scanner = APIScanner(target_url)
                scanner.start_time = time.time()
                
                # Discover endpoints từ Swagger
                if scanner.discover_from_swagger(api_doc_path):
                    logger.info(f"✅ Tìm được {len(scanner.endpoints)} API endpoints")
                else:
                    return jsonify({'error': 'Không tìm được OpenAPI docs. Kiểm tra URL và doc path.'}), 400
                
                # Attack via API
                for ep in scanner.endpoints[:10]:  # Giới hạn 10 endpoints
                    for attack_type, payloads in ATTACK_PAYLOADS.items():
                        for payload in payloads[:3]:  # Giới hạn 3 payloads mỗi loại
                            scanner.attack_endpoint(ep, payload, attack_type)
                
                scanner.end_time = time.time()
                duration = scanner.end_time - scanner.start_time
                
                # Build response
                vuln_by_type = {}
                for v in scanner.vulnerabilities:
                    t = v['attack_type']
                    if t not in vuln_by_type:
                        vuln_by_type[t] = []
                    vuln_by_type[t].append(v)
                
                result = {
                    'target': target_url,
                    'mode': 'api',
                    'duration': round(duration, 1),
                    'total_endpoints': len(scanner.endpoints),
                    'total_vulnerabilities': len(scanner.vulnerabilities),
                    'endpoints': scanner.endpoints,
                    'vulnerabilities_by_type': {},
                }
                
                for attack_type, vulns in vuln_by_type.items():
                    result['vulnerabilities_by_type'][attack_type] = {
                        'severity': 'HIGH',
                        'count': len(vulns),
                        'samples': [{'payload': v['payload']} for v in vulns[:3]]
                    }
                
                return jsonify(result)
            
            else:
                # ===== Mode HTML (cũ) - Giữ nguyên logic cũ =====
                scanner = VulnerabilityScanner(target_url)
                # ... (giữ toàn bộ logic cũ của HTML mode)
                
        except Exception as e:
            import traceback
            logger.error(f"❌ Exception in /api/scan: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'error': f'Internal server error: {str(e)}',
                'details': traceback.format_exc()
            }), 500
```

---

---

### **Bước 3: Cập nhật `ai_waf_scanner.html` - Thêm UI cho API mode**

**Tìm section "Scan Input" trong HTML và thêm mode selector:**

```html
<!-- Tìm cái này: -->
<label>
    <span class="label-dot"></span>
    Nhập URL Mục Tiêu
</label>

<!-- Thêm TRƯỚC nó: -->
<div style="margin-bottom: 16px;">
    <label style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
        <span style="font-weight: 600; color: var(--text-secondary);">Chế độ quét:</span>
    </label>
    <div style="display: flex; gap: 12px; margin-bottom: 16px;">
        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
            <input type="radio" name="scanMode" value="html" checked style="cursor: pointer;">
            <span style="font-size: 13px; color: var(--text-primary);">HTML Form Scanner</span>
        </label>
        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
            <input type="radio" name="scanMode" value="api" style="cursor: pointer;">
            <span style="font-size: 13px; color: var(--accent-light);">🆕 REST API Scanner</span>
        </label>
    </div>
    
    <!-- Input cho API doc path -->
    <div id="apiDocPathBox" style="display: none; margin-bottom: 12px;">
        <label style="display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 6px;">
            API Doc Path (ví dụ: /openapi.json)
        </label>
        <input type="text" id="apiDocPath" placeholder="/openapi.json" 
               style="width: 100%; padding: 10px; border: 1px solid var(--border); 
                      border-radius: 6px; background: var(--bg-input); color: var(--text-primary);">
    </div>
</div>

<!-- Thêm script để hiện/ẩn API doc input -->
<script>
document.querySelectorAll('input[name="scanMode"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
        document.getElementById('apiDocPathBox').style.display = 
            e.target.value === 'api' ? 'block' : 'none';
    });
});
</script>
```

**Cập nhật function `startScan()` trong JavaScript:**

Tìm cái này:
```javascript
async function startScan() {
    const targetUrl = document.getElementById('targetUrl').value.trim();
    if (!targetUrl) { alert('Vui lòng nhập URL mục tiêu!'); return; }
```

Sửa thành:
```javascript
async function startScan() {
    const targetUrl = document.getElementById('targetUrl').value.trim();
    const scanMode = document.querySelector('input[name="scanMode"]:checked').value;
    
    if (!targetUrl) { alert('Vui lòng nhập URL mục tiêu!'); return; }
    
    // Prepare request body
    const requestBody = { target: targetUrl, mode: scanMode };
    
    if (scanMode === 'api') {
        const docPath = document.getElementById('apiDocPath').value || '/openapi.json';
        requestBody.api_doc_path = docPath;
    }
    
    // ... (giữ nguyên phần còn lại, chỉ thay body)
    try {
        const resp = await fetch(`${API}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)  // ← Thay vì chỉ { target: targetUrl }
        });
        
        // ... (phần còn lại giữ nguyên)
```

Trước khi chạy, test xem chưa lỗi:
```bash
# Check syntax
python -m py_compile modul1_scanner.py

# Chạy test
python modul1_scanner.py --server
# Vào http://127.0.0.1:5001
# Thử quét HTML mode trước (chế độ cũ)
```

---

## 🎯 Sử dụng cho project của bạn

**Sau khi sửa cài đặt xong, test với backend FastAPI:**

1. **Bước 1:** Chạy backend
```bash
cd D:\nghich\webtruong\backend
# Nếu dùng Python:
python main.py
# Hoặc FastAPI:
uvicorn app.main:app --reload --port 8000
```

2. **Bước 2:** Chạy scanner server
```bash
cd D:\AI\ai_security
python modul1_scanner.py --server
```

3. **Bước 3:** Vào giao diện
```
http://127.0.0.1:5001
```

4. **Bước 4:** Quét API
- Nhập URL: `http://localhost:8000`
- Chọn radio: **API (OpenAPI/Swagger)**
- Nhập API Doc Path: `/openapi.json`
- Bấm "Bắt đầu quét"

---

## ✨ Lợi ích của cách này

✅ **Không tạo file mới** - giảm complexity  
✅ **Giữ nguyên chức năng HTML 100%** - không ảnh hưởng logic cũ  
✅ **Dùng chung giao diện web** - UX nhất quán  
✅ **Dễ debug** - tất cả ở 1 file, 1 server  
✅ **Dễ maintain** - chỉ sửa 2 file (modul1_scanner.py + ai_waf_scanner.html)  
✅ **Có thể chuyển sang Mode + endpoint nhanh**

---

## 📝 Các file cần sửa

| File | Thay đổi |
|------|---------|
| `modul1_scanner.py` | Thêm class APIScanner + route /api/scan |
| `ai_waf_scanner.html` | Thêm mode radio buttons + API doc input |

**Tất cả đều là added code - không xoá code cũ!**

---

## 🛡️ An toàn đảm bảo

✅ Logic HTML cũ hoàn toàn được giữ nguyên  
✅ API mode là code mới, không liên quan đến HTML mode  
✅ Nếu có lỗi, có thể tắt mode API qua comment code  
✅ Có exception handling bao toàn bộ

---

## 🚀 Bước tiếp theo

1. ✅ Sửa `modul1_scanner.py` - thêm class APIScanner
2. ✅ Sửa `modul1_scanner.py` - cập nhật route /api/scan
3. ✅ Sửa `ai_waf_scanner.html` - thêm mode selector
4. ✅ Test HTML mode trước (chế độ cũ)
5. ✅ Test API mode (chế độ mới)
6. ✅ Quét backend FastAPI của bạn

**Happy scanning! 🎯**
