# Workflow Cuoi Ky - AI WAF cho Web Truong

## 1. Muc tieu de tai

- Xay dung va demo mot AI WAF prototype co kha nang ung dung vao he thong web thuc te.
- Tich hop Module 2 (M2) vao web truong de bao ve cac API quan trong.
- Chung minh duoc 2 gia tri:
  - Gia tri hoc thuat: ket hop rule-based va AI trong phat hien tan cong web.
  - Gia tri thuc tien: co the dat truoc backend that de loc request doc hai.

## 2. He thong thuc te duoc ap dung

- Du an thuc te: `D:\nghich\webtruong`
- Kien truc hien tai:
  - Frontend: React + Vite
  - Backend: FastAPI
  - API chinh:
    - `/health`
    - `/api/v1/projects/search`
    - `/api/v1/filters/*`
- Muc tieu bao ve truoc mat:
  - API tim kiem
  - API loc du lieu
  - Cac endpoint docs/debug neu co

## 3. Kien truc tich hop de demo

- Mo hinh trien khai:
  - Nguoi dung -> Frontend -> M2 WAF -> Backend FastAPI
- Cach dung trong demo:
  - Frontend khong goi truc tiep backend
  - Frontend goi qua WAF
  - WAF scan request truoc khi forward

## 4. Cong viec can lam

### Giai doan A - Khao sat he thong that

- Doc va liet ke toan bo endpoint backend.
- Xac dinh input nguoi dung co the tac dong:
  - query params
  - JSON body
  - form data
  - headers
  - cookies
- Ghi bang thong ke:
  - endpoint
  - method
  - params
  - chuc nang
  - muc do nhay cam
  - nguy co bao mat

### Giai doan B - Nang cap M2 cho phu hop web truong

- Bo sung scan de quy cho JSON body va payload long nhau.
- Khong bo qua scan chi vi request la asset path neu van co query string.
- Cau hinh hoa:
  - backend target
  - threshold
  - secret header
  - webhook alert
- Bo sung log ro rang:
  - allowed
  - suspicious
  - blocked
- Kiem tra reverse proxy chay on dinh voi FastAPI backend.

### Giai doan C - Tich hop that voi web truong

- Cau hinh frontend goi API qua M2.
- Dat M2 dung truoc backend.
- Kiem tra cac request hop le van chay binh thuong.
- Kiem tra frontend khong bi loi CORS hoac routing khi di qua WAF.

### Giai doan D - Xay dung kich ban demo

- Kich ban 1: request hop le
  - Tim kiem binh thuong
  - Loc du lieu binh thuong
  - Kiem tra response va toc do
- Kich ban 2: request doc hai
  - Thu payload SQLi vao `q`
  - Thu payload XSS vao `q`
  - Thu payload traversal vao query
  - Thu payload nghi ngo SSRF neu co endpoint phu hop
- Kich ban 3: tan cong lap lai
  - Gui nhieu request doc hai lien tuc
  - Kiem tra rate limit
  - Kiem tra blacklist
  - Kiem tra alert
- Kich ban 4: surface exposure
  - Kiem tra `/docs`
  - Kiem tra `/openapi.json`
  - Kiem tra endpoint debug neu co

### Giai doan E - Thu nghiem va ghi nhan ket qua

- Do va so sanh:
  - So request hop le duoc cho qua
  - So request tan cong bi chan
  - Block theo tung loai attack
  - Toc do phan hoi truoc va sau khi co WAF
  - False positive neu co
- Thu bang chung:
  - anh man hinh frontend
  - anh request bi block
  - anh `/ai-waf/stats`
  - log tu `shield_protection.log`
  - log alert neu co

## 5. Pham vi attack uu tien cho demo

- Nhom co dien:
  - SQLi
  - XSS
  - Path Traversal
  - SSRF
  - CSRF
- Nhom gan thuc te hon:
  - API abuse qua query params
  - docs exposure
  - debug exposure
  - rate limit / abuse traffic

## 6. Dau ra can hoan thanh

- M2 chay duoc nhu reverse proxy truoc backend that.
- Frontend web truong goi duoc API qua M2.
- Co it nhat 3 kich ban demo thanh cong:
  - request hop le duoc cho qua
  - request doc hai bi chan
  - spam request bi rate-limit/blacklist
- Co bang thong ke va anh chup man hinh de dua vao bao cao.

## 7. Noi dung dua vao bao cao cuoi ky

### 7.1. Bai toan thuc te

- Web truong can co lop bao ve request doc hai toi backend API.
- Cac tan cong web thong dung van co nguy co xay ra tren cong thong tin hoc thuat.

### 7.2. Giai phap de xuat

- Dat AI WAF truoc backend nhu mot reverse proxy.
- Ket hop 2 lop:
  - Rule-based de chan nhanh
  - AI model de phan loai request nghi ngo

### 7.3. Gia tri thuc tien

- Ung dung truc tiep tren web truong that.
- Co kha nang chan mot so payload tan cong pho bien.
- Co monitoring, blacklist, alert va thong ke van hanh.

### 7.4. Gioi han he thong

- Chua thay the duoc WAF thuong mai.
- Chua bao phu het business logic flaws va zero-day.
- Chua toi uu cho luu luong lon production.

## 8. Ke hoach thuc hien de xuat

### Buoc 1

- Rà soat endpoint backend trong `D:\nghich\webtruong\backend`
- Liet ke bề mặt tấn công

### Buoc 2

- Nang cap M2 de scan tot cho FastAPI/API JSON

### Buoc 3

- Tich hop frontend/backend qua WAF

### Buoc 4

- Chay bo kich ban demo

### Buoc 5

- Thu so lieu, log, screenshot

### Buoc 6

- Viet phan "ung dung thuc te" va "ket qua thu nghiem" trong bao cao

## 9. Tieu chi hoan thanh

- WAF chay on dinh truoc backend that
- Frontend van su dung duoc binh thuong
- Chan duoc cac payload demo da chon
- Co so lieu va bang chung minh hoa
- Co the trinh bay ro rang voi giang vien:
  - He thong lam duoc gi
  - Ung dung vao web truong ra sao
  - Gioi han hien tai la gi

## 10. Mo hinh trien khai cho 2 moi truong demo

### 10.1. Moi truong 1 - Webtest

- Muc dich:
  - Demo tan cong co dien
  - Chung minh M2 chan request doc hai theo thoi gian thuc
- Thanh phan:
  - Backend testbed: `webtest.py`
  - WAF: `modul2_waf.py`
- Port de xuat:
  - `webtest.py` -> `127.0.0.1:5170`
  - `M2` -> `127.0.0.1:5000`
- Luong truy cap:
  - Nguoi dung/attacker -> `http://127.0.0.1:5000` -> `http://127.0.0.1:5170`
- Luu y:
  - Khong demo truy cap truc tiep `5170`
  - Toan bo payload tan cong gui vao `5000`

### 10.2. Moi truong 2 - Web truong

- Muc dich:
  - Chung minh tinh ung dung thuc te
  - Bao ve backend API cua he thong tim kiem NCKH
- Thanh phan:
  - Frontend: React/Vite trong `D:\nghich\webtruong\frontend\vnu-frontend`
  - Backend: FastAPI trong `D:\nghich\webtruong\backend`
  - WAF: `modul2_waf.py`
- Port de xuat:
  - Backend FastAPI -> `127.0.0.1:8000`
  - M2 -> `127.0.0.1:5001`
  - Frontend -> `127.0.0.1:5173`
- Luong truy cap:
  - Frontend -> `http://127.0.0.1:5001` -> `http://127.0.0.1:8000`
- Luu y:
  - Frontend khong goi truc tiep `8000`
  - API base URL trong frontend phai tro den `5001`

## 11. Cach chay cu the cho tung moi truong

### 11.1. Chay webtest + M2

#### Terminal 1

```powershell
cd D:\AI\ai_security
python webtest.py
```

#### Terminal 2

```powershell
cd D:\AI\ai_security
python modul2_waf.py --target http://127.0.0.1:5170 --port 5000
```

#### Test

- Truy cap qua WAF:
  - `http://127.0.0.1:5000`
- Khong su dung `http://127.0.0.1:5170` khi demo bao ve

### 11.2. Chay webtruong + M2

#### Terminal 1 - Backend

```powershell
cd D:\nghich\webtruong\backend
..\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

#### Terminal 2 - WAF

```powershell
cd D:\AI\ai_security
python modul2_waf.py --target http://127.0.0.1:8000 --port 5001
```

#### Terminal 3 - Frontend

```powershell
cd D:\nghich\webtruong\frontend\vnu-frontend
npm run dev
```

#### Frontend can cau hinh

- API base URL phai tro den:
  - `http://127.0.0.1:5001`
- Khong tro thang den:
  - `http://127.0.0.1:8000`

## 12. Thu tu demo de bao ve truoc hoi dong

### Buoc 1 - Gioi thieu kien truc

- Trinh bay so do:
  - Client -> WAF -> Backend
- Noi ro:
  - M2 la lop dung giua, khong phai scanner offline

### Buoc 2 - Demo voi webtest

- Gui request hop le -> duoc cho qua
- Gui payload SQLi/XSS/SSRF... -> bi block
- Mo `/ai-waf/stats` de xem thong ke

### Buoc 3 - Demo voi webtruong

- Mo frontend truong
- Tim kiem binh thuong -> hoat dong
- Thu payload doc vao o tim kiem/query -> M2 chan
- Trinh bay log + stats

### Buoc 4 - Ket luan

- Webtest chung minh kha nang phong thu voi tan cong mau
- Webtruong chung minh tinh ung dung thuc te
- M2 la giai phap generic, doi `target` la dung cho web khac

## 13. Ghi chu quan trong ve tinh thuc te

- M2 co the dung lai cho nhieu website khac nhau.
- Tinh tong quat nam o:
  - reverse proxy
  - engine scan
  - logging / alert / blacklist
- De tranh bypass trong demo:
  - chi su dung port cua WAF
  - backend chi nen bind `127.0.0.1`
- Neu trien khai thuc te hon nua:
  - backend se khong public ra ngoai
  - chi WAF duoc expose
