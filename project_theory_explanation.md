# Giai thich toan bo project `ai_security` (bo qua phan keylogger)

Tai lieu nay mo ta toan bo project theo goc nhin kien truc, nguyen ly ly thuyet va luong hoat dong giua cac thanh phan. Pham vi co chu y bo qua file `keylogger_payload.js` va cac phan lien quan den no.

## 1. Muc tieu cua project

Project `ai_security` ket hop 3 lop chuc nang chinh:

1. Mot bo sinh du lieu va model AI de nhan dien payload web dang nghi.
2. Mot scanner chu dong de thu nghiem va danh gia bieu hien bao mat cua mot web app.
3. Mot lop AI-WAF dong vai tro proxy, kiem tra request truoc khi cho di vao ung dung dich.

Ve ban chat, day la mot he thong "scan + phan loai + chan loc":

- `Module 1` thu dong tac kiem thu tren muc tieu.
- `Module 2` danh gia du lieu dau vao theo thoi gian thuc.
- `UI HTML` cho phep quan sat va kich hoat scanner.
- `Notebook + data + model` cung cap nen tang hoc may cho hai module chinh.

## 2. Buc tranh kien truc tong the

Neu dien dat ngan gon, project co 5 tang:

### 2.1. Tang du lieu

Thu muc `data/` chua bo payload duoc gan nhan theo nhieu nhom nhu SQLi, XSS, command injection, path traversal, SSRF...

Vai tro cua tang nay:

- cung cap du lieu huan luyen
- cung cap ngu canh cho phan loai
- giup scanner co tap payload mau de so doi response

### 2.2. Tang huan luyen mo hinh

File `projectai.ipynb` la noi thu nghiem va huan luyen model. Dau ra cua qua trinh nay nam trong thu muc `model/`, gom:

- `deep_learning_agent_core.keras`
- `tokenizer.pkl`
- `label_encoder.pkl`

Tang nay bien du lieu text payload thanh mot mo hinh co kha nang du doan loai tan cong hoac muc do bat thuong.

### 2.3. Tang scanner chu dong

File `modul1_scanner.py` dong vai tro scanner. Ve ly thuyet, no:

- tim form va endpoint dau vao
- thu dua cac payload vao cac diem nhap
- phan tich response de tim dau vet bat thuong
- ket hop AI classification va rule-based signatures
- xuat ket qua ra console, JSON, Markdown, hoac API cho UI

### 2.4. Tang WAF/proxy

File `modul2_waf.py` la lop bao ve runtime. No nhan request truoc backend, quet payload bang model AI, roi:

- cho qua neu duoc xem la binh thuong
- ghi log neu dang nghi
- chan neu vuot nguong confidence

Ve y tuong, day la mot reverse proxy co chen lop phan tich thong minh.

### 2.5. Tang giao dien

File `ai_waf_scanner.html` la dashboard phia client. No goi API cua `modul1_scanner.py` o che do server de:

- check health
- bat dau scan
- hien endpoint da tim thay
- hien score va nhom van de
- luu lich su scan trong `localStorage`

## 3. Vai tro tung file chinh

### 3.1. `modul1_scanner.py`

Day la file trung tam cho phan active scanning. Cac khoi logic chinh:

- `FormParser`: dung `HTMLParser` de doc HTML va trich xuat form, input, va mot so link co query string.
- `ATTACK_PAYLOADS`: tap payload chia theo loai tan cong.
- `VULN_SIGNATURES`: tap mau regex de tim dau hieu response cho thay co van de.
- `AIEngine`: load model, tokenizer, label encoder, sau do phan loai payload.
- `VulnerabilityScanner`: ket hop crawl, attack, AI classification, rule matching, report generation.
- `create_api_server()`: mo scanner thanh mot web service de frontend goi.

No co 2 cach chay:

- CLI mode: quet truc tiep tu terminal.
- Server mode: mo Flask API tren port rieng de HTML dashboard su dung.

### 3.2. `modul2_waf.py`

Day la module "shield". No dung Flask de dung truoc mot web backend. Cac khoi chinh:

- `PayloadCache`: cache theo hash de tranh phai infer cung mot payload nhieu lan.
- `scan_payload()`: chay model AI va tra ve nhan + do tin cay.
- `security_filter()`: middleware quet request truoc khi proxy.
- `/ai-waf/health` va `/ai-waf/stats`: endpoint monitoring.
- `proxy()`: chuyen tiep request den backend that.

Ve kien truc, `modul2_waf.py` khong tu tao app business logic; no bao quanh app khac va lam lop loc.

### 3.3. `ai_waf_scanner.html`

Day la dashboard scan, khong phai trang duoc bao ve. JavaScript ben trong file nay chu yeu:

- goi `GET /api/health` de biet scanner server co song hay khong
- goi `POST /api/scan` de kick off mot dot scan
- render endpoint list
- render score ring, thong ke, danh sach van de
- luu lich su scan vao local storage cua browser

Nghia la frontend nay dong vai tro "operator console".

### 3.4. `webtest.py`

File nay la mot web app test co chu dich de tao moi truong mo phong cho scanner/WAF. Ve mat ly thuyet, no dong vai tro:

- he thong dich de scanner thu nghiem
- bo testbed minh hoa cho cac nhom loi web pho bien
- cach de kiem tra xem WAF co can thiep dung luong hay khong

No phoi hop voi scanner de tao mot vong lap "tao input kiem thu -> quan sat phan ung".

### 3.5. `projectai.ipynb`

Notebook nay giai quyet lop "tai sao model co mat trong project". No la noi:

- nap va hop nhat nhieu nguon du lieu
- lam sach va can bang nhan
- tokenizer text
- chia tap train/test
- huan luyen mang Bi-LSTM
- luu ra model artifacts cho module scanner/WAF su dung lai

### 3.6. `model/`

Thu muc nay la cau noi giua notebook huan luyen va runtime:

- `.keras` chua trong so va cau truc model
- `tokenizer.pkl` quyet dinh cach text duoc doi thanh sequence
- `label_encoder.pkl` anh xa chi so thanh ten nhan

Neu thieu mot trong cac file nay, runtime AI se mat dong bo voi qua trinh train.

### 3.7. `data/`

Thu muc nay chua:

- dataset payload
- script tai du lieu
- ghi chu ve nguon du lieu

No la lop "nguon goc" de project co tri thuc domain.

### 3.8. `WORKFLOW.md`, `SCANNER_ENHANCEMENT.md`, `nhat_ky_phat_trien.md`

Nhom file nay dong vai tro tai lieu noi bo:

- `WORKFLOW.md`: giai thich vong doi he thong.
- `SCANNER_ENHANCEMENT.md`: dinh huong mo rong scanner.
- `nhat_ky_phat_trien.md`: ghi lai qua trinh xay dung.

## 4. Nguyen ly ly thuyet cua tung lop

## 4.1. Nguyen ly cua lop AI

Project dang xem payload web nhu mot bai toan phan loai chuoi ky tu.

Luong ly thuyet co ban:

1. Payload text duoc tokenizer bien thanh day so.
2. Day so duoc padding/truncation ve cung do dai `MAX_LEN`.
3. Model Bi-LSTM doc chuoi theo ngu canh hai chieu.
4. Dau ra la xac suat cho tung nhan.
5. Nhan co xac suat cao nhat duoc chon lam ket qua.

Y nghia cua cach nay:

- khong can phu thuoc hoan toan vao regex co dinh
- co the hoc duoc mau ky tu va cau truc payload
- co the tong quat hoa tot hon voi bien the moi

Tuy nhien, AI khong tu dong "hieu" logic ung dung. No chi hoc mau tu chuoi dau vao.

## 4.2. Nguyen ly cua scanner chu dong

Scanner cua project duoc xay tren y tuong active testing:

1. Tim cac diem nhap lieu.
2. Dua payload mau vao cac diem do.
3. Quan sat response.
4. So khop response voi dau hieu da biet.
5. Tong hop thanh finding.

No ket hop 2 cach suy luan:

- rule-based: dua vao signature, regex, keyword
- AI-based: dua vao xac suat phan loai payload

Scanner khong "xac nhan chan chan" moi lo hong theo nghia exploit den cung. No suy ra kha nang ton tai van de dua tren dau vet response va hanh vi he thong.

## 4.3. Nguyen ly cua WAF proxy

Module 2 van hanh theo chuoi:

1. Request di vao Flask app.
2. `before_request` thu thap query params, JSON body, form body.
3. Tung payload duoc dua qua AI engine.
4. Ket qua duoc so voi `THRESHOLD`.
5. Neu nguy co cao thi tra 403.
6. Neu hop le thi request duoc proxy tiep sang backend that.

Day la mo hinh "inline inspection". Uu diem:

- quyet dinh xay ra truoc backend
- co the log tat ca quyet dinh
- co the bo sung cache de giam do tre

Han che:

- chi thay duoc nhung gi nam trong cac truong ma no thu thap
- de false positive/false negative neu model chua du tot
- khong thay the duoc validation o backend

## 4.4. Nguyen ly cua dashboard

Dashboard khong tu scan tren browser. No chi la lop dieu khien:

- nhan URL muc tieu tu nguoi dung
- goi API scanner
- hien ket qua theo cach de doc

No tach giao dien khoi logic scanner, giup:

- de demo
- de thao tac voi nguoi khong quen CLI
- de xem lich su scan nhanh

## 5. Luong du lieu tu dau den cuoi

Day la luong du lieu tong quat cua project:

### 5.1. Luong offline

1. Dataset duoc dat trong `data/`.
2. Notebook nap va tien xu ly du lieu.
3. Model duoc huan luyen.
4. Artifacts duoc luu trong `model/`.

Day la luong "xay nao AI".

### 5.2. Luong scan

1. Nguoi dung nhap target trong dashboard hoac CLI.
2. `modul1_scanner.py` crawl target.
3. Scanner tim form/input/link co tham so.
4. Scanner dua payload vao tung diem nhap.
5. Response duoc phan tich bang signatures.
6. Payload cung duoc AI classify de bo sung thong tin.
7. Ket qua duoc tong hop thanh score va nhom van de.
8. Bao cao co the duoc luu thanh JSON/Markdown.

### 5.3. Luong WAF runtime

1. Client gui request toi WAF.
2. WAF trich xuat input co y nghia.
3. AI infer nhanh tren payload.
4. Neu diem nguy co vuot nguong thi chan.
5. Neu khong thi WAF proxy request toi web app that.
6. Logging va stats duoc cap nhat.

## 6. Cach cac module lien ket voi nhau

Project co tinh chat modul hoa tuong doi ro:

- `projectai.ipynb` tao ra artifacts cho `modul1_scanner.py` va `modul2_waf.py`.
- `modul1_scanner.py` co the chay doc lap, nhung khi bat server mode no tro thanh backend cho `ai_waf_scanner.html`.
- `webtest.py` cung cap mot target de `modul1_scanner.py` kiem thu.
- `modul2_waf.py` co the dat truoc `webtest.py` hoac mot backend khac de thu nghiem kha nang chan request.

Noi cach khac:

- Notebook tao tri thuc
- Scanner dung tri thuc de thu nghiem
- WAF dung tri thuc de phong thu
- UI giup quan sat va dieu khien

## 7. Cac diem thiet ke dang chu y

### 7.1. Ket hop AI va rule-based

Day la mot diem manh ve mat y tuong. AI giup tong quat hoa mau input, con rule-based giup tim bang chung cu the trong response. Hai lop nay bo sung cho nhau:

- AI tot cho phan loai dau vao
- rule-based tot cho phan tich dau ra

### 7.2. Tach scanner va WAF thanh 2 module

Scanner va WAF giai quyet hai bai toan khac nhau:

- scanner: danh gia chu dong
- WAF: phong thu thoi gian thuc

Tach rieng nhu vay giup code ro vai tro hon.

### 7.3. Co kha nang demo end-to-end

Project co du cac thanh phan de demo tu dau den cuoi:

- testbed
- scanner
- AI model
- WAF
- dashboard
- report

Day la gia tri rat lon ve mat hoc tap va trinh bay de tai.

## 8. Gioi han ly thuyet cua project

De hieu dung project, can biet cac gioi han sau:

### 8.1. Model phu thuoc manh vao du lieu train

Neu dataset thien lech, lap, gan nhan chua tot, hoac khong dai dien cho traffic that, model se kho tong quat hoa.

### 8.2. Scanner phu thuoc vao kha nang quan sat response

Nhieu lo hong khong lo bang dau vet ro rang trong response, nen rule-based detection co the bo sot.

### 8.3. WAF khong thay the secure coding

Du WAF co chan tot den dau, validation, escaping, parameterization va authorization trong backend van la lop phong thu can ban.

### 8.4. UI chi la bo dieu khien

Dashboard khong phai noi sinh ra tri tue bao mat. Toan bo logic that nam o Python backend va artifacts model.

## 9. Cach nen hieu project nay ve mat hoc thuat

Neu bo qua cac chi tiet trien khai, project nay la mot bai toan "ung dung ML vao AppSec" gom 3 cau hoi:

1. Co the huan luyen model de nhan dien payload web doc hai tu text hay khong?
2. Co the dung model do de ho tro scanner chu dong hay khong?
3. Co the dat model vao duong di request de lam mot lop chan loc runtime hay khong?

Toan bo repo la mot cau tra loi thuc nghiem cho 3 cau hoi do.

## 10. Ket luan

Sau khi bo phan keylogger ra khoi pham vi, phan con lai cua project co the duoc hieu nhu sau:

- `projectai.ipynb` va `data/` tao nen "nen tri thuc"
- `model/` la dong goi cua tri thuc da hoc
- `modul1_scanner.py` la bo may danh gia chu dong
- `modul2_waf.py` la lop phong thu runtime
- `ai_waf_scanner.html` la giao dien van hanh
- `webtest.py` la moi truong dich de trinh dien va kiem thu

Neu can mo rong tiep, huong tai lieu hop ly nhat la viet them 1 file nua theo mot trong 2 chieu:

- "Kien truc ky thuat chi tiet theo file va ham"
- "Danh gia diem manh, diem yeu, va de xuat cai tien cho toan project"
