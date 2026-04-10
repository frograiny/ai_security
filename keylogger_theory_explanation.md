# Giai thich ly thuyet ve co che hoat dong cua `keylogger_payload.js`

Tai lieu nay giai thich o muc do phong thu va hoc thuat: no mo ta doan ma dang lam gi, vi sao no hoat dong duoc trong trinh duyet, cac rui ro bao mat, va cach nhan biet. Tai lieu khong huong dan trien khai, phat tan, ne tranh phat hien, hay cai tien payload.

## 1. Tong quan

File `keylogger_payload.js` la mot doan JavaScript ngan chay trong boi canh trinh duyet. Ve ban chat, no:

1. Dang ky mot bo lang nghe su kien ban phim tren `document`.
2. Moi khi nguoi dung nhan phim, no lay gia tri phim vua nhan.
3. Tao mot HTTP request de gui gia tri do den mot dich vu khac.

Neu nhin duoi goc do phong thu, day la mo hinh thu thap input tu ban phim o phia client, roi chuyen du lieu ra ngoai thong qua mang.

## 2. Cac thanh phan chinh trong doan ma

Doan ma co the duoc tach thanh 4 thanh phan:

### 2.1. Dang ky su kien

`document.addEventListener('keydown', ...)`

Trinh duyet cung cap he thong event theo mo hinh event-driven. `document` la doi tuong dai dien cho toan bo tai lieu HTML hien tai. Khi goi `addEventListener`, ma JavaScript yeu cau trinh duyet:

- Theo doi su kien co ten `keydown`
- Moi khi su kien xay ra, thuc thi ham callback di kem

`keydown` xay ra khi nguoi dung bam mot phim xuong. Day la ly do doan ma co the "nghe" duoc thao tac go ban phim.

### 2.2. Thu thong tin tu event object

Trong callback, tham so `e` la event object. Thuoc tinh `e.key` la bieu dien muc cao cua phim vua bam.

Vi du ve mat ly thuyet:

- Nhan phim chu thi co the thu duoc ky tu tuong ung
- Nhan phim dieu huong thi co the thu duoc ten phim chuc nang
- Nhan phim dac biet thi trinh duyet tra ve nhan biet o dang chuoi

Noi cach khac, event object la cau noi giua thao tac nguoi dung va logic JavaScript.

### 2.3. Truyen du lieu bang `fetch`

Doan ma su dung `fetch(...)` de tao mot HTTP request.

Ve nguyen ly, `fetch` la API bat dong bo cua trinh duyet cho phep JavaScript giao tiep voi:

- may chu cung nguon
- may chu khac nguon, tuy thuoc chinh sach trinh duyet va cau hinh server

Trong doan ma nay, gia tri phim bam duoc chen vao URL query string, roi trinh duyet gui request den mot endpoint khac. Dieu nay bien moi lan bam phim thanh mot lan phat sinh luu luong mang.

### 2.4. Ghi log cuc bo

Lenh `console.log(...)` ve ly thuyet dung de hien thong tin ra developer console. Day la kenh quan sat noi bo cua trang, khong phai kenh luu tru an toan. Trong mau ma nay, dong nay co van de dung sai toan tu, nhung ve mat y tuong no dang co gang in phim vua thu duoc ra console.

## 3. Vi sao doan ma nay hoat dong duoc

Doan ma hoat dong duoc vi ket hop 3 nguyen ly co ban cua web runtime:

### 3.1. JavaScript co the dang ky nghe su kien nguoi dung

Trinh duyet duoc thiet ke de trang web co the phan ung voi thao tac cua nguoi dung, nhu:

- click
- nhap lieu
- submit form
- bam phim

Neu mot script da duoc thuc thi trong trang, no co the gan listener vao cac event nay.

### 3.2. JavaScript co the doc metadata cua su kien

Khi event xay ra, trinh duyet tao event object va truyen vao callback. Script khong can "doc ban phim o cap he dieu hanh"; no chi can su kien duoc trinh duyet phat ra trong pham vi trang dang chay. Day la diem quan trong:

- No khong phai keylogger he thong
- No la co che theo doi input trong boi canh trang web

### 3.3. JavaScript co the phat sinh ket noi mang

Sau khi co du lieu, script su dung API mang nhu `fetch` de gui thong tin di. Neu he thong phong thu khong chan, moi event co the dan den mot request.

## 4. Gioi han ky thuat cua kieu ma nay

Ve ly thuyet, doan ma nay van co nhieu gioi han:

### 4.1. Chi thay duoc nhung gi xay ra trong boi canh ma no dang chay

No khong mac dinh theo doi duoc toan bo he thong. No chi nghe duoc phim bam khi:

- script da duoc chen vao trang
- trang dang duoc mo
- focus va luong su kien van di qua document hien tai

### 4.2. Phu thuoc vao chinh sach trinh duyet va moi truong

Cross-origin policy, Content Security Policy, extension policy, sandboxing iframe, va cac co che bao ve khac co the lam request bi chan, bi gioi han, hoac bi giam kha nang hoat dong.

### 4.3. Du lieu thu duoc co the khong day du ngu canh

`e.key` chi la gia tri cua phim. Ve mat phan tich, no khong luon cho biet:

- ngu canh nguoi dung dang nhap vao o nao
- text sau cung sau khi da sua/xoa
- du lieu IME va input method phuc tap

Vi vay, gia tri event khong dong nghia voi "noi dung cuoi cung cua form".

## 5. Rui ro bao mat va quyen rieng tu

Kieu ma nay nguy hiem o cho no ket hop hai kha nang:

1. Quan sat hanh vi nhap lieu
2. Chuyen du lieu ra ngoai

He qua co the bao gom:

- Lo mat khau, token, ma OTP, thong tin ca nhan
- Vi pham chinh sach noi bo va quy dinh bao ve du lieu
- Tao dau vet mang bat thuong do request xay ra lien tuc theo tung phim bam
- Lam tang nguy co bi phat hien boi cong cu giam sat endpoint, browser security controls, WAF, proxy, hoac SIEM

## 6. Dau hieu nhan biet tu goc do phong thu

Khi review ma nguon hoac telemetry, co the chu y cac dau hieu sau:

### 6.1. Trong ma nguon

- Su dung `addEventListener('keydown', ...)`, `keypress`, `keyup`
- Thu thap `e.key`, `e.code`, `which`, `keyCode`
- Goi `fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, WebSocket ngay sau su kien ban phim
- Truyen du lieu qua query string hoac body ma khong co ly do nghiep vu ro rang

### 6.2. Tren mang

- Request lap lai voi tan suat cao, moi request rat ngan
- Payload co dang ky tu don le hoac chuoi ngan bat thuong
- Muc tieu request khong lien quan chuc nang trang web

### 6.3. Tren trinh duyet

- Script la, script inject, hoac script ben thu ba yeu cau quyen khong can thiet
- Event listener duoc gan vao `document` hoac `window` mot cach qua rong

## 7. Phan biet voi chuc nang hop le

Khong phai moi doan ma nghe su kien ban phim deu doc hai. Nhieu tinh nang hop le cung dung keyboard events, vi du:

- Phim tat giao dien
- Dieu huong bang ban phim
- Kiem tra form theo thoi gian thuc
- Tro nang truy cap cho nguoi dung

Diem khac biet nam o muc dich va duong di cua du lieu:

- Chuc nang hop le thuong xu ly ngay trong trang de phuc vu UI
- Hanh vi dang nghi thuong trich xuat input roi gui di khong can thiet

## 8. Y nghia cua `mode: 'no-cors'`

Ve ly thuyet, tuy chon nay cho thay tac gia khong can doc noi dung response tu JavaScript. No thuong duoc dung khi chi muon "ban" request di. Tu goc do phong thu, day la mot dau hieu dang chu y:

- Script uu tien viec gui du lieu hon la xu ly ket qua
- Request co the duoc phat di ngay ca khi response khong de script truy cap day du

Dieu nay khong lam hanh vi tro nen "vo hinh", nhung no the hien mot mo hinh exfiltration don gian.

## 9. Loi logic thay duoc trong mau ma

Dong `console.log( + key);` cho thay co su ep kieu sang so truoc khi ghi log. Ve ly thuyet:

- Neu `key` la chu cai hay ky tu thong thuong, phep ep kieu se khong phu hop
- Ket qua ghi log co the khong phan anh dung gia tri phim nhan

Day la loi correctness, khong lam thay doi ban chat rui ro cua doan ma.

## 10. Cach tiep can an toan neu dung cho lab hoc tap

Neu muc tieu la hoc ve phat hien va phong thu, cach tiep can tot hon la dung ban mo phong an toan:

- Chi bat su kien trong mot o input demo co dan nhan ro rang
- Khong gui du lieu ra mang
- Thay gia tri that bang du lieu gia lap hoac thong ke tong hop
- Ghi ro day la moi truong lab co consent
- Dung de kiem thu detection rule, CSP, logging, alerting

## 11. Ket luan

Ve ban chat, `keylogger_payload.js` duoc xay dung tren co che hop phap cua trinh duyet:

- nghe su kien
- doc event object
- gui request mang

Dieu lam no tro thanh van de bao mat khong nam o "ky thuat cao sieu", ma o cho cac kha nang hop le cua web API bi dung sai muc dich. Khi danh gia loai ma nay, can tap trung vao:

- pham vi script dang theo doi gi
- du lieu nao duoc thu thap
- du lieu duoc gui di dau
- co co so nghiep vu va su dong y ro rang hay khong

Neu can, buoc tiep theo hop ly la viet them mot tai lieu thu hai theo huong phong thu:

- checklist review ma JavaScript nghi ngo
- Sigma/YARA/regex goi y de tim dau hieu tuong tu
- huong dan hardening CSP va giam sat network telemetry
