# Lab 02 — From the One-Time Pad to Stream Ciphers

**IT4010E — Nhập môn An toàn thông tin, SoICT, HUST**

## Thành viên nhóm

- Nguyễn Hoàng Khôi — 202416710
- Nguyễn Quý Dương — 202416683
- Lê Trọng Đạt — 202416672

## Tổng quan

Repo này chứa lời giải cho Lab 02, đi từ one-time pad (OTP) đến các stream cipher thực tế, gồm 7 task:

| File | Task | Tóm tắt |
|---|---|---|
| `task1.py` | One-time pad | Port đoạn code OTP từ Python 2 sang Python 3, mã hoá/giải mã với key 1024 byte, và xử lý trường hợp message dài hơn key. |
| `task2.py` | Reusing the pad | Khai thác lỗi tái sử dụng OTP: tính `M1 xor M2` mà không cần key, crib-drag `" the "`, và giả mạo key để một ciphertext giải mã ra thông điệp tuỳ ý. |
| `task3.py` | Pseudorandom pad from NaCl | Xây stream cipher dựa trên `SecretBox` (XSalsa20) của PyNaCl, và minh hoạ hậu quả khi dùng lại nonce (giống hệt lỗi ở Task 2). |
| `task4.py` | Encrypting a book | Mã hoá một file PDF lớn theo từng chunk với `nonce = prefix \|\| counter`, kiểm tra tính toàn vẹn qua SHA-256, và tái hiện lỗi "quên tăng counter". |
| `task5.py` | Changing an encrypted amount | Tấn công bit-flipping trên stream cipher không có xác thực, rồi cho thấy `SecretBox` thật (có tag Poly1305) chặn được tấn công này. |
| `task6.py` | A shift-register generator | Cài đặt LFSR, đo chu kỳ với vài bộ taps/seed, và dùng nó làm bộ sinh keystream. |
| `task7.py` | Breaking the shift register | Khôi phục seed và toàn bộ plaintext của LFSR từ 8 byte plaintext đã biết; **bonus**: khôi phục mà không cần biết taps, dùng thuật toán Berlekamp–Massey. |

Output đầy đủ + giải thích cho từng task nằm trong **`Lab02_Report.docx`**.
File `lab02.ipynb` là bản notebook tương tác (chỉ để tham khảo/chạy thử —
bài nộp chính thức là các file `taskN.py`).

## Yêu cầu môi trường

- Python 3.8+
- [PyNaCl](https://pynacl.readthedocs.io/): `pip install pynacl`

## Cách chạy

Mỗi task là một file độc lập, tự chứa (không phụ thuộc lẫn nhau) — chạy trực tiếp:

```bash
python task1.py
python task2.py   # cần ciphertexts.txt, được task1.py tạo ra
python task3.py
python task4.py   # cần book.pdf (xem bên dưới)
python task5.py
python task6.py
python task7.py
```

Nhớ chạy `task1.py` trước `task2.py`: Task 1 ghi ra `ciphertexts.txt`, Task 2
đọc lại file này (không dùng key — đúng ý đồ của bài tập).

### Điều kiện riêng cho Task 4

`task4.py` mã hoá giáo trình *A Graduate Course in Applied Cryptography*
(Boneh & Shoup). File PDF này **không** được đưa vào repo (do bản quyền, và
là file nhị phân khá nặng) — cần tải về trước, để cùng thư mục:

```bash
curl -O https://toc.cryptobook.us/book.pdf
# hoặc trên PowerShell:
# Invoke-WebRequest -Uri "https://toc.cryptobook.us/book.pdf" -OutFile "book.pdf"
```

Sau đó `task4.py` sẽ tự tạo ra `book.enc`, `book.dec.pdf`, `book.buggy.enc`
(các file này cũng đã được `.gitignore` loại khỏi repo).

## Kết quả chính

- **Task 2 / 3**: dùng lại key OTP hay nonce của stream cipher đều dẫn đến
  cùng một lỗi: `c1 xor c2 == M1 xor M2`, lộ ra XOR của hai plaintext mà
  không cần đụng đến key.
- **Task 5**: stream cipher không có xác thực là *malleable* — attacker biết
  định dạng plaintext có thể sửa đúng vài bit của ciphertext để đổi số tiền
  giải mã ra, mà không cần biết key. Một MAC (như trong `SecretBox`) chặn
  được điều này bằng cách từ chối mọi ciphertext bị sửa.
- **Task 6 / 7**: output của LFSR "trông ngẫu nhiên" (qua các kiểm tra thống
  kê đơn giản) nhưng thực chất hoàn toàn tuyến tính. Chỉ cần biết `n` bit
  keystream liên tiếp là đọc ra ngay seed, và `2n` bit là đủ để thuật toán
  Berlekamp–Massey dựng lại toàn bộ cấu trúc hồi quy — kể cả khi không biết
  taps. Đây là lý do các stream cipher thật (như XSalsa20 dùng ở Task 3–4)
  không bao giờ để lộ trực tiếp output của một LFSR thuần tuý làm keystream.
