# Hướng dẫn chạy EphemeralShare

## Tài khoản Admin mẫu

| Trường | Giá trị |
|--------|---------|
| **Password** | `Admin@EphemeralShare2024` |
| **TOTP** | Tắt (để trống `TOTP_SECRET`) |
| **URL đăng nhập** | `http://localhost/admin` |

> ⚠️ Đây là tài khoản demo. Trong production, hãy tạo password mới và cập nhật `ADMIN_PASSWORD_HASH` trong file `.env`.

---

## Yêu cầu hệ thống

- **Docker Desktop** ≥ 24.0 — [Tải tại đây](https://www.docker.com/products/docker-desktop/)
- **Docker Compose** ≥ 2.20 (đi kèm Docker Desktop)
- **Cloudflare R2** hoặc **AWS S3** bucket (xem bước 2)

**Cài Docker Desktop trên Windows:**
1. Tải installer từ https://www.docker.com/products/docker-desktop/
2. Chạy installer, chọn "Use WSL 2 instead of Hyper-V" nếu được hỏi
3. Restart máy sau khi cài
4. Mở Docker Desktop, chờ engine khởi động (icon Docker ở system tray chuyển sang màu xanh)
5. Mở terminal mới và kiểm tra: `docker --version`

---

## Bước 1 — Cấu hình S3/R2

Mở file `.env` và điền thông tin bucket của bạn:

```dotenv
S3_ENDPOINT=https://YOUR_ACCOUNT_ID.r2.cloudflarestorage.com
S3_REGION=auto
S3_BUCKET=ephemeral-share
S3_ACCESS_KEY_ID=YOUR_ACCESS_KEY_ID
S3_SECRET_ACCESS_KEY=YOUR_SECRET_ACCESS_KEY
PUBLIC_BASE_URL=http://localhost
```

**Tạo bucket (nếu chưa có):**

```bash
cd infra
S3_BUCKET=ephemeral-share \
S3_ENDPOINT=https://YOUR_ACCOUNT_ID.r2.cloudflarestorage.com \
AWS_ACCESS_KEY_ID=YOUR_KEY \
AWS_SECRET_ACCESS_KEY=YOUR_SECRET \
bash setup-s3.sh
```

---

## Bước 2 — Cấu hình TLS cho Nginx (dev)

Nginx cần cert TLS để chạy. Tạo self-signed cert cho local dev:

```bash
mkdir -p nginx/ssl

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/CN=localhost"
```

---

## Bước 3 — Khởi động toàn bộ stack

```bash
docker compose up --build -d
```

Lần đầu build sẽ mất vài phút (Go compile + Next.js build + ClamAV download virus DB).

**Kiểm tra trạng thái:**

```bash
docker compose ps
```

Tất cả services phải ở trạng thái `healthy` trước khi dùng được.

> **Lưu ý:** ClamAV cần ~5–10 phút để tải virus database lần đầu. Backend sẽ chờ ClamAV healthy trước khi start.

---

## Bước 4 — Truy cập ứng dụng

| URL | Mô tả |
|-----|-------|
| `https://localhost/admin` | Trang đăng nhập Admin |
| `https://localhost/health` | Health check endpoint |
| `http://localhost/health` | Health check (HTTP, redirect sang HTTPS) |

> Trình duyệt sẽ cảnh báo self-signed cert — chọn "Advanced → Proceed" để tiếp tục.

**Đăng nhập:**
- Mở `https://localhost/admin`
- Nhập password: `Admin@EphemeralShare2024`
- Click **Sign in**

---

## Bước 5 — Upload và chia sẻ file

1. Sau khi đăng nhập, kéo thả file vào vùng upload hoặc click để chọn file
2. Chọn TTL (thời gian tồn tại của link)
3. Click upload — hệ thống sẽ scan virus và tạo link
4. Copy link và gửi cho người nhận
5. Người nhận mở link, đọc cảnh báo "one-time link", click **Download file**
6. File bị xóa ngay sau khi tải xong

---

## Xem logs

```bash
# Tất cả services
docker compose logs -f

# Chỉ backend (audit logs dạng JSON)
docker compose logs -f backend

# Chỉ frontend
docker compose logs -f frontend

# ClamAV (theo dõi quá trình tải virus DB)
docker compose logs -f clamav
```

---

## Dừng và xóa

```bash
# Dừng (giữ data)
docker compose down

# Dừng và xóa toàn bộ data (Redis + ClamAV DB)
docker compose down -v
```

---

## Tạo password mới cho production

```bash
# Cách 1: dùng htpasswd (cần apache2-utils)
htpasswd -bnBC 12 "" YOUR_NEW_PASSWORD | tr -d ':\n'

# Cách 2: dùng Python
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_NEW_PASSWORD', bcrypt.gensalt(12)).decode())"

# Cách 3: dùng Node.js (cần cài bcrypt)
node -e "const b=require('bcrypt'); b.hash('YOUR_NEW_PASSWORD',12).then(h=>console.log(h))"
```

Sau đó cập nhật `ADMIN_PASSWORD_HASH` trong `.env` và restart backend:

```bash
docker compose restart backend
```

---

## Tạo JWT secret mới

```bash
openssl rand -hex 32
```

Cập nhật `JWT_SECRET` trong `.env` — tất cả session hiện tại sẽ bị invalidate.

---

## Chạy integration tests (cần Redis local)

```bash
# Khởi động Redis local
docker run -d -p 6379:6379 redis:7.2-alpine

# Chạy tests
cd backend
REDIS_ADDR=localhost:6379 go test -tags integration -run TestIntegration -v ./...
```

---

## Cấu trúc thư mục

```
.
├── backend/          # Go Fiber API server
│   ├── cmd/server/   # main.go — entry point
│   └── internal/     # auth, upload, download, worker, store, ...
├── frontend/         # Next.js 14 App Router
│   ├── app/          # Pages: /admin, /d/[token], /expired
│   └── lib/          # API client, auth context
├── nginx/            # Nginx reverse proxy config + SSL certs
├── infra/            # IAM policy, S3 lifecycle, setup script
├── docker-compose.yml
├── .env              # Cấu hình (đã có sẵn cho local dev)
└── .env.example      # Template
```

---

## Chạy frontend riêng lẻ (không cần Docker)

Nếu chưa có Docker, bạn có thể chạy frontend standalone để xem giao diện:

```bash
cd frontend
npm install
npm run dev
```

Mở `http://localhost:3000/admin` — giao diện sẽ hiện ra nhưng các API call sẽ fail vì backend chưa chạy.

**TypeScript type check:**
```bash
cd frontend
npm run type-check   # phải pass 0 errors
```

---

## Troubleshooting

**Backend không start — lỗi `ADMIN_PASSWORD_HASH is required`**
→ Kiểm tra file `.env` có tồn tại và có dòng `ADMIN_PASSWORD_HASH=...`

**ClamAV timeout khi scan**
→ ClamAV chưa tải xong virus DB. Chờ thêm vài phút rồi thử lại.
```bash
docker compose logs clamav | tail -20
```

**Nginx lỗi `cannot load certificate`**
→ Chưa tạo SSL cert. Chạy lại lệnh `openssl` ở Bước 2.

**Upload lỗi `SSRF_ENDPOINT_MISMATCH`**
→ `S3_ENDPOINT` trong `.env` không khớp với endpoint thực tế của bucket.

**Không kết nối được Redis**
→ Kiểm tra service redis đang chạy:
```bash
docker compose ps redis
docker compose exec redis redis-cli ping
```
