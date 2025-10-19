# 🧾 Signature Playground v6 (PKCS#1-Compatible)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-blue.svg)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-18.x-61dafb.svg?logo=react&logoColor=white)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-Supported-0db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)

**Signature Playground v6** adalah aplikasi interaktif berbasis web untuk melakukan proses **RSA PKCS#1 v1.5 (SHA-256)** signature generation dan verification secara lokal menggunakan WebCrypto API. Dirancang agar kompatibel dengan spesifikasi **Paylabs** dan sistem berbasis RSA digital signature.

---

## 🔐 Fitur Utama

- Implementasi **RSA PKCS#1 v1.5 + SHA-256** (WebCrypto-native, browser-side)
- Mendukung **PKCS#1 dan PKCS#8** untuk private key, serta **SPKI dan PKCS#1** untuk public key
- Format _canonical string_ yang mudah digunakan:

  ```
  HTTPMethod:EndpointUrl:lowercase(SHA256hex(minify(body))):TimeStamp
  ```

- Validasi JSON otomatis (minify sebelum hashing)
- Dukungan dark mode & animasi interaktif (Framer Motion)
- Aman — semua proses dilakukan di sisi klien (tidak ada data dikirim ke server)

---

## 🧩 Dukungan Format Key

| Jenis           | Format | Header                            |
| :-------------- | :----- | :-------------------------------- |
| **Private Key** | PKCS#8 | `-----BEGIN PRIVATE KEY-----`     |
| **Private Key** | PKCS#1 | `-----BEGIN RSA PRIVATE KEY-----` |
| **Public Key**  | SPKI   | `-----BEGIN PUBLIC KEY-----`      |
| **Public Key**  | PKCS#1 | `-----BEGIN RSA PUBLIC KEY-----`  |

---

## ⚙️ Instalasi (Local Development)

### 1️⃣ Prasyarat

Pastikan telah terinstal:

- Node.js v18 atau lebih baru
- npm v9 atau lebih baru

### 2️⃣ Instal dependensi

```bash
npm install
```

### 3️⃣ Jalankan mode development

```bash
npm run dev
```

Akses aplikasi di: `http://localhost:5173`

---

## 🧱 Build & Preview (Production)

### Build aplikasi

```bash
npm run build
```

### Preview hasil build

```bash
npm run preview
```

Server lokal akan berjalan untuk meninjau hasil produksi sebelum deploy.

---

## 🐳 Menjalankan dengan Docker

### Build image Docker

```bash
docker build -t signature-playground-v6 -f docker/Dockerfile .
```

### Jalankan container

```bash
docker run --rm -p 8080:80 signature-playground-v6
```

Akses di `http://localhost:8080`

### Contoh docker-compose.yml

```yaml
version: "3.8"
services:
  signature-playground:
    image: signature-playground-v6:latest
    container_name: signature-playground
    ports:
      - "8080:80"
    restart: unless-stopped
```

---

## 🧪 Contoh Penggunaan

### Input contoh

```json
{
  "partnerReferenceNo": "1234567890",
  "amount": 10000,
  "currency": "IDR"
}
```

### Canonical String

```
POST:/api/v1/payment:q94b9e66b54f72d6a78d06a7e6a0d0b3d2b420aa7f7b92e05a4e3a53e94a1229:2025-10-10T09:00:00+07:00
```

### Output Signature (Base64)

```
XvKThxZy2b2Pw9LczPYyXQx7JTkW8UQKfZ5EKz9EGB1yYQZQv0tUlz7f5...==
```

---

## 🧠 Arsitektur Teknis

| Layer                 | Teknologi                | Deskripsi                                   |
| :-------------------- | :----------------------- | :------------------------------------------ |
| **Frontend**          | React + Vite             | Build cepat dan modular untuk UI interaktif |
| **Styling**           | TailwindCSS              | Utility-first CSS untuk tampilan modern     |
| **Animation**         | Framer Motion            | Transisi halus antar tab (Sign/Verify)      |
| **Crypto Engine**     | WebCrypto (SubtleCrypto) | Native API browser untuk signing/verifying  |
| **Container Runtime** | Docker + Nginx           | Distribusi ringan untuk deployment produksi |

---

## 🧩 Struktur Direktori (Ringkasan)

```bash
signature-playground-v6/
├── src/
│   ├── components/
│   ├── utils/crypto.js
│   └── SignaturePlaygroundV6.jsx
├── docker/
│   └── Dockerfile
├── public/
├── package.json
└── README.md
```

---

## 🧱 Deployment

### 1️⃣ Build & Push Image

```bash
docker build -t ghcr.io/ahmadeko/signature-playground-v6:latest .
docker push ghcr.io/ahmadeko/signature-playground-v6:latest
```

### 2️⃣ Deploy ke Server

Gunakan `docker-compose` atau `systemd service` untuk menjalankan container di server produksi.

---

## 📜 Best Practice Keamanan

- Simpan **private key** hanya di sisi lokal pengguna.
- Pastikan **https** digunakan saat aplikasi di-deploy publik.
- Hindari menggunakan browser lama tanpa dukungan WebCrypto.
- Selalu verifikasi hasil signature menggunakan public key yang benar.

---

## 👥 Kontributor

| Nama                    | Peran                                    | Kontak                                        |
| :---------------------- | :--------------------------------------- | :-------------------------------------------- |
| **Ahmad Eko Kurniawan** | Application Support Engineer / Developer | [ahmad@example.com](mailto:ahmad@example.com) |

Kontribusi baru sangat diterima melalui **pull request** atau **issue report**.

---

## 📄 Lisensi

Proyek ini dilisensikan di bawah **MIT License** © 2025 Ahmad Eko Kurniawan.

Lihat berkas [LICENSE](./LICENSE) untuk informasi lebih lanjut.

---

## 🌐 Tautan Terkait

- [Dokumentasi RSA WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign)
- [PKCS#1 v1.5 Specification (RFC 8017)](https://www.rfc-editor.org/rfc/rfc8017)
- [Paylabs Developer Portal](https://paylabs.co.id/api-reference.html)
