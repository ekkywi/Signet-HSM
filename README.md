# 🛡️ Signet Hardware Root CA: Micro-PKI & Key Generation Engine

**Signet HSM** has evolved into a dedicated **Hardware Certificate Authority (Root CA)** built on the ESP32 microcontroller. Designed to power the **Signet Cloud KMS** infrastructure, it provides military-grade cryptographic key generation and X.509 certificate stamping without the risk of network-based exfiltration.

Instead of signing individual daily licenses, Signet now acts as the ultimate Root of Trust. It dynamically generates mathematically unique RSA keypairs for every new software product and issues mathematically signed `.cert` passports directly from silicon.

## ✨ Core Features

- **On-Chip RSA Key Generation:** Powered by the ESP32's True Random Number Generator (TRNG) feeding into the mbedTLS CTR-DRBG algorithm. Generates highly secure, unique RSA-2048 keypairs entirely within the hardware.

- **X.509 Certificate Stamping:** Acts as a standalone Certificate Authority. Automatically wraps newly generated public keys into standard X.509 certificates, cryptographically signed by the air-gapped Master Root Key.

- **Heap-Optimized Cryptography:** Custom memory allocation (malloc/free) to safely perform heavy "Bignum" math operations in the Heap RAM, bypassing standard RTOS stack limitations and preventing kernel panics.

- **True Air-Gapped Security:** Zero network attack surface. WiFi and Bluetooth modules are strictly powered off at the firmware level (WiFi.mode(WIFI_OFF) and btStop()).

- **JSON-over-Serial API:** Seamlessly communicates with backend servers (via Node.js bridge to Laravel) using a strict, fast, and easily parsable JSON interface.

## 🧰 Hardware Requirements

- **Board:** ESP32 Development Module (e.g., ESP32-WROOM-32)
- **Connection:** High-quality Micro-USB / USB-C data cable (connected directly to the host server/homelab)
- **Host Environment:** Proxmox, LXC, or bare-metal Linux (Ubuntu/Debian) capable of reading `/dev/ttyUSB0`

## 🚀 Installation & Setup

This project uses [PlatformIO](https://platformio.org/).

### 1. Secure Your Master Key

**WARNING: NEVER commit your actual Private Key to version control!**

Generate an Elliptic Curve private key on your secure host machine:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out master_private.pem
```

Copy the provided template to create your local key vault:

```bash
cp src/keys.example.h src/keys.h
```

Paste your PEM-formatted Private Key inside `src/keys.h`. (Ensure `src/keys.h` is added to your `.gitignore`).

### 2. Build and Flash

Connect your ESP32 to your machine and compile the firmware:

```bash
pio run --target upload
```

## 🔌 API Usage (JSON over Serial)

Signet HSM operates at a baud rate of `115200`. Send a JSON string terminated by a newline character (`\n`) to execute cryptographic operations.

### 1. Ping / Health Check

Check if the HSM is alive and responding.
**Request:**

```json
{ "action": "ping" }
```

**Response:**

```json
{ "status": "ok", "message": "Signet Root CA is secure and operational" }
```

### 2. Generate Product Identity (Keypair & Certificate)

Instruct the HSM to utilize its TRNG to generate a new RSA-2048 keypair and sign the public key into an X.509 Certificate. (Note: This operation takes 1-3 seconds of compute time).

**Request:**

```json
{
  "action": "generate_identity",
  "data": {
    "product_name": "Awesome Product"
  }
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "raw_private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
    "certificate": "-----BEGIN CERTIFICATE-----\nMIICJzCCAc2gAwIBAg...\n-----END CERTIFICATE-----\n"
  }
}
```

## 🔒 Security Architecture (Cloud KMS Model)

1. **Root Isolation:** The Master CA Key is compiled directly into the ESP32's flash memory. It never leaves the device.
2. **Identity Creation:** When a new software product is registered, the HSM generates a unique keypair. The raw private key is sent back to the server (where Laravel encrypts it at rest using AES-256), alongside the globally distributable `.cert` file.
3. **Delegated Signing:** To eliminate USB bottlenecks, the HSM is only used for high-value Root CA operations (Product Registration). High-frequency daily license validations are signed by the Cloud KMS using the software's specific encrypted private key.
4. **Offline Validation:** Client applications verify their licenses entirely offline using the mathematically paired `.cert` file downloaded from the Signet Console.

## 📜 License

This project is open-sourced software licensed under the **[MIT License](https://opensource.org/licenses/MIT)**.

Copyright (c) 2026 Yon Ekky Wijayanto / Trezanix.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
