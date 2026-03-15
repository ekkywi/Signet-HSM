# 🛡️ Signet HSM: Enterprise-Grade Micro Hardware Security Module

**Signet HSM** is an ultra-low-cost, air-gapped Hardware Security Module (HSM) built on top of the ESP32 microcontroller. Designed specifically for secure software licensing and PaaS environments, it provides military-grade cryptographic signing capabilities without the risk of network-based exfiltration.

Built to power the infrastructure of **Trezanix**, Signet turns a standard ESP32 into a dedicated cryptographic engine capable of generating unforgeable Elliptic Curve Digital Signatures (ECDSA).

---

## ✨ Core Features

- **Military-Grade Cryptography:** Powered by the industry-standard `mbedTLS` library. Utilizes **ECDSA (secp256r1)** and **SHA-256** hashing—the same algorithms used in Bitcoin wallets and modern biometric passports.
- **True Air-Gapped Security:** Zero network attack surface. WiFi and Bluetooth modules are strictly powered off at the firmware level (`WiFi.mode(WIFI_OFF)` and `btStop()`). Communication is restricted entirely to local Serial (USB).
- **Deterministic Signatures (RFC 6979):** Protects against Side-Channel Attacks and Random Number Generator (RNG) failures. The same payload will reliably produce the same signature, preventing catastrophic nonce-leakage.
- **JSON-over-Serial API:** Seamlessly communicates with backend servers (Laravel, Node.js, Go) using a strict, fast, and easily parsable JSON interface.
- **Disaster Recovery Ready:** Uses a "Key Injection" architecture. If the hardware is physically destroyed, the Master Private Key can be safely flashed into a new $5 ESP32 board in under 60 seconds.

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
{ "status": "ok", "message": "HSM is alive and secure" }
```

### 2. Sign Payload (License Generation)

Generate a Base64-encoded ASN.1 DER signature for your license payload.
**Request:**

```json
{
  "action": "sign_license",
  "data": "TRZX-9922-AABB|PRO_PLAN|2027-12-31|MAC-A1:B2:C3"
}
```

**Response:**

```json
{
  "status": "success",
  "signature": "MEUCIAz5imXSFSlu2RYMXT9sTpgfSHWoF2kWKa5dTfQNPrPTAiEAunppl1Q1qulvX3GUlDMYe329UsvMfKSO2RLZwms7OLI="
}
```

## 🔒 Security Architecture

1. **Isolation:** The Private Key is compiled directly into the ESP32's flash memory. It is never exported, printed, or transmitted over any interface.
2. **Execution:** The Laravel/backend server constructs the license payload and sends it to the HSM. The HSM hashes the payload, signs it internally, and returns _only_ the cryptographic signature.
3. **Validation:** Client applications verify the license entirely offline using the mathematically paired Public Key hardcoded in their source code.

## 📜 License

This project is open-sourced software licensed under the **[MIT License](https://opensource.org/licenses/MIT)**.

Copyright (c) 2026 Yon Ekky Wijayanto / Trezanix.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
