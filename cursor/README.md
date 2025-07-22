# CipherStation: Secure Cryptanalysis, Encryption & Messaging Platform

[![GitHub Repo](https://img.shields.io/badge/GitHub-View%20on%20GitHub-181717?logo=github&style=for-the-badge)](https://github.com/dokabi-recon67/cipherstation)

## Overview
CipherStation is a professional-grade platform for classical cipher analysis, modern encryption/decryption, and secure message relay. It features a robust web interface and CLI, real-time progress feedback, a privacy-first message relay station, and strong security protections.

---

## Lightweight Test Implementation Notice

CipherStation is designed as a lightweight, efficient test implementation for educational and practical use. It is optimized to easily crack small and moderate-sized ciphers with minimal compute power, making it ideal for quick analysis, demonstrations, and resource-constrained environments.

- **Performance Tradeoff:** To ensure fast response and avoid excessive CPU usage, the default configuration uses limited key lengths and a moderate dictionary size for attacks.
- **Scalability:** For advanced users running CipherStation privately on a high-performance machine, the system can be extended to support larger keyspaces, longer keys, and exhaustive dictionary attacks for more robust cryptanalysis.
- **Customization:** You may increase dictionary size, key length, and brute-force depth in the code to tackle more complex or industrial-strength ciphers, at the cost of higher compute requirements.

This balance allows CipherStation to be both accessible and extensible, serving as a practical tool for most classical ciphers while remaining adaptable for more demanding research or forensic applications.

---

## Features

- **Classical Cipher Cracking & Analysis**
  - Caesar, Vigenère, XOR, Atbash, Substitution ciphers
  - Multi-metric scoring, pattern/structure hypothesis engine
  - Real-time progress and confidence ranking
  - Web UI and CLI support

- **Modern Encryption & Decryption**
  - AES-128/192/256-GCM, ChaCha20-Poly1305
  - Password-based key derivation (Argon2id)
  - File and text encryption/decryption (web & CLI)
  - No file storage: all processing is in-memory and temporary

- **Message Relay Station**
  - Ticket-based encrypted message drop and retrieval
  - Privacy-first: only encrypted previews are shown
  - Copy and search by ticket number

- **Command-Line Interface (CLI)**
  - Full-featured CLI for all cryptographic and classical operations
  - Key generation, encryption, decryption, digital signatures, hybrid encryption, batch processing
  - Interactive menu and advanced options

- **Web Interface**
  - Modern, responsive design (Bootstrap 5)
  - Live progress bar, queue system, and analysis stats
  - Input sanitization to prevent XSS

- **Security**
  - No SQL/database usage (no SQL injection risk)
  - All user input sanitized (XSS protection)
  - Rate limiting (10 requests/minute/IP per endpoint)
  - Input size limits (10,000 characters max)
  - Concurrency queue (max 3 heavy tasks, others queued with position shown)
  - No file uploads or arbitrary file access
  - No command injection, eval, or exec
  - No sensitive data exposure

- **Self-Test & Health Check**
  - Built-in self-test page for cryptographic verification
  - API and CLI health checks

---

## Web UI Usage

1. **Classical Cipher Cracking**
   - Go to `/classical`
   - Enter encrypted text, optionally add custom words
   - Click "Crack Cipher" to start analysis
   - View real-time progress, queue position, and results

2. **File & Message Encryption/Decryption**
   - Go to `/`
   - Choose file or enter text, select algorithm, set password/key
   - Encrypt or decrypt instantly in-browser

3. **Message Relay Station**
   - Go to `/station`
   - Drop encrypted messages, retrieve by ticket number
   - Only encrypted previews are shown for privacy

4. **Self-Test**
   - Go to `/selftest` to verify cryptographic operations and API health

---

## CLI Usage

### Installation
```bash
pip install -r requirements.txt
```

### Help & Menu
```bash
python cipherstationv0.py --help
python cipherstationv0.py menu
```

### Key Generation
```bash
python cipherstationv0.py keygen aes256 --out mykey.key
python cipherstationv0.py keygen ed25519 --priv private.key --pub public.key
```

### Encryption/Decryption
```bash
# Encrypt file
python cipherstationv0.py encrypt --key mykey.key --infile secret.txt --out encrypted.json
# Decrypt file
python cipherstationv0.py decrypt --key mykey.key --infile encrypted.json --out decrypted.txt
# Encrypt with password
encrypt --password --infile secret.txt --out encrypted.json
# Decrypt with password
decrypt --password --salt salt.bin --infile encrypted.json --out decrypted.txt
```

### Classical Cipher Commands
```bash
# Encode text
python cipherstationv0.py classical-encode --cipher caesar --text "HELLO" --shift 3
# Decode text
python cipherstationv0.py classical-decode --cipher caesar --text "KHOOR" --shift 3
# Auto-crack unknown cipher
python cipherstationv0.py classical-crack --text "KHOORZRUOG"
# Run tests
python cipherstationv0.py classical-selftest
```

### Advanced CLI Cracking (with cli_cracker.py)
```bash
# Crack encrypted text
python cli_cracker.py --text "Wklv lv d whvw phvvdjh."
# Crack from file
python cli_cracker.py --file encrypted.txt
# Use custom word list
python cli_cracker.py --text "ZINCS PGVNU" --wordlist custom_words.txt
# Interactive mode
python cli_cracker.py --interactive
# Benchmark mode
python cli_cracker.py --benchmark
```

### Digital Signatures & Hybrid Encryption
```bash
# Sign a file
python cipherstationv0.py sign --priv ed.priv --infile document.txt --sig signature.json
# Verify signature
python cipherstationv0.py verify --sig signature.json --pub ed.pub --infile document.txt
# Hybrid encryption
python cipherstationv0.py hybrid-encrypt --peer-pub recipient.pub --infile secret.txt --out hybrid.json
python cipherstationv0.py hybrid-decrypt --priv my.priv --infile hybrid.json --out decrypted.txt
```

---

## Project Structure
```
cipherstation/
├── cipherstationv0.py        # Main CLI cryptography toolkit
├── classical_ciphers.py      # Classical cipher implementation
├── cli_cracker.py            # Classical cipher CLI interface
├── requirements.txt          # Python dependencies
├── README.md                 # This file
└── cursor/                   # Web interface
    ├── app.py                # Flask web application
    ├── templates/            # HTML templates
    └── static/               # Static assets (CSS, JS)
```

---

## Security Summary
- All endpoints are rate-limited and input-validated
- All user input is sanitized in the frontend and backend
- No SQL, no file uploads, no command execution
- Queue system prevents overload and DoS
- No sensitive data is stored or exposed

---

## Author & Credits

**Project by:**
- Saadi Agha (Advocate High Court)
- Cursor
- ChatGPT 4o and o3 Model

All code, design, and implementation by the above. No MIT or open-source license applies. All rights reserved.

---

## Contact
For questions, feedback, or professional inquiries, contact Saadi Agha.

**GitHub Repository:** [https://github.com/dokabi-recon67/cipherstation](https://github.com/dokabi-recon67/cipherstation) 