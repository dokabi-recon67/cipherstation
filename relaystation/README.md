# CipherStation: Secure Cryptanalysis, Encryption & Messaging Platform

[![GitHub Repo](https://img.shields.io/badge/GitHub-View%20on%20GitHub-181717?logo=github&style=for-the-badge)](https://github.com/dokabi-recon67/cipherstation)

## Overview
CipherStation is a professional-grade platform for classical cipher analysis, modern encryption/decryption, and secure message relay. It features a robust web interface and CLI, real-time progress feedback, a privacy-first message relay station with live public message board, and strong security protections.

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
  - Web UI and CLI support with advanced cracking options

- **Modern Encryption & Decryption**
  - AES-128/192/256-GCM, ChaCha20-Poly1305
  - Password-based key derivation (Argon2id)
  - Text and file encryption/decryption (web & CLI)
  - No file storage: all processing is in-memory and temporary

- **Enhanced Message Relay Station**
  - **6-Step Secure Workflow**: Cipher → Encrypt → Send → Retrieve → Decrypt → Decode
  - **Live Public Message Board**: Real-time display of available encrypted messages
  - **Ticket-Based System**: Secure message drop and retrieval with unique ticket IDs
  - **Auto-Rotation**: Message board updates every 30 seconds with newest messages
  - **24-Hour Auto-Cleanup**: Messages automatically deleted after 24 hours
  - **Privacy-First**: Only encrypted message previews shown, no plaintext exposure
  - **Click-to-Retrieve**: Select tickets directly from the public board
  - **In-Memory Storage**: High-capacity message handling limited by available system memory

- **Command-Line Interface (CLI)**
  - Full-featured CLI for all cryptographic and classical operations
  - Key generation, encryption, decryption, digital signatures, hybrid encryption, batch processing
  - Interactive menu and advanced cracking options
  - Benchmark and analysis tools

- **Web Interface**
  - Modern, responsive design (Bootstrap 5) with dark theme
  - Live progress bars, queue system, and real-time analysis stats
  - Input sanitization and XSS protection
  - Animated logo with encryption/decryption simulation

- **Security & Performance**
  - No SQL/database usage (no SQL injection risk)
  - All user input sanitized and validated
  - Rate limiting (10 requests/minute/IP per endpoint)
  - Input size limits (10,000 characters max)
  - Concurrency queue (max 3 heavy tasks, others queued with position shown)
  - No file uploads or arbitrary file access
  - No command injection, eval, or exec
  - No sensitive data exposure

- **Comprehensive Self-Test & Health Check**
  - Built-in self-test page (`/selftest`) for cryptographic verification
  - 24 comprehensive tests covering all system components
  - Real-time test execution with progress tracking
  - API, encryption, classical cipher, and web interface validation
  - Detailed error reporting and performance metrics

---

## Web UI Usage

### 1. **Message Relay Station (Homepage)**
Complete 6-step secure messaging workflow:

1. **Step 1: Apply Cipher** - Transform plaintext using classical cryptography (Caesar, Vigenère, XOR, Atbash, Substitution)
2. **Step 2: Modern Encryption** - Secure with AES-256-GCM using password-based key derivation
3. **Step 3: Send to Station** - Upload to relay station and receive unique ticket ID
4. **Step 4: Retrieve from Station** - Browse live public message board or enter ticket manually
5. **Step 5: Decrypt Message** - Decrypt using the same password from Step 2
6. **Step 6: Decode Cipher** - Reverse the cipher from Step 1 to reveal original message

**Live Public Message Board Features:**
- Real-time display of 3 most recent encrypted messages
- Auto-updates every 30 seconds with server data
- Click any ticket to auto-fill for retrieval
- Shows "X min ago" timestamps for each message
- Messages persist across page refreshes until 24-hour cleanup

### 2. **Classical Cipher Cracking**
   - Go to `/classical`
   - Enter encrypted text, optionally add custom words
   - Configure advanced options (time limits, cipher selection, key lengths)
   - Click "Crack Cipher" to start analysis with real-time progress
   - View confidence-ranked results with detailed analysis

### 3. **Self-Test & Diagnostics**
   - Go to `/selftest` to verify all system components
   - Run comprehensive tests covering cryptography, APIs, and web interface
   - View real-time progress and detailed results
   - Verify system health and troubleshoot issues

### 4. **Documentation**
   - Go to `/documentation` for complete usage guides
   - API documentation and examples
   - Security best practices and implementation details

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
python cipherstationv0.py encrypt --password --infile secret.txt --out encrypted.json
# Decrypt with password
python cipherstationv0.py decrypt --password --salt salt.bin --infile encrypted.json --out decrypted.txt
```

### Classical Cipher Commands
```bash
# Encode text
python cipherstationv0.py classical-encode --cipher caesar --text "HELLO" --shift 3
# Decode text
python cipherstationv0.py classical-decode --cipher caesar --text "KHOOR" --shift 3
# Auto-crack unknown cipher
python cipherstationv0.py classical-crack --text "KHOORZRUOG"
# Run classical cipher tests
python cipherstationv0.py classical-selftest
```

### Advanced CLI Cracking (with cli_cracker.py)
```bash
# Crack encrypted text with advanced options
python cli_cracker.py --text "Wklv lv d whvw phvvdjh." --max-time 300
# Crack from file
python cli_cracker.py --file encrypted.txt
# Use custom word list
python cli_cracker.py --text "ZINCS PGVNU" --wordlist custom_words.txt --max-key-length 10
# Interactive mode with full control
python cli_cracker.py --interactive
# Benchmark system performance
python cli_cracker.py --benchmark
# Enable specific ciphers only
python cli_cracker.py --text "CIPHER" --enabled-ciphers caesar,vigenere
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

## API Endpoints

### Message Relay Station
- `POST /encrypt-message` - Encrypt and optionally send to station
- `POST /decrypt-message` - Decrypt retrieved messages
- `GET /api/station/messages` - Get all station messages (for message board)
- `GET /api/station/ticket/<id>` - Retrieve specific message by ticket ID

### Classical Ciphers
- `POST /api/encode` - Encode text with classical cipher
- `POST /api/decode` - Decode text with classical cipher
- `POST /api/crack` - Advanced cipher cracking with progress tracking
- `GET /api/crack/progress/<task_id>` - Get cracking progress
- `GET /api/crack/results/<task_id>` - Get final cracking results
- `POST /api/analyze` - Comprehensive text analysis
- `POST /api/benchmark` - Performance benchmarking

---

## Project Structure
```
cipherstation/
├── cipherstationv0.py        # Main CLI cryptography toolkit
├── classical_ciphers.py      # Classical cipher implementation
├── cli_cracker.py            # Advanced classical cipher CLI interface
├── requirements.txt          # Python dependencies
├── README.md                 # This file
└── relaystation/             # Web interface
    ├── app.py                # Flask web application
    ├── templates/            # HTML templates
    │   ├── index.html        # Main relay station (6-step workflow)
    │   ├── classical.html    # Cipher cracking interface
    │   ├── selftest.html     # Comprehensive system testing
    │   └── documentation.html # Complete documentation
    └── static/               # Static assets (CSS, JS, icons)
```

---

## Security Summary
- **No Database Dependencies**: All data stored in memory, no SQL injection risks
- **Input Validation**: All user input sanitized and size-limited (10,000 chars max)
- **Rate Limiting**: 10 requests/minute/IP per endpoint to prevent abuse
- **Queue Management**: Max 3 concurrent heavy operations, others queued with position display
- **No File System Access**: No file uploads, downloads, or arbitrary file operations
- **XSS Protection**: All output properly escaped and sanitized
- **No Code Execution**: No eval, exec, or command injection vulnerabilities
- **Memory Management**: Automatic cleanup of expired messages (24-hour retention)
- **Privacy-First**: Only encrypted message previews displayed, no plaintext exposure

---

## Recent Updates

### Message Relay Station Enhancements
- **Real Server Integration**: Message board now displays actual server messages instead of fake data
- **Live Updates**: Auto-refreshes every 30 seconds with current server state
- **Improved UX**: Better loading states, error handling, and visual feedback
- **Text Visibility**: Fixed all status text to be properly visible on dark background
- **Debugging Tools**: Added console logging for troubleshooting ticket retrieval issues

### System Improvements
- **Comprehensive Self-Test**: 24 automated tests covering all system components
- **Enhanced Documentation**: Updated to reflect all current features and workflows
- **Performance Optimization**: Improved response times and resource usage
- **Error Handling**: Better error messages and user feedback throughout the system

---

## Author & Credits

**Project by:**
- Saadi Agha (Advocate High Court)
- Cursor AI Assistant
- ChatGPT 4o and o3 Models

All code, design, and implementation by the above. No MIT or open-source license applies. All rights reserved.

---

## Contact
For questions, feedback, or professional inquiries, contact Saadi Agha.

**GitHub Repository:** [https://github.com/dokabi-recon67/cipherstation](https://github.com/dokabi-recon67/cipherstation) 