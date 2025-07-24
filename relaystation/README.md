# CipherStation: Secure Cryptanalysis, Encryption & Messaging Platform

[![GitHub Repo](https://img.shields.io/badge/GitHub-View%20on%20GitHub-181717?logo=github&style=for-the-badge)](https://github.com/dokabi-recon67/cipherstation)

## Overview
CipherStation is a professional-grade platform for classical cipher analysis, modern encryption/decryption, and secure message relay. It features a robust web interface and CLI, real-time progress feedback, a privacy-first message relay station with live public message board, and strong security protections.

---

## Technical Stack
- Python 3.9+
- Flask 2.3+
- cryptography
- argon2-cffi
- SQLite (persistent message storage)
- Bootstrap 5 (web UI)
- HTML5, CSS3, JavaScript

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
  - All processing is in-memory and temporary except for relay station messages

- **Enhanced Message Relay Station**
  - **6-Step Secure Workflow**: Cipher → Encrypt → Send → Retrieve → Decrypt → Decode
  - **Live Public Message Board**: Real-time display of available encrypted messages
  - **Ticket-Based System**: Secure message drop and retrieval with unique ticket IDs
  - **Auto-Rotation**: Message board updates every 30 seconds with newest messages
  - **24-Hour Auto-Cleanup**: Messages automatically deleted after 24 hours
  - **Privacy-First**: Only encrypted message previews shown, no plaintext exposure
  - **SQLite Database**: 100MB persistent storage supporting high message capacity

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
  - **Automatic Step Progression**: As each step is completed, the next is highlighted and the page scrolls smoothly to the active section, providing a guided workflow.

- **Security & Performance**
  - All user input sanitized and validated
  - Rate limiting (10 requests/minute/IP per endpoint)
  - Input size limits (10,000 characters max)
  - Concurrency queue (max 3 heavy tasks, others queued with position shown)
  - No file uploads or arbitrary file access
  - No command injection, eval, or exec
  - No sensitive data exposure
  - **Database Management**: SQLite-based persistent storage with automatic cleanup (24-hour retention)
  - Only encrypted message previews displayed, no plaintext exposure

- **Comprehensive Self-Test & Health Check**
  - Built-in self-test page (`/selftest`) for cryptographic verification
  - 24 comprehensive tests covering all system components
  - Real-time test execution with progress tracking
  - API, encryption, classical cipher, and web interface validation
  - Detailed error reporting and performance metrics

---

## Web UI Usage

### 1. Message Relay Station (Homepage)
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

**Step Progression and Smooth Scrolling:**
- The web interface features automatic step progression. As users complete each step, the next step is highlighted and the page scrolls smoothly to the active section. Completed steps are visually marked, and users are guided through the entire process without manual navigation.

### 2. Classical Cipher Cracking
   - Go to `/classical`
   - Enter encrypted text, optionally add custom words
   - Configure advanced options (time limits, cipher selection, key lengths)
   - Click "Crack Cipher" to start analysis with real-time progress
   - View confidence-ranked results with detailed analysis

### 3. Self-Test & Diagnostics
   - Go to `/selftest` to verify all system components
   - Run comprehensive tests covering cryptography, APIs, and web interface
   - View real-time progress and detailed results
   - Verify system health and troubleshoot issues

### 4. Documentation
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
- `POST /encrypt-message` - Encrypt and optionally send to station (SQLite storage)
- `POST /decrypt-message` - Decrypt retrieved messages
- `GET /api/station/messages` - Get all station messages from database (for message board)
- `GET /api/station/ticket/<id>` - Retrieve specific message by ticket ID from database
- `GET /api/station/stats` - Get database statistics (message count, size, capacity)

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
├── README.md                 # Main project documentation
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
- All data stored in SQLite database for relay station messages (no SQL injection risk with parameterized queries)
- All user input sanitized and size-limited (10,000 chars max)
- Rate limiting: 10 requests/minute/IP per endpoint to prevent abuse
- Queue management: Max 3 concurrent heavy operations, others queued with position display
- No file system access for uploads or arbitrary file operations
- XSS protection: All output properly escaped and sanitized
- No code execution: No eval, exec, or command injection vulnerabilities
- Database management: SQLite-based persistent storage with automatic cleanup (24-hour retention)
- Privacy-first: Only encrypted message previews displayed, no plaintext exposure

---

## Recent Updates

### SQLite Database Integration (Latest)
- Persistent Storage: Uses 100MB SQLite database for message relay station
- Increased Capacity: Supports high message volume
- Server Restart Resilience: Messages persist across server restarts
- Database Statistics: `/api/station/stats` endpoint for monitoring
- Optimized Performance: Indexed queries for fast message retrieval

### Message Relay Station Enhancements
- Real Server Integration: Message board displays actual server messages
- Live Updates: Auto-refreshes every 30 seconds with current server state
- Improved UX: Better loading states, error handling, and visual feedback
- Debugging Tools: Added console logging for troubleshooting ticket retrieval issues

### System Improvements
- Comprehensive Self-Test: 24 automated tests covering all system components
- Enhanced Documentation: Updated to reflect all current features and workflows
- Performance Optimization: Improved response times and resource usage
- Error Handling: Better error messages and user feedback throughout the system
- Step Progression: Automatic highlighting and smooth scrolling for each workflow step

---

## Author & Credits

**Project by:**
- Saadi Agha (Advocate High Court)
- Cursor AI Assistant
- ChatGPT Models

All code, design, and implementation by the above. All rights reserved.

---

## Contact
For questions, feedback, or professional inquiries, contact Saadi Agha.

**GitHub Repository:** [https://github.com/dokabi-recon67/cipherstation](https://github.com/dokabi-recon67/cipherstation) 