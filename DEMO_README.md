# CipherStation Live Demo

Automated browser demonstration of all CipherStation capabilities.

## 🎬 What This Demo Shows

This script opens a Chrome browser and automatically demonstrates:

1. **🏪 Relay Station** - Complete 6-step secure messaging workflow
   - Apply classical cipher (Caesar with shift 7)
   - Modern encryption (AES-256-GCM)
   - Send to relay station
   - Browse public message board
   - Retrieve encrypted message
   - Decrypt and decode to reveal original message

2. **🔍 Auto-Cracker** - Classical cipher analysis
   - Caesar cipher cracking
   - Vigenère cipher analysis  
   - Atbash cipher detection
   - Real-time progress and results

3. **🧪 Self-Test** - Comprehensive system testing
   - 24 automated tests
   - Live terminal output with scrolling
   - Summary statistics and results
   - Error detection and reporting

4. **📚 Documentation** - Feature overview
   - Complete API documentation
   - Security features
   - Usage examples
   - Implementation details

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- Google Chrome browser
- CipherStation server running

### Setup and Run

1. **Install demo dependencies:**
   ```bash
   python setup_demo.py
   ```

2. **Start CipherStation server** (in another terminal):
   ```bash
   cd relaystation
   python -m flask run --host=0.0.0.0 --port=5002 --debug
   ```

3. **Run the demo:**
   ```bash
   python cipherstation_demo.py
   ```

## 📹 Demo Features

### Visual Highlights
- **Element highlighting** - Red borders show current focus
- **Slow typing** - Realistic user input simulation
- **Auto-scrolling** - Follows the action automatically
- **Progress monitoring** - Shows test execution in real-time

### Demo Pacing
- **Smart delays** - Appropriate pauses for visibility
- **Progress messages** - Console output explains each step
- **Error handling** - Graceful fallbacks if elements not found
- **Browser persistence** - Stays open for manual exploration

### Test Cases
The demo uses realistic test data:
- **Caesar cipher**: "WKLV LV D WHVW PHVVDJH" (shift 3)
- **Vigenère cipher**: "ZINCS PGVNU DQJQX" 
- **Atbash cipher**: "GSVH RH ZM ZGYZHS XRKSVI"

## 🎯 Perfect for:

- **Live presentations** - Automated, professional demo
- **Screen recording** - Capture full capabilities
- **Feature showcasing** - Highlight all major functions
- **Quality assurance** - Verify end-to-end workflows
- **Training** - Show proper usage patterns

## 🔧 Customization

### Modify Demo Content
Edit `cipherstation_demo.py` to change:
- Test messages and passwords
- Cipher types and keys
- Demo timing and pacing
- Browser window size

### Server Configuration
The demo auto-detects servers on ports:
- 5002 (primary)
- 5001 (fallback)
- 5000 (fallback)

### Browser Options
Currently supports Chrome with options for:
- Full-screen presentation mode
- Developer tools disabled
- Security warnings disabled
- Persistent browser session

## 📊 Demo Output

```
🎬 STARTING CIPHERSTATION LIVE DEMO
============================================================
This demo will showcase all CipherStation capabilities:
1. 🏪 Relay Station - Secure 6-step messaging
2. 🔍 Auto-Cracker - Classical cipher analysis
3. 🧪 Self-Test - Comprehensive system testing
4. 📚 Documentation - Feature overview
============================================================

🚀 Setting up browser for CipherStation demo...
✅ Browser ready!

🎯 DEMONSTRATING RELAY STATION
==================================================
📝 Step 1: Apply Classical Cipher
⏸️  Loading CipherStation homepage...
⏸️  Applying Caesar cipher with shift 7...

🔐 Step 2: Modern Encryption
⏸️  Encrypting with AES-256-GCM...

📡 Step 3: Send to Relay Station
⏸️  Sending to relay station...

📋 Step 4: Browse Public Message Board
⏸️  Viewing live public message board...
⏸️  Selecting message from public board...
⏸️  Retrieving encrypted message...

🔓 Step 5: Decrypt Message
⏸️  Decrypting message...

🔑 Step 6: Decode Cipher
⏸️  Decoding Caesar cipher...
✅ Relay Station demonstration complete!

[... continues with Auto-Cracker, Self-Test, and Documentation demos ...]

🎉 DEMO COMPLETE!
============================================================
✅ All CipherStation features demonstrated successfully!
🌐 Browser will remain open for further exploration
============================================================
```

## 🛠️ Troubleshooting

### Common Issues

**Server not detected:**
- Ensure Flask server is running on port 5002
- Check firewall settings
- Verify no port conflicts

**Chrome not found:**
- Install Google Chrome
- Update webdriver-manager: `pip install --upgrade webdriver-manager`

**Elements not found:**
- Server might be slow to respond
- Increase wait timeouts in script
- Check if page structure has changed

**Demo runs too fast:**
- Increase `demo_pause()` durations
- Reduce typing speed in `type_slowly()`
- Add more highlighting time

### Performance Tips

- Close other browser windows
- Ensure sufficient system memory
- Use wired internet connection
- Disable browser extensions

## 📝 Notes

- Demo keeps browser open for manual exploration
- Press Ctrl+C to close demo and browser
- All demo data is temporary and safe
- No real data is transmitted or stored
- Perfect for screen recording at 1080p+

---

**Created for CipherStation demonstration purposes**  
**Not part of the main CipherStation codebase** 