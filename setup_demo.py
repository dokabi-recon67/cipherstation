#!/usr/bin/env python3
"""
CipherStation Demo Setup Script
Installs required dependencies and checks system requirements
"""

import subprocess
import sys
import requests
import time

def install_requirements():
    """Install demo requirements"""
    print("📦 Installing demo dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "demo_requirements.txt"])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def check_server():
    """Check if CipherStation server is running"""
    print("🔍 Checking CipherStation server...")
    
    ports_to_check = [5002, 5001, 5000]
    
    for port in ports_to_check:
        try:
            url = f"http://localhost:{port}"
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                print(f"✅ CipherStation server found at {url}")
                return url
        except:
            continue
    
    print("❌ CipherStation server not detected on any port")
    print("Please start the server first:")
    print("  cd relaystation")
    print("  python -m flask run --host=0.0.0.0 --port=5002 --debug")
    return None

def check_chrome():
    """Check if Chrome browser is available"""
    print("🌐 Checking Chrome browser...")
    try:
        # Try to detect Chrome
        import shutil
        chrome_paths = [
            "google-chrome",
            "chromium-browser", 
            "chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        ]
        
        for path in chrome_paths:
            if shutil.which(path) or path.startswith("/Applications"):
                print("✅ Chrome browser detected")
                return True
        
        print("❌ Chrome browser not found")
        print("Please install Google Chrome from: https://www.google.com/chrome/")
        return False
        
    except Exception as e:
        print(f"⚠️  Could not verify Chrome: {e}")
        return True  # Assume it's available

def main():
    print("🎬 CipherStation Demo Setup")
    print("=" * 40)
    
    # Install dependencies
    if not install_requirements():
        return False
    
    # Check Chrome
    if not check_chrome():
        return False
    
    # Check server
    server_url = check_server()
    if not server_url:
        return False
    
    print("\n🎉 Setup complete!")
    print("=" * 40)
    print("Ready to run demo:")
    print("  python cipherstation_demo.py")
    print("=" * 40)
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 