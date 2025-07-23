#!/usr/bin/env python3
"""
CipherStation Web Application - Comprehensive Test Suite
Tests all functionality including buttons, encryption algorithms, and UI elements.
"""

import requests
import json
import time
import sys
from urllib.parse import urljoin

# Configuration
BASE_URL = "http://localhost:5001"
TEST_MESSAGE = "Hello, this is a test message for CipherStation!"
TEST_PASSWORD = "mysecretpassword123"  # Any password works now

def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🧪 TESTING: {title}")
    print(f"{'='*60}")

def print_success(message):
    """Print a success message."""
    print(f"✅ {message}")

def print_error(message):
    """Print an error message."""
    print(f"❌ {message}")

def print_info(message):
    """Print an info message."""
    print(f"ℹ️  {message}")

def test_server_health():
    """Test if the server is running and responding."""
    print_header("Server Health Check")
    
    try:
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code == 200:
            print_success("Server is running and responding")
            return True
        else:
            print_error(f"Server returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Server connection failed: {e}")
        return False

def test_main_page():
    """Test the main page loads with correct content."""
    print_header("Main Page Test")
    
    try:
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code == 200:
            content = response.text
            
            # Check for key elements
            checks = [
                ("CipherStation branding", "CipherStation"),
                ("Dark theme CSS variables", "--bg-primary"),
                ("Google Translate style boxes", "text-box-container"),
                ("Input text box", "inputText"),
                ("Output text box", "outputText"),
                ("All encryption algorithms", "aes128"),
                ("All encryption algorithms", "aes192"),
                ("All encryption algorithms", "aes256"),
                ("ChaCha20 algorithm", "chacha20"),
                ("Copy button functionality", "copyToClipboard"),
                ("File upload section", "file-upload-section"),
                ("Message station link", "/station"),
                ("Self-test link", "/selftest"),
                ("Help link", "/help"),
                ("CLI download link", "/download-cli")
            ]
            
            passed = 0
            for name, search_term in checks:
                if search_term in content:
                    print_success(f"{name} found")
                    passed += 1
                else:
                    print_error(f"{name} missing")
            
            if passed == len(checks):
                print_success("Main page loads with all expected elements")
                return True
            else:
                print_error(f"Only {passed}/{len(checks)} elements found")
                return False
        else:
            print_error(f"Main page returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Main page request failed: {e}")
        return False

def test_encryption_algorithms():
    """Test all encryption algorithms work correctly."""
    print_header("Encryption Algorithms Test")
    
    algorithms = [
        ("aes256", TEST_PASSWORD, "AES-256-GCM"),
        ("aes192", TEST_PASSWORD, "AES-192-GCM"),
        ("aes128", TEST_PASSWORD, "AES-128-GCM"),
        ("chacha20", TEST_PASSWORD, "ChaCha20-Poly1305")
    ]
    
    passed = 0
    for alg, password, alg_name in algorithms:
        try:
            print_info(f"Testing {alg_name}...")
            
            # Test encryption
            encrypt_data = {
                "text": TEST_MESSAGE,
                "password": password,
                "algorithm": alg,
                "send_to_station": False
            }
            
            response = requests.post(
                urljoin(BASE_URL, "/encrypt-message"),
                headers={"Content-Type": "application/json"},
                json=encrypt_data,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    encrypted_text = data.get("encrypted", "")
                    
                    # Test decryption
                    decrypt_data = {
                        "encrypted_text": encrypted_text,
                        "password": password,
                        "algorithm": alg
                    }
                    
                    decrypt_response = requests.post(
                        urljoin(BASE_URL, "/decrypt-message"),
                        headers={"Content-Type": "application/json"},
                        json=decrypt_data,
                        timeout=10
                    )
                    
                    if decrypt_response.status_code == 200:
                        decrypt_data = decrypt_response.json()
                        if decrypt_data.get("success"):
                            decrypted_text = decrypt_data.get("decrypted", "")
                            if decrypted_text == TEST_MESSAGE:
                                print_success(f"{alg_name} encryption/decryption successful")
                                passed += 1
                            else:
                                print_error(f"{alg_name} decryption result mismatch")
                        else:
                            print_error(f"{alg_name} decryption failed: {decrypt_data.get('error')}")
                    else:
                        print_error(f"{alg_name} decryption request failed: {decrypt_response.status_code}")
                else:
                    print_error(f"{alg_name} encryption failed: {data.get('error')}")
            else:
                print_error(f"{alg_name} encryption request failed: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print_error(f"{alg_name} request failed: {e}")
        except Exception as e:
            print_error(f"{alg_name} test failed: {e}")
    
    if passed == len(algorithms):
        print_success(f"All {len(algorithms)} encryption algorithms working")
        return True
    else:
        print_error(f"Only {passed}/{len(algorithms)} algorithms working")
        return False

def test_message_station():
    """Test message station functionality."""
    print_header("Message Station Test")
    
    try:
        # Test station page loads
        response = requests.get(urljoin(BASE_URL, "/station"), timeout=5)
        if response.status_code == 200:
            content = response.text
            
            # Check for station elements
            station_checks = [
                ("Station page loads", "Message Relay Station"),
                ("Dark theme", "--bg-primary"),
                ("Search functionality", "searchTicket"),
                ("Message table", "messagesTable"),
                ("Copy buttons", "copyMessage"),
                ("Decryption form", "decryptForm"),
                ("All algorithms in decryption", "aes128"),
                ("All algorithms in decryption", "aes192"),
                ("All algorithms in decryption", "aes256"),
                ("ChaCha20 in decryption", "chacha20")
            ]
            
            passed = 0
            for name, search_term in station_checks:
                if search_term in content:
                    print_success(f"{name} found")
                    passed += 1
                else:
                    print_error(f"{name} missing")
            
            if passed == len(station_checks):
                print_success("Station page loads with all expected elements")
                return True
            else:
                print_error(f"Only {passed}/{len(station_checks)} station elements found")
                return False
        else:
            print_error(f"Station page returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Station page request failed: {e}")
        return False

def test_station_submission():
    """Test sending messages to the station."""
    print_header("Station Message Submission Test")
    
    try:
        # Send a message to the station
        station_data = {
            "text": f"Station test message - {int(time.time())}",
            "password": TEST_PASSWORD,
            "algorithm": "aes256",
            "send_to_station": True
        }
        
        response = requests.post(
            urljoin(BASE_URL, "/encrypt-message"),
            headers={"Content-Type": "application/json"},
            json=station_data,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                ticket_id = data.get("ticket_id")
                station_url = data.get("station_url")
                
                print_success(f"Message sent to station with ticket #{ticket_id}")
                
                # Test station search
                search_response = requests.get(
                    urljoin(BASE_URL, f"/station?ticket={ticket_id}"),
                    timeout=5
                )
                
                if search_response.status_code == 200:
                    search_content = search_response.text
                    if f"#{ticket_id}" in search_content:
                        print_success(f"Found message with ticket #{ticket_id} in station")
                        return True
                    else:
                        print_error(f"Message with ticket #{ticket_id} not found in station")
                        return False
                else:
                    print_error(f"Station search failed: {search_response.status_code}")
                    return False
            else:
                print_error(f"Station submission failed: {data.get('error')}")
                return False
        else:
            print_error(f"Station submission request failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Station submission request failed: {e}")
        return False

def test_self_test_page():
    """Test the self-test page."""
    print_header("Self-Test Page Test")
    
    try:
        response = requests.get(urljoin(BASE_URL, "/selftest"), timeout=5)
        if response.status_code == 200:
            content = response.text
            
            # Check for self-test elements
            selftest_checks = [
                ("Self-test page loads", "Self-Test Results"),
                ("Dark theme", "--bg-primary"),
                ("Test results table", "test-results"),
                ("AES test", "AES roundtrip"),
                ("ChaCha test", "ChaCha roundtrip"),
                ("Ed25519 test", "Ed25519 sign/verify"),
                ("Hybrid test", "Hybrid")
            ]
            
            passed = 0
            for name, search_term in selftest_checks:
                if search_term in content:
                    print_success(f"{name} found")
                    passed += 1
                else:
                    print_error(f"{name} missing")
            
            if passed == len(selftest_checks):
                print_success("Self-test page loads with all expected elements")
                return True
            else:
                print_error(f"Only {passed}/{len(selftest_checks)} self-test elements found")
                return False
        else:
            print_error(f"Self-test page returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Self-test page request failed: {e}")
        return False

def test_help_page():
    """Test the help page."""
    print_header("Help Page Test")
    
    try:
        response = requests.get(urljoin(BASE_URL, "/help"), timeout=5)
        if response.status_code == 200:
            content = response.text
            
            # Check for help page elements
            help_checks = [
                ("Help page loads", "Help & Instructions"),
                ("Dark theme", "--bg-primary"),
                ("Usage instructions", "Usage"),
                ("Security information", "Security"),
                ("CLI information", "Command Line"),
                ("Contact information", "Contact")
            ]
            
            passed = 0
            for name, search_term in help_checks:
                if search_term in content:
                    print_success(f"{name} found")
                    passed += 1
                else:
                    print_error(f"{name} missing")
            
            if passed == len(help_checks):
                print_success("Help page loads with all expected elements")
                return True
            else:
                print_error(f"Only {passed}/{len(help_checks)} help elements found")
                return False
        else:
            print_error(f"Help page returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Help page request failed: {e}")
        return False

def test_cli_download_page():
    """Test the CLI download page."""
    print_header("CLI Download Page Test")
    
    try:
        response = requests.get(urljoin(BASE_URL, "/download-cli"), timeout=5)
        if response.status_code == 200:
            content = response.text
            
            # Check for CLI download elements
            cli_checks = [
                ("CLI download page loads", "Command Line Interface"),
                ("Dark theme", "--bg-primary"),
                ("Installation instructions", "Installation"),
                ("Usage examples", "Usage Examples"),
                ("Download links", "Download"),
                ("CLI features", "Features")
            ]
            
            passed = 0
            for name, search_term in cli_checks:
                if search_term in content:
                    print_success(f"{name} found")
                    passed += 1
                else:
                    print_error(f"{name} missing")
            
            if passed == len(cli_checks):
                print_success("CLI download page loads with all expected elements")
                return True
            else:
                print_error(f"Only {passed}/{len(cli_checks)} CLI elements found")
                return False
        else:
            print_error(f"CLI download page returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"CLI download page request failed: {e}")
        return False

def test_copy_functionality():
    """Test copy button functionality (simulated)."""
    print_header("Copy Button Functionality Test")
    
    try:
        # Test that copy functions are present in the JavaScript
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code == 200:
            content = response.text
            
            copy_checks = [
                ("Copy to clipboard function", "copyToClipboard"),
                ("Copy success feedback", "showCopySuccess"),
                ("Copy button styling", "copy-btn"),
                ("Copy button hover effects", "copy-btn:hover"),
                ("Copy success state", "copy-btn.copied")
            ]
            
            passed = 0
            for name, search_term in copy_checks:
                if search_term in content:
                    print_success(f"{name} found")
                    passed += 1
                else:
                    print_error(f"{name} missing")
            
            if passed == len(copy_checks):
                print_success("Copy functionality properly implemented")
                return True
            else:
                print_error(f"Only {passed}/{len(copy_checks)} copy elements found")
                return False
        else:
            print_error(f"Main page request failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Copy functionality test failed: {e}")
        return False

def test_dark_theme():
    """Test dark theme implementation."""
    print_header("Dark Theme Test")
    
    try:
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code == 200:
            content = response.text
            
            # Check for dark theme elements
            theme_checks = [
                ("Dark background", "--bg-primary: #1e1e1e"),
                ("Secondary background", "--bg-secondary: #252526"),
                ("Tertiary background", "--bg-tertiary: #2d2d30"),
                ("Primary text color", "--text-primary: #cccccc"),
                ("Secondary text color", "--text-secondary: #969696"),
                ("Accent blue", "--accent-blue: #007acc"),
                ("Accent green", "--accent-green: #4ec9b0"),
                ("Border color", "--border-color: #3e3e42"),
                ("Success color", "--success-color: #4ec9b0"),
                ("Error color", "--error-color: #f44747")
            ]
            
            passed = 0
            for name, search_term in theme_checks:
                if search_term in content:
                    print_success(f"{name} found")
                    passed += 1
                else:
                    print_error(f"{name} missing")
            
            if passed == len(theme_checks):
                print_success("Dark theme properly implemented")
                return True
            else:
                print_error(f"Only {passed}/{len(theme_checks)} theme elements found")
                return False
        else:
            print_error(f"Main page request failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Dark theme test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 CipherStation Web Application - Comprehensive Test Suite")
    print("=" * 60)
    
    # Test results
    results = []
    
    # Run all tests
    tests = [
        ("Server Health", test_server_health),
        ("Main Page", test_main_page),
        ("Dark Theme", test_dark_theme),
        ("Encryption Algorithms", test_encryption_algorithms),
        ("Message Station", test_message_station),
        ("Station Submission", test_station_submission),
        ("Self-Test Page", test_self_test_page),
        ("Help Page", test_help_page),
        ("CLI Download Page", test_cli_download_page),
        ("Copy Functionality", test_copy_functionality)
    ]
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print_error(f"{test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print_header("Test Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"📊 Results: {passed}/{total} tests passed")
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} - {test_name}")
    
    if passed == total:
        print("✅ 🎉 All tests passed! CipherStation is working perfectly!")
        return 0
    else:
        print(f"❌ ⚠️  {total - passed} tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 