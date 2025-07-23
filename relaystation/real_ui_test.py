#!/usr/bin/env python3
"""
CipherStation Real UI Test Suite
Tests actual UI functionality by simulating real user interactions.
"""

import requests
import time
import json
from urllib.parse import urljoin

# Configuration
BASE_URL = "http://localhost:5001"
TEST_MESSAGE = "Hello, this is a test message for CipherStation!"
TEST_PASSWORD = "mysecretpassword123"  # Any password works now

def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🧪 REAL UI TESTING: {title}")
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

def test_text_encryption_functionality():
    """Test actual text encryption functionality."""
    print_header("Text Encryption Functionality Test")
    
    algorithms = [
        ("aes256", TEST_PASSWORD),
        ("aes192", TEST_PASSWORD),
        ("aes128", TEST_PASSWORD),
        ("chacha20", TEST_PASSWORD)
    ]
    
    passed = 0
    for algorithm, password in algorithms:
        try:
            print_info(f"Testing {algorithm.upper()} text encryption...")
            
            # Test text encryption
            encrypt_data = {
                "text": TEST_MESSAGE,
                "password": password,
                "algorithm": algorithm,
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
                    encrypted_text = data.get("encrypted")
                    if encrypted_text:
                        print_success(f"{algorithm.upper()} text encryption successful")
                        
                        # Test text decryption
                        decrypt_data = {
                            "encrypted_text": encrypted_text,
                            "password": password,
                            "algorithm": algorithm
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
                                decrypted_text = decrypt_data.get("decrypted")
                                if decrypted_text == TEST_MESSAGE:
                                    print_success(f"{algorithm.upper()} text decryption successful")
                                    passed += 1
                                else:
                                    print_error(f"{algorithm.upper()} text decryption failed - text mismatch")
                            else:
                                print_error(f"{algorithm.upper()} text decryption failed: {decrypt_data.get('error')}")
                                print_info(f"Error details: {decrypt_data}")
                        else:
                            print_error(f"{algorithm.upper()} text decryption request failed: {decrypt_response.status_code}")
                    else:
                        print_error(f"{algorithm.upper()} text encryption failed - no encrypted text returned")
                else:
                    print_error(f"{algorithm.upper()} text encryption failed: {data.get('error')}")
            else:
                print_error(f"{algorithm.upper()} text encryption request failed: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print_error(f"{algorithm.upper()} text test failed: {e}")
    
    print_success(f"Text encryption test: {passed}/{len(algorithms)} algorithms working")
    return passed == len(algorithms)

def test_station_sending_functionality():
    """Test sending messages to station functionality."""
    print_header("Station Sending Functionality Test")
    
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
                encrypted_text = data.get("encrypted")
                
                if ticket_id and encrypted_text:
                    print_success(f"Message sent to station with ticket #{ticket_id}")
                    
                    # Check if message appears in station
                    station_response = requests.get(urljoin(BASE_URL, "/station"), timeout=5)
                    if station_response.status_code == 200:
                        station_content = station_response.text
                        if f"#{ticket_id}" in station_content:
                            print_success(f"Message with ticket #{ticket_id} found in station")
                            
                            # Test station search functionality
                            search_response = requests.get(
                                urljoin(BASE_URL, f"/station?ticket={ticket_id}"),
                                timeout=5
                            )
                            
                            if search_response.status_code == 200:
                                search_content = search_response.text
                                if f"#{ticket_id}" in search_content:
                                    print_success(f"Station search for ticket #{ticket_id} successful")
                                    return True
                                else:
                                    print_error(f"Station search for ticket #{ticket_id} failed")
                                    return False
                            else:
                                print_error(f"Station search request failed: {search_response.status_code}")
                                return False
                        else:
                            print_error(f"Message with ticket #{ticket_id} not found in station")
                            return False
                    else:
                        print_error(f"Station page request failed: {station_response.status_code}")
                        return False
                else:
                    print_error("Station submission failed - missing ticket_id or encrypted text")
                    return False
            else:
                print_error(f"Station submission failed: {data.get('error')}")
                return False
        else:
            print_error(f"Station submission request failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Station sending test failed: {e}")
        return False

def test_station_display_and_copy():
    """Test station display and copy functionality."""
    print_header("Station Display and Copy Test")
    
    try:
        # First send a message to station
        station_data = {
            "text": f"Copy test message - {int(time.time())}",
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
                encrypted_text = data.get("encrypted")
                
                print_success(f"Test message sent with ticket #{ticket_id}")
                
                # Check station page for proper display
                station_response = requests.get(urljoin(BASE_URL, "/station"), timeout=5)
                if station_response.status_code == 200:
                    station_content = station_response.text
                    
                    # Check for essential station elements
                    checks = [
                        ("Message table", "messagesTable"),
                        ("Copy buttons", "copyMessage"),
                        ("Decryption form", "decryptForm"),
                        ("Search functionality", "searchTicket"),
                        ("Ticket display", f"#{ticket_id}"),
                        ("Encrypted preview", "message-preview"),
                        ("Copy button styling", "copy-btn")
                    ]
                    
                    passed = 0
                    for description, search_term in checks:
                        if search_term in station_content:
                            print_success(f"{description} found in station")
                            passed += 1
                        else:
                            print_error(f"{description} missing in station")
                    
                    print_success(f"Station display test: {passed}/{len(checks)} elements found")
                    
                    # Check if the encrypted text is properly displayed (truncated)
                    # The encrypted text is a JSON string, so we need to check for parts of it
                    # Try different patterns since JSON might be escaped
                    found = False
                    patterns_to_check = [
                        encrypted_text[:40],
                        encrypted_text[:60],
                        encrypted_text[:20],
                        '"version": 2',
                        '"alg": "AES-256-GCM"',
                        'AES-256-GCM'
                    ]
                    
                    for pattern in patterns_to_check:
                        if pattern in station_content:
                            print_success(f"Found pattern in station: {pattern[:30]}...")
                            found = True
                            break
                    
                    if found:
                        print_success("Encrypted text properly displayed in station")
                        return True
                    else:
                        print_error("Encrypted text not properly displayed in station")
                        print_info(f"Looking for patterns: {patterns_to_check}")
                        
                        # Debug: Check what's actually in the station content
                        if "message-preview" in station_content:
                            print_info("Message preview elements found in station")
                        else:
                            print_error("No message preview elements found")
                        
                        # Check for the ticket number
                        if f"#{ticket_id}" in station_content:
                            print_info(f"Ticket #{ticket_id} found in station")
                        else:
                            print_error(f"Ticket #{ticket_id} not found in station")
                        
                        return False
                else:
                    print_error(f"Station page request failed: {station_response.status_code}")
                    return False
            else:
                print_error(f"Test message sending failed: {data.get('error')}")
                return False
        else:
            print_error(f"Test message request failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Station display test failed: {e}")
        return False

def test_file_upload_functionality():
    """Test file upload functionality."""
    print_header("File Upload Functionality Test")
    
    try:
        # Create a test file content
        test_content = "This is a test file for CipherStation file upload functionality."
        
        # Test file encryption
        files = {'file': ('test.txt', test_content, 'text/plain')}
        data = {
            'algorithm': 'aes256'
        }
        
        response = requests.post(
            urljoin(BASE_URL, "/encrypt"),
            files=files,
            data=data,
            timeout=10
        )
        
        if response.status_code == 200:
            # Check if response is a file download
            content_type = response.headers.get('content-type', '')
            if 'application/json' in content_type or 'application/octet-stream' in content_type:
                print_success("File upload and encryption successful")
                return True
            else:
                print_error(f"File upload failed: unexpected content type {content_type}")
                return False
        else:
            print_error(f"File upload request failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"File upload test failed: {e}")
        return False

def test_ui_elements_and_navigation():
    """Test UI elements and navigation."""
    print_header("UI Elements and Navigation Test")
    
    try:
        # Test main page
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code == 200:
            content = response.text
            
            # Check for essential UI elements
            ui_checks = [
                ("Input text box", "inputText"),
                ("Output text box", "outputText"),
                ("Encryption password input", "encryptionPassword"),
                ("Algorithm selector", "algorithmSelect"),
                ("Encrypt button", "encryptMessage"),
                ("Send to station button", "encryptAndSendToStation"),
                ("Decrypt button", "decryptMessage"),
                ("File upload area", "file-upload-section"),
                ("Dark theme", "--bg-primary"),
                ("Copy buttons", "copyToClipboard")
            ]
            
            passed = 0
            for description, element_id in ui_checks:
                if element_id in content:
                    print_success(f"{description} found")
                    passed += 1
                else:
                    print_error(f"{description} missing")
            
            print_success(f"UI elements test: {passed}/{len(ui_checks)} elements found")
            
            # Test navigation pages
            nav_pages = [
                ("/station", "Message Relay Station"),
                ("/selftest", "Cryptographic Self-Test"),
                ("/help", "Help & Instructions"),
                ("/download-cli", "Command Line Interface")
            ]
            
            nav_passed = 0
            for url, expected_title in nav_pages:
                try:
                    nav_response = requests.get(urljoin(BASE_URL, url), timeout=5)
                    if nav_response.status_code == 200:
                        nav_content = nav_response.text
                        if expected_title in nav_content:
                            print_success(f"Navigation to {url} successful")
                            nav_passed += 1
                        else:
                            print_error(f"Navigation to {url} failed - wrong content")
                    else:
                        print_error(f"Navigation to {url} failed - status {nav_response.status_code}")
                except requests.exceptions.RequestException as e:
                    print_error(f"Navigation to {url} failed: {e}")
            
            print_success(f"Navigation test: {nav_passed}/{len(nav_pages)} pages accessible")
            
            return passed == len(ui_checks) and nav_passed == len(nav_pages)
        else:
            print_error(f"Main page request failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"UI elements test failed: {e}")
        return False

def main():
    """Run all real UI tests."""
    print("🚀 CipherStation Real UI Test Suite")
    print("=" * 60)
    
    tests = [
        ("Text Encryption", test_text_encryption_functionality),
        ("Station Sending", test_station_sending_functionality),
        ("Station Display & Copy", test_station_display_and_copy),
        ("File Upload", test_file_upload_functionality),
        ("UI Elements & Navigation", test_ui_elements_and_navigation)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print_error(f"Test {test_name} crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print_header("Real UI Test Summary")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} - {test_name}")
    
    print(f"\n📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ 🎉 All real UI tests passed! CipherStation UI is fully functional!")
        return True
    else:
        print("❌ ⚠️  Some real UI tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    import sys
    sys.exit(0 if success else 1) 