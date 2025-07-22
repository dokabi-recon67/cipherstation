#!/usr/bin/env python3
"""
CipherStation Simple UI Test Suite
Tests core functionality without requiring browser automation.
"""

import requests
import time
import json
import sys
from urllib.parse import urljoin

# Configuration
BASE_URL = "http://localhost:5001"
TEST_MESSAGE = "Hello, this is a test message for CipherStation!"
TEST_PASSWORD = "mysecretpassword123"  # Any password works now

def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🧪 SIMPLE UI TESTING: {title}")
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

def test_server_running():
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

def test_main_page_elements():
    """Test if main page has all required elements."""
    print_header("Main Page Elements Test")
    
    try:
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code == 200:
            content = response.text
            
            # Check for essential UI elements
            elements_to_check = [
                ("Input text box", "inputText"),
                ("Output text box", "outputText"),
                ("Encryption password input", "encryptionPassword"),
                ("Algorithm selector", "algorithmSelect"),
                ("Copy button", "copyOutputBtn"),
                ("Encrypt button", "encryptMessage"),
                ("Decrypt button", "decryptMessage"),
                ("File upload area", "file-upload-section"),
                ("Message station link", "/station"),
                ("Dark theme", "--bg-primary")
            ]
            
            passed = 0
            for description, element_id in elements_to_check:
                if element_id in content:
                    print_success(f"{description} found")
                    passed += 1
                else:
                    print_error(f"{description} missing")
            
            print_success(f"Main page elements: {passed}/{len(elements_to_check)} found")
            return passed == len(elements_to_check)
        else:
            print_error(f"Main page returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Main page request failed: {e}")
        return False

def test_encryption_api():
    """Test encryption API functionality."""
    print_header("Encryption API Test")
    
    algorithms = [
        ("aes256", TEST_PASSWORD),
        ("aes192", TEST_PASSWORD),
        ("aes128", TEST_PASSWORD),
        ("chacha20", TEST_PASSWORD)
    ]
    passed = 0
    
    for algorithm, password in algorithms:
        try:
            print_info(f"Testing {algorithm.upper()}...")
            
            # Test encryption
            encrypt_data = {
                "text": TEST_MESSAGE,
                "password": password,
                "algorithm": algorithm
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
                        print_success(f"{algorithm.upper()} encryption successful")
                        
                        # Test decryption
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
                                    print_success(f"{algorithm.upper()} decryption successful")
                                    passed += 1
                                else:
                                    print_error(f"{algorithm.upper()} decryption failed - text mismatch")
                            else:
                                print_error(f"{algorithm.upper()} decryption failed: {decrypt_data.get('error')}")
                        else:
                            print_error(f"{algorithm.upper()} decryption request failed: {decrypt_response.status_code}")
                    else:
                        print_error(f"{algorithm.upper()} encryption failed - no encrypted text returned")
                else:
                    print_error(f"{algorithm.upper()} encryption failed: {data.get('error')}")
            else:
                print_error(f"{algorithm.upper()} encryption request failed: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print_error(f"{algorithm.upper()} test failed: {e}")
    
    print_success(f"Encryption API test: {passed}/{len(algorithms)} algorithms working")
    return passed == len(algorithms)

def test_message_station():
    """Test message station functionality."""
    print_header("Message Station Test")
    
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
                print_success(f"Message sent to station with ticket #{ticket_id}")
                
                # Check station page
                station_response = requests.get(urljoin(BASE_URL, "/station"), timeout=5)
                if station_response.status_code == 200:
                    station_content = station_response.text
                    if "Message Relay Station" in station_content:
                        print_success("Station page loads correctly")
                        
                        # Check if message appears in station
                        if f"#{ticket_id}" in station_content:
                            print_success(f"Message with ticket #{ticket_id} found in station")
                            return True
                        else:
                            print_error(f"Message with ticket #{ticket_id} not found in station")
                            return False
                    else:
                        print_error("Station page content incorrect")
                        return False
                else:
                    print_error(f"Station page request failed: {station_response.status_code}")
                    return False
            else:
                print_error(f"Station submission failed: {data.get('error')}")
                return False
        else:
            print_error(f"Station submission request failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Message station test failed: {e}")
        return False

def test_file_upload_api():
    """Test file upload API functionality."""
    print_header("File Upload API Test")
    
    try:
        # Create a test file
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
            # Check if response is a file download (encrypted file)
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

def test_navigation_pages():
    """Test all navigation pages load correctly."""
    print_header("Navigation Pages Test")
    
    pages_to_test = [
        ("/station", "Message Relay Station"),
        ("/selftest", "Cryptographic Self-Test"),
        ("/help", "Help & Instructions"),
        ("/download-cli", "Command Line Interface")
    ]
    
    passed = 0
    for url, expected_title in pages_to_test:
        try:
            response = requests.get(urljoin(BASE_URL, url), timeout=5)
            if response.status_code == 200:
                content = response.text
                if expected_title in content:
                    print_success(f"Page {url} loads correctly")
                    passed += 1
                else:
                    print_error(f"Page {url} content incorrect")
            else:
                print_error(f"Page {url} returned status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print_error(f"Page {url} request failed: {e}")
    
    print_success(f"Navigation pages test: {passed}/{len(pages_to_test)} pages working")
    return passed == len(pages_to_test)

import requests

BASE = 'http://127.0.0.1:5001'

def test_interactive_mode():
    # Start session
    r = requests.post(f'{BASE}/api/interactive/start', json={'text': 'KHOOR ZRUOG'})
    assert r.ok and r.json().get('success')
    session_id = r.json()['session_id']
    # Lock letters
    r = requests.post(f'{BASE}/api/interactive/lock', json={'session_id': session_id, 'locked_letters': {'0': 'H'}})
    assert r.ok and r.json().get('success')
    # Suggest key
    r = requests.post(f'{BASE}/api/interactive/suggest', json={'session_id': session_id, 'key': 'KEY'})
    assert r.ok and r.json().get('success')
    # Step
    r = requests.post(f'{BASE}/api/interactive/step', json={'session_id': session_id})
    assert r.ok and r.json().get('success')
    # Status
    r = requests.get(f'{BASE}/api/interactive/status/{session_id}')
    assert r.ok and r.json().get('success')

def test_ciphershare_ui():
    # Submit
    r = requests.post(f'{BASE}/api/ciphershare/submit', json={
        'ciphertext': 'KHOOR ZRUOG',
        'plaintext': 'HELLO WORLD',
        'pipeline': 'caesar',
        'tags': ['test', 'caesar']
    })
    assert r.ok and r.json().get('success')
    # Metadata
    r = requests.get(f'{BASE}/api/ciphershare/metadata')
    assert r.ok and r.json().get('success')
    assert any('KHOOR ZRUOG' in m['ciphertext'] for m in r.json()['metadata'])

def main():
    test_interactive_mode()
    test_ciphershare_ui()
    print('Web UI tests passed.')

if __name__ == '__main__':
    main()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 