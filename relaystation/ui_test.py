#!/usr/bin/env python3
"""
CipherStation UI Test Suite
Tests all UI functionality including buttons, forms, and user interactions.
"""

import time
import sys
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# Configuration
BASE_URL = "http://localhost:5001"
TEST_MESSAGE = "Hello, this is a test message for CipherStation!"
TEST_KEY_32 = "12345678901234567890123456789012"  # Exactly 32 bytes for AES-256

def setup_driver():
    """Setup Chrome driver with headless mode."""
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(10)
        return driver
    except Exception as e:
        print(f"❌ Failed to setup Chrome driver: {e}")
        print("Please install Chrome and chromedriver")
        return None

def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🧪 UI TESTING: {title}")
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

def test_page_load(driver, url, title):
    """Test if a page loads correctly."""
    try:
        driver.get(url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        if title in driver.title:
            print_success(f"Page loaded: {title}")
            return True
        else:
            print_error(f"Page title mismatch. Expected: {title}, Got: {driver.title}")
            return False
    except Exception as e:
        print_error(f"Failed to load page: {e}")
        return False

def test_main_page_ui(driver):
    """Test main page UI elements."""
    print_header("Main Page UI Test")
    
    if not test_page_load(driver, BASE_URL, "CipherStation"):
        return False
    
    try:
        # Test if key elements are present
        elements_to_test = [
            ("inputText", "Input text box"),
            ("outputText", "Output text box"),
            ("encryptionKey", "Encryption key input"),
            ("algorithmSelect", "Algorithm selector"),
            ("copyOutputBtn", "Copy output button")
        ]
        
        passed = 0
        for element_id, description in elements_to_test:
            try:
                element = driver.find_element(By.ID, element_id)
                if element.is_displayed():
                    print_success(f"{description} found and visible")
                    passed += 1
                else:
                    print_error(f"{description} found but not visible")
            except NoSuchElementException:
                print_error(f"{description} not found")
        
        # Test algorithm options
        algorithm_select = driver.find_element(By.ID, "algorithmSelect")
        options = algorithm_select.find_elements(By.TAG_NAME, "option")
        expected_algorithms = ["aes256", "aes192", "aes128", "chacha20"]
        
        for expected in expected_algorithms:
            found = any(opt.get_attribute("value") == expected for opt in options)
            if found:
                print_success(f"Algorithm {expected} found")
                passed += 1
            else:
                print_error(f"Algorithm {expected} not found")
        
        print_success(f"Main page UI test: {passed}/{len(elements_to_test) + len(expected_algorithms)} elements working")
        return passed == len(elements_to_test) + len(expected_algorithms)
        
    except Exception as e:
        print_error(f"Main page UI test failed: {e}")
        return False

def test_encryption_functionality(driver):
    """Test encryption functionality."""
    print_header("Encryption Functionality Test")
    
    try:
        # Navigate to main page
        driver.get(BASE_URL)
        
        # Fill in the form
        input_text = driver.find_element(By.ID, "inputText")
        input_text.clear()
        input_text.send_keys(TEST_MESSAGE)
        
        encryption_key = driver.find_element(By.ID, "encryptionKey")
        encryption_key.clear()
        encryption_key.send_keys(TEST_KEY_32)
        
        # Select AES-256 algorithm
        algorithm_select = driver.find_element(By.ID, "algorithmSelect")
        algorithm_select.click()
        aes256_option = driver.find_element(By.CSS_SELECTOR, "option[value='aes256']")
        aes256_option.click()
        
        # Click encrypt button
        encrypt_btn = driver.find_element(By.CSS_SELECTOR, "button[onclick='encryptMessage()']")
        encrypt_btn.click()
        
        # Wait for result
        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "resultSection"))
            )
            
            result_section = driver.find_element(By.ID, "resultSection")
            if result_section.is_displayed():
                result_text = result_section.text
                if "success" in result_text.lower():
                    print_success("Encryption completed successfully")
                    
                    # Check if output text is filled
                    output_text = driver.find_element(By.ID, "outputText")
                    encrypted_value = output_text.get_attribute("value")
                    if encrypted_value and len(encrypted_value) > 0:
                        print_success("Encrypted text appears in output box")
                        return True
                    else:
                        print_error("Encrypted text not found in output box")
                        return False
                else:
                    print_error(f"Encryption failed: {result_text}")
                    return False
            else:
                print_error("Result section not displayed")
                return False
                
        except TimeoutException:
            print_error("Encryption timed out - no result after 10 seconds")
            return False
            
    except Exception as e:
        print_error(f"Encryption functionality test failed: {e}")
        return False

def test_navigation(driver):
    """Test navigation between pages."""
    print_header("Navigation Test")
    
    pages_to_test = [
        ("/station", "Message Relay Station"),
        ("/selftest", "Cryptographic Self-Test"),
        ("/help", "Help & Instructions"),
        ("/download-cli", "Command Line Interface")
    ]
    
    passed = 0
    for url, expected_title in pages_to_test:
        try:
            driver.get(BASE_URL + url)
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            if expected_title in driver.title or expected_title in driver.page_source:
                print_success(f"Navigation to {url} successful")
                passed += 1
            else:
                print_error(f"Navigation to {url} failed - title/content not found")
                
        except Exception as e:
            print_error(f"Navigation to {url} failed: {e}")
    
    print_success(f"Navigation test: {passed}/{len(pages_to_test)} pages accessible")
    return passed == len(pages_to_test)

def main():
    """Run all UI tests."""
    print("🚀 CipherStation UI Test Suite")
    print("=" * 60)
    
    # Setup driver
    driver = setup_driver()
    if not driver:
        return 1
    
    try:
        # Test results
        results = []
        
        # Run all tests
        tests = [
            ("Main Page UI", test_main_page_ui),
            ("Encryption Functionality", test_encryption_functionality),
            ("Navigation", test_navigation)
        ]
        
        for test_name, test_func in tests:
            try:
                result = test_func(driver)
                results.append((test_name, result))
            except Exception as e:
                print_error(f"{test_name} test crashed: {e}")
                results.append((test_name, False))
        
        # Print summary
        print_header("UI Test Summary")
        
        passed = sum(1 for _, result in results if result)
        total = len(results)
        
        print(f"📊 Results: {passed}/{total} tests passed")
        
        for test_name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"  {status} - {test_name}")
        
        if passed == total:
            print("✅ 🎉 All UI tests passed! CipherStation UI is working perfectly!")
            return 0
        else:
            print(f"❌ ⚠️  {total - passed} UI tests failed. Please check the implementation.")
            return 1
            
    finally:
        driver.quit()

if __name__ == "__main__":
    sys.exit(main()) 