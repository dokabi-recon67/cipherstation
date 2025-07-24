#!/usr/bin/env python3
"""
CipherStation Live Demo Script
Automated browser demonstration of all CipherStation capabilities

This script opens a browser and demonstrates:
1. Relay Station - Complete 6-step secure messaging workflow
2. Auto-Cracker - Classical cipher cracking with various algorithms
3. Self-Test - Comprehensive system testing with terminal output
4. Documentation - Complete feature overview

Requirements:
- pip install selenium webdriver-manager
- Chrome browser installed
"""

import time
import random
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from webdriver_manager.chrome import ChromeDriverManager

class CipherStationDemo:
    def __init__(self, base_url="http://localhost:5002"):
        self.base_url = base_url
        self.driver = None
        self.wait = None
        
    def setup_browser(self):
        """Setup Chrome browser with optimal settings for demo"""
        print("🚀 Setting up browser for CipherStation demo...")
        
        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--disable-features=VizDisplayCompositor")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        chrome_options.add_experimental_option("detach", True)  # Keep browser open
        
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=chrome_options)
        self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        self.wait = WebDriverWait(self.driver, 15)
        
        print("✅ Browser ready!")
        
    def demo_pause(self, seconds=2, message=""):
        """Pause with optional message for demo pacing"""
        if message:
            print(f"⏸️  {message}")
        time.sleep(seconds)
        
    def type_slowly(self, element, text, delay=0.08):
        """Type text slowly for demo effect"""
        element.clear()
        time.sleep(0.5)  # Pause before typing
        for char in text:
            element.send_keys(char)
            time.sleep(delay)
        time.sleep(0.3)  # Pause after typing
            
    def scroll_to_element(self, element):
        """Scroll element into view"""
        self.driver.execute_script("arguments[0].scrollIntoView(true);", element)
        time.sleep(0.5)
        
    def highlight_element(self, element, duration=1):
        """Highlight element with border for demo"""
        original_style = element.get_attribute("style")
        self.driver.execute_script(
            "arguments[0].style.border='4px solid #ff6b6b'; arguments[0].style.backgroundColor='rgba(255,107,107,0.2)'; arguments[0].style.boxShadow='0 0 10px rgba(255,107,107,0.5)';", 
            element
        )
        time.sleep(duration)
        self.driver.execute_script(f"arguments[0].style='{original_style}';", element)

    def demonstrate_relay_station(self):
        """Demonstrate complete 6-step relay station workflow"""
        print("\n🎯 DEMONSTRATING RELAY STATION")
        print("=" * 50)
        
        # Navigate to homepage
        self.driver.get(self.base_url)
        self.demo_pause(3, "Loading CipherStation homepage...")
        
        # Wait for page to load and scroll to show the interface
        self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        self.demo_pause(2, "Page loaded, showing interface...")
        
        # Scroll down to show the first step
        self.driver.execute_script("window.scrollTo(0, 300);")
        self.demo_pause(2, "Scrolling to Step 1...")
        
        print("📝 Step 1: Apply Classical Cipher")
        
        # Step 1: Apply Cipher
        plaintext_input = self.wait.until(EC.element_to_be_clickable((By.ID, "plaintext_input")))
        self.scroll_to_element(plaintext_input)
        self.highlight_element(plaintext_input, 2)
        
        demo_message = "SECRET RELAY STATION DEMO MESSAGE"
        print(f"⌨️  Typing: '{demo_message}'")
        self.type_slowly(plaintext_input, demo_message, 0.06)
        self.demo_pause(2, "Message entered...")
        
        # Select cipher type
        cipher_select = Select(self.driver.find_element(By.ID, "cipher_type"))
        self.highlight_element(cipher_select.element, 1)
        cipher_select.select_by_value("caesar")
        self.demo_pause(2, "Selected Caesar cipher...")
        
        # Set key
        key_input = self.driver.find_element(By.ID, "cipher_key")
        self.highlight_element(key_input, 1)
        print("⌨️  Setting cipher key: 7")
        self.type_slowly(key_input, "7", 0.2)
        self.demo_pause(2, "Key set to 7...")
        
        # Apply cipher
        apply_btn = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Apply Cipher')]")
        self.highlight_element(apply_btn, 2)
        print("🔐 Applying Caesar cipher with shift 7...")
        apply_btn.click()
        self.demo_pause(4, "Cipher applied successfully!")
        
        print("🔐 Step 2: Modern Encryption")
        
        # Scroll to Step 2
        self.driver.execute_script("window.scrollTo(0, 600);")
        self.demo_pause(2, "Scrolling to Step 2...")
        
        # Step 2: Encrypt
        password_input = self.wait.until(EC.element_to_be_clickable((By.ID, "enc_password")))
        self.scroll_to_element(password_input)
        self.highlight_element(password_input, 2)
        print("⌨️  Entering encryption password...")
        self.type_slowly(password_input, "DemoPassword123!", 0.08)
        self.demo_pause(2, "Password entered...")
        
        # Select encryption algorithm
        algorithm_select = Select(self.driver.find_element(By.ID, "enc_algorithm"))
        self.highlight_element(algorithm_select.element, 1)
        algorithm_select.select_by_value("aes256")
        self.demo_pause(2, "Selected AES-256-GCM algorithm...")
        
        # Encrypt
        encrypt_btn = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Encrypt Message')]")
        self.highlight_element(encrypt_btn, 2)
        print("🔐 Encrypting with AES-256-GCM...")
        encrypt_btn.click()
        self.demo_pause(5, "Message encrypted successfully!")
        
        print("📡 Step 3: Send to Relay Station")
        
        # Step 3: Send to Station
        send_btn = self.wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Send to Station')]")))
        self.scroll_to_element(send_btn)
        self.highlight_element(send_btn, 2)
        print("📡 Sending encrypted message to relay station...")
        send_btn.click()
        self.demo_pause(4, "Message sent to station! Ticket generated...")
        
        print("📋 Step 4: Browse Public Message Board")
        
        # Scroll to Step 4
        self.driver.execute_script("window.scrollTo(0, 1000);")
        self.demo_pause(2, "Scrolling to Step 4...")
        
        # Step 4: Show message board
        message_board = self.wait.until(EC.presence_of_element_located((By.ID, "public_message_board")))
        self.scroll_to_element(message_board)
        self.highlight_element(message_board, 3)
        self.demo_pause(3, "Viewing live public message board...")
        
        # Click on a message from the board
        try:
            board_message = self.driver.find_element(By.CSS_SELECTOR, ".board-message")
            self.highlight_element(board_message, 2)
            print("📋 Clicking on message from public board...")
            board_message.click()
            self.demo_pause(3, "Message selected from board...")
        except:
            # Fallback: manual ticket entry
            ticket_input = self.driver.find_element(By.ID, "ticket_number")
            self.highlight_element(ticket_input, 1)
            print("⌨️  Entering ticket number manually...")
            self.type_slowly(ticket_input, "1001", 0.2)
            self.demo_pause(2, "Ticket number entered...")
        
        # Retrieve message
        retrieve_btn = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Retrieve Message')]")
        self.highlight_element(retrieve_btn, 2)
        print("📥 Retrieving encrypted message...")
        retrieve_btn.click()
        self.demo_pause(4, "Message retrieved successfully!")
        
        print("🔓 Step 5: Decrypt Message")
        
        # Scroll to Step 5
        self.driver.execute_script("window.scrollTo(0, 1400);")
        self.demo_pause(2, "Scrolling to Step 5...")
        
        # Step 5: Decrypt
        decrypt_password = self.driver.find_element(By.ID, "dec_password")
        self.scroll_to_element(decrypt_password)
        self.highlight_element(decrypt_password, 2)
        print("⌨️  Entering decryption password...")
        self.type_slowly(decrypt_password, "DemoPassword123!", 0.08)
        self.demo_pause(2, "Password entered...")
        
        # Decrypt
        decrypt_btn = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Decrypt Message')]")
        self.highlight_element(decrypt_btn, 2)
        print("🔓 Decrypting message...")
        decrypt_btn.click()
        self.demo_pause(4, "Message decrypted successfully!")
        
        print("🔑 Step 6: Decode Cipher")
        
        # Scroll to Step 6
        self.driver.execute_script("window.scrollTo(0, 1800);")
        self.demo_pause(2, "Scrolling to Step 6...")
        
        # Step 6: Decode
        decode_cipher_select = Select(self.driver.find_element(By.ID, "decode_cipher_type"))
        self.highlight_element(decode_cipher_select.element, 1)
        decode_cipher_select.select_by_value("caesar")
        self.demo_pause(2, "Selected Caesar cipher for decoding...")
        
        decode_key = self.driver.find_element(By.ID, "decode_key")
        self.highlight_element(decode_key, 1)
        print("⌨️  Setting decode key: 7")
        self.type_slowly(decode_key, "7", 0.2)
        self.demo_pause(2, "Decode key set...")
        
        # Final decode
        decode_btn = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Decode Cipher')]")
        self.highlight_element(decode_btn, 2)
        print("🔑 Decoding Caesar cipher...")
        decode_btn.click()
        self.demo_pause(5, "Cipher decoded! Original message revealed!")
        
        print("✅ Relay Station demonstration complete!")
        self.demo_pause(4, "Complete 6-step workflow demonstrated successfully!")

    def demonstrate_auto_cracker(self):
        """Demonstrate classical cipher auto-cracker"""
        print("\n🔍 DEMONSTRATING AUTO-CRACKER")
        print("=" * 50)
        
        # Navigate to classical cipher page
        self.driver.get(f"{self.base_url}/classical")
        self.demo_pause(3, "Loading Classical Cipher Cracker...")
        
        # Wait for page and scroll to show interface
        self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        self.driver.execute_script("window.scrollTo(0, 200);")
        self.demo_pause(2, "Showing cipher cracker interface...")
        
        # Test cases for different ciphers
        test_cases = [
            {
                'name': 'Caesar Cipher (Shift 3)',
                'ciphertext': 'WKLV LV D WHVW PHVVDJH',
                'expected': 'Caesar cipher with shift 3'
            },
            {
                'name': 'Vigenère Cipher',
                'ciphertext': 'ZINCS PGVNU DQJQX',
                'expected': 'Vigenère cipher with key'
            },
            {
                'name': 'Atbash Cipher',
                'ciphertext': 'GSVH RH ZM ZGYZHS XRKSVI',
                'expected': 'Atbash cipher'
            }
        ]
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"🧪 Test {i}: {test_case['name']}")
            
            # Enter ciphertext
            ciphertext_input = self.wait.until(EC.element_to_be_clickable((By.ID, "ciphertext_input")))
            self.scroll_to_element(ciphertext_input)
            self.highlight_element(ciphertext_input, 2)
            ciphertext_input.clear()
            print(f"⌨️  Entering ciphertext: '{test_case['ciphertext']}'")
            self.type_slowly(ciphertext_input, test_case['ciphertext'], 0.04)
            self.demo_pause(2, "Ciphertext entered...")
            
            # Start cracking
            crack_btn = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Crack Cipher')]")
            self.highlight_element(crack_btn, 2)
            print(f"🔍 Starting crack analysis for {test_case['name']}...")
            crack_btn.click()
            self.demo_pause(3, f"Analyzing {test_case['name']}...")
            
            # Wait for results and show progress
            try:
                # Wait for progress or results
                self.wait.until(EC.presence_of_element_located((By.ID, "crack_results")))
                self.demo_pause(3, "Analysis complete! Showing results...")
                
                # Highlight results
                results_section = self.driver.find_element(By.ID, "crack_results")
                self.scroll_to_element(results_section)
                self.highlight_element(results_section, 3)
                self.demo_pause(3, f"Results for {test_case['name']} displayed...")
                
            except:
                print(f"⚠️  Results not immediately available for {test_case['name']}")
                self.demo_pause(2, "Waiting for analysis to complete...")
            
            self.demo_pause(3)
        
        print("✅ Auto-cracker demonstration complete!")
        self.demo_pause(4, "All cipher cracking tests completed!")

    def demonstrate_self_test(self):
        """Demonstrate comprehensive self-test with scrolling terminal"""
        print("\n🧪 DEMONSTRATING SELF-TEST")
        print("=" * 50)
        
        # Navigate to self-test page
        self.driver.get(f"{self.base_url}/selftest")
        self.demo_pause(3, "Loading Self-Test page...")
        
        # Wait for page and scroll to show interface
        self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        self.driver.execute_script("window.scrollTo(0, 200);")
        self.demo_pause(2, "Showing self-test interface...")
        
        # Start self-test
        start_btn = self.wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Start Self-Test')]")))
        self.scroll_to_element(start_btn)
        self.highlight_element(start_btn, 3)
        print("🧪 Starting comprehensive system test...")
        start_btn.click()
        self.demo_pause(3, "Self-test initiated! Running 24 automated tests...")
        
        # Wait for terminal to appear
        try:
            terminal = self.wait.until(EC.presence_of_element_located((By.ID, "terminal-output")))
            self.scroll_to_element(terminal)
            
            # Monitor test progress
            print("📊 Monitoring test execution with live terminal output...")
            
            # Wait for tests to complete (or timeout after 60 seconds)
            start_time = time.time()
            while time.time() - start_time < 60:
                try:
                    # Check if results section is visible
                    results_section = self.driver.find_element(By.ID, "results-section")
                    if results_section.is_displayed():
                        break
                except:
                    pass
                
                # Scroll terminal to show activity
                self.driver.execute_script("arguments[0].scrollTop = arguments[0].scrollHeight;", terminal)
                time.sleep(3)  # Longer pause to show scrolling
            
            # Show final results
            self.demo_pause(3, "All tests completed! Showing comprehensive results...")
            
            try:
                results_section = self.driver.find_element(By.ID, "results-section")
                self.scroll_to_element(results_section)
                self.highlight_element(results_section, 4)
                
                # Highlight summary cards
                summary_cards = self.driver.find_elements(By.CSS_SELECTOR, ".summary-card")
                for card in summary_cards:
                    self.highlight_element(card, 2)
                    self.demo_pause(1)
                
                self.demo_pause(3, "All test results displayed successfully!")
                
            except:
                print("⚠️  Results section not found")
            
        except:
            print("⚠️  Terminal output not found")
        
        print("✅ Self-test demonstration complete!")
        self.demo_pause(4, "Complete system validation demonstrated!")

    def demonstrate_documentation(self):
        """Show documentation page"""
        print("\n📚 DEMONSTRATING DOCUMENTATION")
        print("=" * 50)
        
        # Navigate to documentation
        self.driver.get(f"{self.base_url}/documentation")
        self.demo_pause(2, "Loading Documentation page...")
        
        # Scroll through different sections
        sections = [
            "overview",
            "features", 
            "api-endpoints",
            "security",
            "examples"
        ]
        
        for section in sections:
            try:
                section_element = self.driver.find_element(By.ID, section)
                self.scroll_to_element(section_element)
                self.highlight_element(section_element, 2)
                self.demo_pause(2, f"Showing {section.replace('-', ' ').title()} section...")
            except:
                print(f"⚠️  Section {section} not found")
        
        # Scroll to top
        self.driver.execute_script("window.scrollTo(0, 0);")
        self.demo_pause(2, "Documentation overview complete!")
        
        print("✅ Documentation demonstration complete!")

    def run_full_demo(self):
        """Run the complete CipherStation demonstration"""
        print("🎬 STARTING CIPHERSTATION LIVE DEMO")
        print("=" * 60)
        print("This demo will showcase all CipherStation capabilities:")
        print("1. 🏪 Relay Station - Secure 6-step messaging")
        print("2. 🔍 Auto-Cracker - Classical cipher analysis") 
        print("3. 🧪 Self-Test - Comprehensive system testing")
        print("4. 📚 Documentation - Feature overview")
        print("=" * 60)
        
        try:
            self.setup_browser()
            
            # Run all demonstrations
            self.demonstrate_relay_station()
            self.demonstrate_auto_cracker() 
            self.demonstrate_self_test()
            self.demonstrate_documentation()
            
            print("\n🎉 DEMO COMPLETE!")
            print("=" * 60)
            print("✅ All CipherStation features demonstrated successfully!")
            print("🌐 Browser will remain open for further exploration")
            print("=" * 60)
            
        except Exception as e:
            print(f"❌ Demo error: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            # Keep browser open for manual exploration
            print("🔍 Browser kept open for manual exploration...")
            print("Press Ctrl+C to close when done.")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n👋 Closing demo...")
                if self.driver:
                    self.driver.quit()

if __name__ == "__main__":
    # Check if server is running
    import requests
    
    demo_url = "http://localhost:5002"
    
    try:
        response = requests.get(demo_url, timeout=5)
        print(f"✅ CipherStation server detected at {demo_url}")
    except:
        print(f"❌ CipherStation server not running at {demo_url}")
        print("Please start the server first:")
        print("cd relaystation && python -m flask run --host=0.0.0.0 --port=5002 --debug")
        exit(1)
    
    # Run the demo
    demo = CipherStationDemo(demo_url)
    demo.run_full_demo() 