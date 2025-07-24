#!/usr/bin/env python3
"""
Modern Cryptography Test Suite for CipherStation
Testing AES-256-GCM, ChaCha20-Poly1305, Ed25519, X25519, and hybrid encryption
"""

import time
import sys
import os
import json
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List, Tuple, Any
import hashlib

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class ModernCryptoTester:
    def __init__(self):
        self.results = {
            'test_start_time': datetime.now().isoformat(),
            'key_generation_tests': {},
            'encryption_tests': {},
            'decryption_tests': {},
            'signature_tests': {},
            'hybrid_tests': {},
            'performance_data': {},
            'error_log': []
        }
        
    def test_key_generation(self) -> Dict[str, Any]:
        """Test key generation for various algorithms"""
        print("Testing Key Generation...")
        results = {
            'aes_keys': [],
            'ed25519_keys': [],
            'x25519_keys': [],
            'performance': {}
        }
        
        # Test AES key generation
        aes_sizes = ['aes128', 'aes192', 'aes256']
        for size in aes_sizes:
            start_time = time.time()
            try:
                result = subprocess.run(
                    ['python3', 'cipherstationv0.py', 'keygen', size, '--out', f'{size}_test.key'],
                    capture_output=True, text=True, timeout=10
                )
                execution_time = time.time() - start_time
                
                # Check if key file was created
                key_exists = os.path.exists(f'{size}_test.key')
                key_size = os.path.getsize(f'{size}_test.key') if key_exists else 0
                
                results['aes_keys'].append({
                    'algorithm': size,
                    'success': result.returncode == 0 and key_exists,
                    'execution_time': execution_time,
                    'key_size_bytes': key_size,
                    'stdout_length': len(result.stdout),
                    'stderr_length': len(result.stderr)
                })
                
                # Clean up
                if key_exists:
                    os.remove(f'{size}_test.key')
                    
            except subprocess.TimeoutExpired:
                results['aes_keys'].append({
                    'algorithm': size,
                    'success': False,
                    'execution_time': 10.0,
                    'error': 'Timeout'
                })
            except Exception as e:
                results['aes_keys'].append({
                    'algorithm': size,
                    'success': False,
                    'execution_time': 0.0,
                    'error': str(e)
                })
        
        # Test Ed25519 key generation
        start_time = time.time()
        try:
            result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'keygen', 'ed25519', '--priv', 'ed25519_priv.key', '--pub', 'ed25519_pub.key'],
                capture_output=True, text=True, timeout=10
            )
            execution_time = time.time() - start_time
            
            priv_exists = os.path.exists('ed25519_priv.key')
            pub_exists = os.path.exists('ed25519_pub.key')
            
            results['ed25519_keys'].append({
                'success': result.returncode == 0 and priv_exists and pub_exists,
                'execution_time': execution_time,
                'private_key_size': os.path.getsize('ed25519_priv.key') if priv_exists else 0,
                'public_key_size': os.path.getsize('ed25519_pub.key') if pub_exists else 0,
                'stdout_length': len(result.stdout),
                'stderr_length': len(result.stderr)
            })
            
            # Clean up
            if priv_exists:
                os.remove('ed25519_priv.key')
            if pub_exists:
                os.remove('ed25519_pub.key')
                
        except Exception as e:
            results['ed25519_keys'].append({
                'success': False,
                'execution_time': 0.0,
                'error': str(e)
            })
        
        # Test X25519 key generation
        start_time = time.time()
        try:
            result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'keygen', 'x25519', '--priv', 'x25519_priv.key', '--pub', 'x25519_pub.key'],
                capture_output=True, text=True, timeout=10
            )
            execution_time = time.time() - start_time
            
            priv_exists = os.path.exists('x25519_priv.key')
            pub_exists = os.path.exists('x25519_pub.key')
            
            results['x25519_keys'].append({
                'success': result.returncode == 0 and priv_exists and pub_exists,
                'execution_time': execution_time,
                'private_key_size': os.path.getsize('x25519_priv.key') if priv_exists else 0,
                'public_key_size': os.path.getsize('x25519_pub.key') if pub_exists else 0,
                'stdout_length': len(result.stdout),
                'stderr_length': len(result.stderr)
            })
            
            # Clean up
            if priv_exists:
                os.remove('x25519_priv.key')
            if pub_exists:
                os.remove('x25519_pub.key')
                
        except Exception as e:
            results['x25519_keys'].append({
                'success': False,
                'execution_time': 0.0,
                'error': str(e)
            })
        
        # Calculate performance metrics
        results['performance'] = {
            'aes_success_rate': sum(1 for t in results['aes_keys'] if t['success']) / len(results['aes_keys']),
            'ed25519_success_rate': sum(1 for t in results['ed25519_keys'] if t['success']) / len(results['ed25519_keys']),
            'x25519_success_rate': sum(1 for t in results['x25519_keys'] if t['success']) / len(results['x25519_keys']),
            'avg_aes_time': sum(t['execution_time'] for t in results['aes_keys']) / len(results['aes_keys']),
            'avg_ed25519_time': sum(t['execution_time'] for t in results['ed25519_keys']) / len(results['ed25519_keys']),
            'avg_x25519_time': sum(t['execution_time'] for t in results['x25519_keys']) / len(results['x25519_keys'])
        }
        
        return results
    
    def test_encryption_decryption(self) -> Dict[str, Any]:
        """Test encryption and decryption with various algorithms"""
        print("Testing Encryption/Decryption...")
        results = {
            'aes_tests': [],
            'chacha_tests': [],
            'password_tests': [],
            'performance': {}
        }
        
        # Create test data
        test_data = "This is a test message for encryption. It contains various characters: 123!@#$%^&*()"
        
        # Test AES-256-GCM encryption/decryption
        start_time = time.time()
        try:
            # Generate key
            subprocess.run(['python3', 'cipherstationv0.py', 'keygen', 'aes256', '--out', 'aes_test.key'], 
                         capture_output=True, check=True)
            
            # Create test file
            with open('test_data.txt', 'w') as f:
                f.write(test_data)
            
            # Encrypt
            encrypt_start = time.time()
            encrypt_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'encrypt', '--alg', 'aes256', '--key', 'aes_test.key', 
                 '--infile', 'test_data.txt', '--out', 'encrypted_aes.json'],
                capture_output=True, text=True, timeout=30
            )
            encrypt_time = time.time() - encrypt_start
            
            # Decrypt
            decrypt_start = time.time()
            decrypt_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'decrypt', '--key', 'aes_test.key', 
                 '--infile', 'encrypted_aes.json', '--out', 'decrypted_aes.txt'],
                capture_output=True, text=True, timeout=30
            )
            decrypt_time = time.time() - decrypt_start
            
            # Verify
            with open('decrypted_aes.txt', 'r') as f:
                decrypted_data = f.read()
            
            success = decrypted_data == test_data
            total_time = time.time() - start_time
            
            results['aes_tests'].append({
                'success': success,
                'encrypt_time': encrypt_time,
                'decrypt_time': decrypt_time,
                'total_time': total_time,
                'data_size': len(test_data),
                'encrypted_size': os.path.getsize('encrypted_aes.json') if os.path.exists('encrypted_aes.json') else 0,
                'encrypt_success': encrypt_result.returncode == 0,
                'decrypt_success': decrypt_result.returncode == 0
            })
            
            # Clean up
            for file in ['aes_test.key', 'test_data.txt', 'encrypted_aes.json', 'decrypted_aes.txt']:
                if os.path.exists(file):
                    os.remove(file)
                    
        except Exception as e:
            results['aes_tests'].append({
                'success': False,
                'error': str(e)
            })
        
        # Test ChaCha20-Poly1305 encryption/decryption
        start_time = time.time()
        try:
            # Generate key
            subprocess.run(['python3', 'cipherstationv0.py', 'keygen', 'aes256', '--out', 'chacha_test.key'], 
                         capture_output=True, check=True)
            
            # Create test file
            with open('test_data.txt', 'w') as f:
                f.write(test_data)
            
            # Encrypt
            encrypt_start = time.time()
            encrypt_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'encrypt', '--alg', 'chacha20', '--key', 'chacha_test.key', 
                 '--infile', 'test_data.txt', '--out', 'encrypted_chacha.json'],
                capture_output=True, text=True, timeout=30
            )
            encrypt_time = time.time() - encrypt_start
            
            # Decrypt
            decrypt_start = time.time()
            decrypt_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'decrypt', '--key', 'chacha_test.key', 
                 '--infile', 'encrypted_chacha.json', '--out', 'decrypted_chacha.txt'],
                capture_output=True, text=True, timeout=30
            )
            decrypt_time = time.time() - decrypt_start
            
            # Verify
            with open('decrypted_chacha.txt', 'r') as f:
                decrypted_data = f.read()
            
            success = decrypted_data == test_data
            total_time = time.time() - start_time
            
            results['chacha_tests'].append({
                'success': success,
                'encrypt_time': encrypt_time,
                'decrypt_time': decrypt_time,
                'total_time': total_time,
                'data_size': len(test_data),
                'encrypted_size': os.path.getsize('encrypted_chacha.json') if os.path.exists('encrypted_chacha.json') else 0,
                'encrypt_success': encrypt_result.returncode == 0,
                'decrypt_success': decrypt_result.returncode == 0
            })
            
            # Clean up
            for file in ['chacha_test.key', 'test_data.txt', 'encrypted_chacha.json', 'decrypted_chacha.txt']:
                if os.path.exists(file):
                    os.remove(file)
                    
        except Exception as e:
            results['chacha_tests'].append({
                'success': False,
                'error': str(e)
            })
        
        # Test password-based encryption
        start_time = time.time()
        try:
            # Create test file
            with open('test_data.txt', 'w') as f:
                f.write(test_data)
            
            # Encrypt with password
            encrypt_start = time.time()
            encrypt_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'encrypt', '--password', 
                 '--infile', 'test_data.txt', '--out', 'encrypted_pwd.json'],
                capture_output=True, text=True, timeout=30, input='testpassword\n'
            )
            encrypt_time = time.time() - encrypt_start
            
            # Decrypt with password
            decrypt_start = time.time()
            decrypt_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'decrypt', '--password', 
                 '--infile', 'encrypted_pwd.json', '--out', 'decrypted_pwd.txt'],
                capture_output=True, text=True, timeout=30, input='testpassword\n'
            )
            decrypt_time = time.time() - decrypt_start
            
            # Verify
            with open('decrypted_pwd.txt', 'r') as f:
                decrypted_data = f.read()
            
            success = decrypted_data == test_data
            total_time = time.time() - start_time
            
            results['password_tests'].append({
                'success': success,
                'encrypt_time': encrypt_time,
                'decrypt_time': decrypt_time,
                'total_time': total_time,
                'data_size': len(test_data),
                'encrypted_size': os.path.getsize('encrypted_pwd.json') if os.path.exists('encrypted_pwd.json') else 0,
                'encrypt_success': encrypt_result.returncode == 0,
                'decrypt_success': decrypt_result.returncode == 0
            })
            
            # Clean up
            for file in ['test_data.txt', 'encrypted_pwd.json', 'decrypted_pwd.txt']:
                if os.path.exists(file):
                    os.remove(file)
                    
        except Exception as e:
            results['password_tests'].append({
                'success': False,
                'error': str(e)
            })
        
        # Calculate performance metrics
        results['performance'] = {
            'aes_success_rate': sum(1 for t in results['aes_tests'] if t['success']) / len(results['aes_tests']),
            'chacha_success_rate': sum(1 for t in results['chacha_tests'] if t['success']) / len(results['chacha_tests']),
            'password_success_rate': sum(1 for t in results['password_tests'] if t['success']) / len(results['password_tests']),
            'avg_aes_encrypt_time': sum(t['encrypt_time'] for t in results['aes_tests']) / len(results['aes_tests']),
            'avg_aes_decrypt_time': sum(t['decrypt_time'] for t in results['aes_tests']) / len(results['aes_tests']),
            'avg_chacha_encrypt_time': sum(t['encrypt_time'] for t in results['chacha_tests']) / len(results['chacha_tests']),
            'avg_chacha_decrypt_time': sum(t['decrypt_time'] for t in results['chacha_tests']) / len(results['chacha_tests'])
        }
        
        return results
    
    def test_digital_signatures(self) -> Dict[str, Any]:
        """Test digital signature generation and verification"""
        print("Testing Digital Signatures...")
        results = {
            'signature_tests': [],
            'performance': {}
        }
        
        # Create test data
        test_data = "This is a test message for digital signature verification."
        
        try:
            # Generate Ed25519 keypair
            subprocess.run(['python3', 'cipherstationv0.py', 'keygen', 'ed25519', '--priv', 'ed25519_priv.key', '--pub', 'ed25519_pub.key'], 
                         capture_output=True, check=True)
            
            # Create test file
            with open('test_document.txt', 'w') as f:
                f.write(test_data)
            
            # Sign the document
            sign_start = time.time()
            sign_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'sign', '--priv', 'ed25519_priv.key', 
                 '--infile', 'test_document.txt', '--sig', 'signature.json'],
                capture_output=True, text=True, timeout=30
            )
            sign_time = time.time() - sign_start
            
            # Verify the signature
            verify_start = time.time()
            verify_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'verify', '--sig', 'signature.json', 
                 '--pub', 'ed25519_pub.key', '--infile', 'test_document.txt'],
                capture_output=True, text=True, timeout=30
            )
            verify_time = time.time() - verify_start
            
            # Test with modified document (should fail)
            with open('modified_document.txt', 'w') as f:
                f.write(test_data + " MODIFIED")
            
            verify_modified_start = time.time()
            verify_modified_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'verify', '--sig', 'signature.json', 
                 '--pub', 'ed25519_pub.key', '--infile', 'modified_document.txt'],
                capture_output=True, text=True, timeout=30
            )
            verify_modified_time = time.time() - verify_modified_start
            
            results['signature_tests'].append({
                'sign_success': sign_result.returncode == 0,
                'verify_success': verify_result.returncode == 0,
                'verify_modified_failure': verify_modified_result.returncode != 0,
                'sign_time': sign_time,
                'verify_time': verify_time,
                'verify_modified_time': verify_modified_time,
                'signature_size': os.path.getsize('signature.json') if os.path.exists('signature.json') else 0,
                'document_size': len(test_data)
            })
            
            # Clean up
            for file in ['ed25519_priv.key', 'ed25519_pub.key', 'test_document.txt', 'modified_document.txt', 'signature.json']:
                if os.path.exists(file):
                    os.remove(file)
                    
        except Exception as e:
            results['signature_tests'].append({
                'success': False,
                'error': str(e)
            })
        
        # Calculate performance metrics
        if results['signature_tests']:
            test = results['signature_tests'][0]
            results['performance'] = {
                'sign_success_rate': 1.0 if test.get('sign_success', False) else 0.0,
                'verify_success_rate': 1.0 if test.get('verify_success', False) else 0.0,
                'tamper_detection_rate': 1.0 if test.get('verify_modified_failure', False) else 0.0,
                'avg_sign_time': test.get('sign_time', 0),
                'avg_verify_time': test.get('verify_time', 0)
            }
        
        return results
    
    def test_hybrid_encryption(self) -> Dict[str, Any]:
        """Test hybrid encryption (X25519 + AES)"""
        print("Testing Hybrid Encryption...")
        results = {
            'hybrid_tests': [],
            'performance': {}
        }
        
        # Create test data
        test_data = "This is a test message for hybrid encryption using X25519 key exchange and AES encryption."
        
        try:
            # Generate X25519 keypairs for sender and recipient
            subprocess.run(['python3', 'cipherstationv0.py', 'keygen', 'x25519', '--priv', 'sender_priv.key', '--pub', 'sender_pub.key'], 
                         capture_output=True, check=True)
            subprocess.run(['python3', 'cipherstationv0.py', 'keygen', 'x25519', '--priv', 'recipient_priv.key', '--pub', 'recipient_pub.key'], 
                         capture_output=True, check=True)
            
            # Create test file
            with open('test_hybrid.txt', 'w') as f:
                f.write(test_data)
            
            # Encrypt for recipient
            encrypt_start = time.time()
            encrypt_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'hybrid-encrypt', '--peer-pub', 'recipient_pub.key', 
                 '--infile', 'test_hybrid.txt', '--out', 'hybrid_encrypted.json'],
                capture_output=True, text=True, timeout=30
            )
            encrypt_time = time.time() - encrypt_start
            
            # Decrypt with recipient's private key
            decrypt_start = time.time()
            decrypt_result = subprocess.run(
                ['python3', 'cipherstationv0.py', 'hybrid-decrypt', '--priv', 'recipient_priv.key', 
                 '--infile', 'hybrid_encrypted.json', '--out', 'hybrid_decrypted.txt'],
                capture_output=True, text=True, timeout=30
            )
            decrypt_time = time.time() - decrypt_start
            
            # Verify
            with open('hybrid_decrypted.txt', 'r') as f:
                decrypted_data = f.read()
            
            success = decrypted_data == test_data
            total_time = time.time() - encrypt_start
            
            results['hybrid_tests'].append({
                'success': success,
                'encrypt_time': encrypt_time,
                'decrypt_time': decrypt_time,
                'total_time': total_time,
                'data_size': len(test_data),
                'encrypted_size': os.path.getsize('hybrid_encrypted.json') if os.path.exists('hybrid_encrypted.json') else 0,
                'encrypt_success': encrypt_result.returncode == 0,
                'decrypt_success': decrypt_result.returncode == 0
            })
            
            # Clean up
            for file in ['sender_priv.key', 'sender_pub.key', 'recipient_priv.key', 'recipient_pub.key', 
                        'test_hybrid.txt', 'hybrid_encrypted.json', 'hybrid_decrypted.txt']:
                if os.path.exists(file):
                    os.remove(file)
                    
        except Exception as e:
            results['hybrid_tests'].append({
                'success': False,
                'error': str(e)
            })
        
        # Calculate performance metrics
        results['performance'] = {
            'hybrid_success_rate': sum(1 for t in results['hybrid_tests'] if t['success']) / len(results['hybrid_tests']),
            'avg_hybrid_encrypt_time': sum(t['encrypt_time'] for t in results['hybrid_tests']) / len(results['hybrid_tests']),
            'avg_hybrid_decrypt_time': sum(t['decrypt_time'] for t in results['hybrid_tests']) / len(results['hybrid_tests'])
        }
        
        return results
    
    def run_all_modern_crypto_tests(self) -> Dict[str, Any]:
        """Run all modern cryptography tests"""
        print("Starting Modern Cryptography Test Suite...")
        print(f"Test started at: {self.results['test_start_time']}")
        
        # Run individual test suites
        self.results['key_generation_tests'] = self.test_key_generation()
        self.results['encryption_tests'] = self.test_encryption_decryption()
        self.results['signature_tests'] = self.test_digital_signatures()
        self.results['hybrid_tests'] = self.test_hybrid_encryption()
        
        # Calculate overall metrics
        self.results['test_end_time'] = datetime.now().isoformat()
        self.results['overall_metrics'] = self._calculate_overall_metrics()
        
        return self.results
    
    def _calculate_overall_metrics(self) -> Dict[str, Any]:
        """Calculate overall performance metrics"""
        metrics = {
            'total_tests': 0,
            'successful_tests': 0,
            'overall_success_rate': 0.0,
            'avg_execution_time': 0.0,
            'test_summary': {}
        }
        
        # Aggregate metrics from all test suites
        test_suites = ['key_generation_tests', 'encryption_tests', 'signature_tests', 'hybrid_tests']
        
        for suite in test_suites:
            if suite in self.results and 'performance' in self.results[suite]:
                perf = self.results[suite]['performance']
                metrics['test_summary'][suite] = {
                    'success_rate': perf.get('aes_success_rate', 
                                           perf.get('hybrid_success_rate',
                                                   perf.get('sign_success_rate', 0))),
                    'avg_time': perf.get('avg_aes_time',
                                       perf.get('avg_hybrid_encrypt_time',
                                               perf.get('avg_sign_time', 0)))
                }
        
        return metrics
    
    def save_results(self, filename: str = None):
        """Save test results to file"""
        if filename is None:
            filename = f"modern_crypto_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"Modern crypto test results saved to: {filename}")
        return filename
    
    def print_summary(self):
        """Print a summary of modern crypto test results"""
        print("\n" + "="*80)
        print("MODERN CRYPTOGRAPHY TEST SUITE SUMMARY")
        print("="*80)
        
        print(f"Test Duration: {self.results['test_start_time']} to {self.results['test_end_time']}")
        
        # Key Generation Summary
        if 'key_generation_tests' in self.results and 'performance' in self.results['key_generation_tests']:
            kg_perf = self.results['key_generation_tests']['performance']
            print(f"\nKey Generation:")
            print(f"  AES Success Rate: {kg_perf.get('aes_success_rate', 0):.2%}")
            print(f"  Ed25519 Success Rate: {kg_perf.get('ed25519_success_rate', 0):.2%}")
            print(f"  X25519 Success Rate: {kg_perf.get('x25519_success_rate', 0):.2%}")
        
        # Encryption Summary
        if 'encryption_tests' in self.results and 'performance' in self.results['encryption_tests']:
            enc_perf = self.results['encryption_tests']['performance']
            print(f"\nEncryption/Decryption:")
            print(f"  AES Success Rate: {enc_perf.get('aes_success_rate', 0):.2%}")
            print(f"  ChaCha20 Success Rate: {enc_perf.get('chacha_success_rate', 0):.2%}")
            print(f"  Password-based Success Rate: {enc_perf.get('password_success_rate', 0):.2%}")
        
        # Signature Summary
        if 'signature_tests' in self.results and 'performance' in self.results['signature_tests']:
            sig_perf = self.results['signature_tests']['performance']
            print(f"\nDigital Signatures:")
            print(f"  Sign Success Rate: {sig_perf.get('sign_success_rate', 0):.2%}")
            print(f"  Verify Success Rate: {sig_perf.get('verify_success_rate', 0):.2%}")
            print(f"  Tamper Detection Rate: {sig_perf.get('tamper_detection_rate', 0):.2%}")
        
        # Hybrid Summary
        if 'hybrid_tests' in self.results and 'performance' in self.results['hybrid_tests']:
            hyb_perf = self.results['hybrid_tests']['performance']
            print(f"\nHybrid Encryption:")
            print(f"  Success Rate: {hyb_perf.get('hybrid_success_rate', 0):.2%}")
        
        print("\n" + "="*80)

def main():
    """Main modern crypto test execution"""
    tester = ModernCryptoTester()
    
    try:
        results = tester.run_all_modern_crypto_tests()
        tester.print_summary()
        
        # Save detailed results
        filename = tester.save_results()
        print(f"\nDetailed modern crypto results saved to: {filename}")
        
    except KeyboardInterrupt:
        print("\nModern crypto test interrupted by user")
        tester.save_results("interrupted_modern_crypto_test_results.json")
    except Exception as e:
        print(f"\nModern crypto test failed with error: {e}")
        tester.results['error_log'].append(str(e))
        tester.save_results("error_modern_crypto_test_results.json")

if __name__ == "__main__":
    main() 