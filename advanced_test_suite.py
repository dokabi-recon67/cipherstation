#!/usr/bin/env python3
"""
Advanced Test Suite for CipherStation
Testing CLI, Web Interface, and Stress Testing
"""

import time
import sys
import os
import json
import subprocess
import requests
import threading
from datetime import datetime
from typing import Dict, List, Tuple, Any
import random
import string

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class AdvancedTester:
    def __init__(self):
        self.results = {
            'test_start_time': datetime.now().isoformat(),
            'cli_tests': {},
            'web_tests': {},
            'stress_tests': {},
            'performance_data': {},
            'error_log': []
        }
        
    def test_cli_interface(self) -> Dict[str, Any]:
        """Test the CLI interface comprehensively"""
        print("Testing CLI Interface...")
        results = {
            'basic_commands': [],
            'cipher_operations': [],
            'error_handling': [],
            'performance': {}
        }
        
        # Test basic CLI commands
        basic_commands = [
            (['python3', 'cli_cracker.py', '--help'], 'Help command'),
            (['python3', 'cipherstationv0.py', '--help'], 'Main CLI help'),
            (['python3', 'cipherstationv0.py', 'keygen', '--help'], 'Keygen help'),
            (['python3', 'cipherstationv0.py', 'encrypt', '--help'], 'Encrypt help'),
            (['python3', 'cipherstationv0.py', 'decrypt', '--help'], 'Decrypt help'),
        ]
        
        for cmd, description in basic_commands:
            start_time = time.time()
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                execution_time = time.time() - start_time
                
                results['basic_commands'].append({
                    'command': ' '.join(cmd),
                    'description': description,
                    'success': result.returncode == 0,
                    'execution_time': execution_time,
                    'stdout_length': len(result.stdout),
                    'stderr_length': len(result.stderr)
                })
            except subprocess.TimeoutExpired:
                results['basic_commands'].append({
                    'command': ' '.join(cmd),
                    'description': description,
                    'success': False,
                    'execution_time': 10.0,
                    'error': 'Timeout'
                })
            except Exception as e:
                results['basic_commands'].append({
                    'command': ' '.join(cmd),
                    'description': description,
                    'success': False,
                    'execution_time': 0.0,
                    'error': str(e)
                })
        
        # Test cipher cracking with CLI
        test_cases = [
            ("KHOORZRUOG", "Caesar cipher test"),
            ("RIJVSUYVJN", "Vigenère cipher test"),
            ("SVOOLDLIOW", "Atbash cipher test"),
            ("HELLO WORLD", "Plain text test")
        ]
        
        for text, description in test_cases:
            start_time = time.time()
            try:
                result = subprocess.run(
                    ['python3', 'cli_cracker.py', '--text', text],
                    capture_output=True, text=True, timeout=30
                )
                execution_time = time.time() - start_time
                
                results['cipher_operations'].append({
                    'input': text,
                    'description': description,
                    'success': result.returncode == 0,
                    'execution_time': execution_time,
                    'stdout_length': len(result.stdout),
                    'stderr_length': len(result.stderr),
                    'output_sample': result.stdout[:200] if result.stdout else ''
                })
            except subprocess.TimeoutExpired:
                results['cipher_operations'].append({
                    'input': text,
                    'description': description,
                    'success': False,
                    'execution_time': 30.0,
                    'error': 'Timeout'
                })
            except Exception as e:
                results['cipher_operations'].append({
                    'input': text,
                    'description': description,
                    'success': False,
                    'execution_time': 0.0,
                    'error': str(e)
                })
        
        # Test error handling
        error_cases = [
            (['python3', 'cli_cracker.py', '--text', ''], 'Empty text'),
            (['python3', 'cli_cracker.py', '--text', '123!@#'], 'Non-alphabetic text'),
            (['python3', 'cli_cracker.py', '--invalid-flag'], 'Invalid flag'),
        ]
        
        for cmd, description in error_cases:
            start_time = time.time()
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                execution_time = time.time() - start_time
                
                results['error_handling'].append({
                    'command': ' '.join(cmd),
                    'description': description,
                    'expected_failure': True,
                    'actual_failure': result.returncode != 0,
                    'execution_time': execution_time,
                    'stderr_length': len(result.stderr)
                })
            except Exception as e:
                results['error_handling'].append({
                    'command': ' '.join(cmd),
                    'description': description,
                    'expected_failure': True,
                    'actual_failure': True,
                    'execution_time': 0.0,
                    'error': str(e)
                })
        
        # Calculate performance metrics
        results['performance'] = {
            'basic_command_success_rate': sum(1 for t in results['basic_commands'] if t['success']) / len(results['basic_commands']),
            'cipher_operation_success_rate': sum(1 for t in results['cipher_operations'] if t['success']) / len(results['cipher_operations']),
            'error_handling_success_rate': sum(1 for t in results['error_handling'] if t['actual_failure'] == t['expected_failure']) / len(results['error_handling']),
            'avg_basic_command_time': sum(t['execution_time'] for t in results['basic_commands']) / len(results['basic_commands']),
            'avg_cipher_operation_time': sum(t['execution_time'] for t in results['cipher_operations']) / len(results['cipher_operations'])
        }
        
        return results
    
    def test_web_interface(self) -> Dict[str, Any]:
        """Test the web interface"""
        print("Testing Web Interface...")
        results = {
            'server_startup': {},
            'api_endpoints': [],
            'cipher_operations': [],
            'performance': {}
        }
        
        # Test server startup
        try:
            # Start the web server in background
            server_process = subprocess.Popen(
                ['python3', 'relaystation/app.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for server to start
            time.sleep(3)
            
            # Test if server is running
            try:
                response = requests.get('http://localhost:5001/', timeout=5)
                results['server_startup'] = {
                    'success': True,
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds()
                }
            except requests.exceptions.RequestException as e:
                results['server_startup'] = {
                    'success': False,
                    'error': str(e)
                }
            
            # Test API endpoints
            api_tests = [
                ('/classical', 'GET', 'Classical ciphers page'),
                ('/api/encode', 'POST', 'Encode API'),
                ('/api/decode', 'POST', 'Decode API'),
                ('/api/crack', 'POST', 'Crack API'),
            ]
            
            for endpoint, method, description in api_tests:
                try:
                    if method == 'GET':
                        response = requests.get(f'http://localhost:5001{endpoint}', timeout=5)
                    else:
                        response = requests.post(f'http://localhost:5001{endpoint}', 
                                               json={'text': 'TEST'}, timeout=5)
                    
                    results['api_endpoints'].append({
                        'endpoint': endpoint,
                        'method': method,
                        'description': description,
                        'success': response.status_code < 500,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds()
                    })
                except requests.exceptions.RequestException as e:
                    results['api_endpoints'].append({
                        'endpoint': endpoint,
                        'method': method,
                        'description': description,
                        'success': False,
                        'error': str(e)
                    })
            
            # Test cipher operations via API
            cipher_tests = [
                ('KHOORZRUOG', 'Caesar cipher'),
                ('RIJVSUYVJN', 'Vigenère cipher'),
                ('SVOOLDLIOW', 'Atbash cipher'),
            ]
            
            for text, description in cipher_tests:
                try:
                    response = requests.post(
                        'http://localhost:5001/api/crack',
                        json={'text': text},
                        timeout=30
                    )
                    
                    results['cipher_operations'].append({
                        'input': text,
                        'description': description,
                        'success': response.status_code == 200,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds(),
                        'response_size': len(response.text) if response.text else 0
                    })
                except requests.exceptions.RequestException as e:
                    results['cipher_operations'].append({
                        'input': text,
                        'description': description,
                        'success': False,
                        'error': str(e)
                    })
            
            # Stop server
            server_process.terminate()
            server_process.wait(timeout=5)
            
        except Exception as e:
            results['server_startup'] = {
                'success': False,
                'error': str(e)
            }
        
        # Calculate performance metrics
        if results['api_endpoints']:
            results['performance'] = {
                'server_startup_success': results['server_startup'].get('success', False),
                'api_endpoint_success_rate': sum(1 for t in results['api_endpoints'] if t['success']) / len(results['api_endpoints']),
                'cipher_operation_success_rate': sum(1 for t in results['cipher_operations'] if t['success']) / len(results['cipher_operations']),
                'avg_api_response_time': sum(t.get('response_time', 0) for t in results['api_endpoints']) / len(results['api_endpoints']),
                'avg_cipher_response_time': sum(t.get('response_time', 0) for t in results['cipher_operations']) / len(results['cipher_operations'])
            }
        
        return results
    
    def test_stress_performance(self) -> Dict[str, Any]:
        """Test performance with larger datasets"""
        print("Testing Stress Performance...")
        results = {
            'large_text_tests': [],
            'concurrent_tests': [],
            'memory_tests': [],
            'performance': {}
        }
        
        # Generate large test texts
        large_texts = [
            ('A' * 1000, '1000 repeated characters'),
            ('THE QUICK BROWN FOX ' * 50, '1000 character pangram'),
            (''.join(random.choices(string.ascii_uppercase, k=1000)), '1000 random characters'),
            ('HELLO WORLD ' * 83, '1000 character repeated phrase'),
        ]
        
        for text, description in large_texts:
            start_time = time.time()
            try:
                result = subprocess.run(
                    ['python3', 'cli_cracker.py', '--text', text],
                    capture_output=True, text=True, timeout=60
                )
                execution_time = time.time() - start_time
                
                results['large_text_tests'].append({
                    'text_length': len(text),
                    'description': description,
                    'success': result.returncode == 0,
                    'execution_time': execution_time,
                    'memory_usage': len(result.stdout) + len(result.stderr)
                })
            except subprocess.TimeoutExpired:
                results['large_text_tests'].append({
                    'text_length': len(text),
                    'description': description,
                    'success': False,
                    'execution_time': 60.0,
                    'error': 'Timeout'
                })
            except Exception as e:
                results['large_text_tests'].append({
                    'text_length': len(text),
                    'description': description,
                    'success': False,
                    'execution_time': 0.0,
                    'error': str(e)
                })
        
        # Test concurrent operations
        concurrent_texts = ['KHOORZRUOG', 'RIJVSUYVJN', 'SVOOLDLIOW', 'HELLO WORLD']
        
        def run_concurrent_test(text, index):
            start_time = time.time()
            try:
                result = subprocess.run(
                    ['python3', 'cli_cracker.py', '--text', text],
                    capture_output=True, text=True, timeout=30
                )
                execution_time = time.time() - start_time
                return {
                    'index': index,
                    'text': text,
                    'success': result.returncode == 0,
                    'execution_time': execution_time
                }
            except Exception as e:
                return {
                    'index': index,
                    'text': text,
                    'success': False,
                    'execution_time': 0.0,
                    'error': str(e)
                }
        
        # Run concurrent tests
        threads = []
        for i, text in enumerate(concurrent_texts):
            thread = threading.Thread(target=lambda: results['concurrent_tests'].append(run_concurrent_test(text, i)))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Calculate performance metrics
        results['performance'] = {
            'large_text_success_rate': sum(1 for t in results['large_text_tests'] if t['success']) / len(results['large_text_tests']),
            'concurrent_success_rate': sum(1 for t in results['concurrent_tests'] if t['success']) / len(results['concurrent_tests']),
            'avg_large_text_time': sum(t['execution_time'] for t in results['large_text_tests']) / len(results['large_text_tests']),
            'avg_concurrent_time': sum(t['execution_time'] for t in results['concurrent_tests']) / len(results['concurrent_tests']),
            'max_concurrent_time': max(t['execution_time'] for t in results['concurrent_tests']) if results['concurrent_tests'] else 0
        }
        
        return results
    
    def test_dictionary_attack(self) -> Dict[str, Any]:
        """Test dictionary attack capabilities"""
        print("Testing Dictionary Attack...")
        results = {
            'dictionary_tests': [],
            'performance': {}
        }
        
        # Test with various dictionary words as keys
        test_keys = ['KEY', 'SECRET', 'PASSWORD', 'LEMON', 'ATTACK', 'DEFEND', 'MISSION', 'TARGET']
        test_plaintext = 'HELLO WORLD THIS IS A TEST MESSAGE'
        
        for key in test_keys:
            start_time = time.time()
            try:
                # Create Vigenère cipher with this key
                from classical_ciphers import VigenereCipher
                vigenere = VigenereCipher()
                ciphertext = vigenere.encode(test_plaintext, key)
                
                # Try to crack it
                result = subprocess.run(
                    ['python3', 'cli_cracker.py', '--text', ciphertext],
                    capture_output=True, text=True, timeout=60
                )
                execution_time = time.time() - start_time
                
                # Check if the key was found
                success = key.upper() in result.stdout.upper() or test_plaintext.upper() in result.stdout.upper()
                
                results['dictionary_tests'].append({
                    'key': key,
                    'ciphertext': ciphertext,
                    'success': success,
                    'execution_time': execution_time,
                    'stdout_length': len(result.stdout),
                    'found_key': key.upper() in result.stdout.upper(),
                    'found_plaintext': test_plaintext.upper() in result.stdout.upper()
                })
            except subprocess.TimeoutExpired:
                results['dictionary_tests'].append({
                    'key': key,
                    'ciphertext': 'timeout',
                    'success': False,
                    'execution_time': 60.0,
                    'error': 'Timeout'
                })
            except Exception as e:
                results['dictionary_tests'].append({
                    'key': key,
                    'ciphertext': 'error',
                    'success': False,
                    'execution_time': 0.0,
                    'error': str(e)
                })
        
        # Calculate performance metrics
        results['performance'] = {
            'dictionary_success_rate': sum(1 for t in results['dictionary_tests'] if t['success']) / len(results['dictionary_tests']),
            'avg_dictionary_time': sum(t['execution_time'] for t in results['dictionary_tests']) / len(results['dictionary_tests']),
            'key_found_rate': sum(1 for t in results['dictionary_tests'] if t.get('found_key', False)) / len(results['dictionary_tests']),
            'plaintext_found_rate': sum(1 for t in results['dictionary_tests'] if t.get('found_plaintext', False)) / len(results['dictionary_tests'])
        }
        
        return results
    
    def run_all_advanced_tests(self) -> Dict[str, Any]:
        """Run all advanced tests"""
        print("Starting Advanced Test Suite...")
        print(f"Test started at: {self.results['test_start_time']}")
        
        # Run individual test suites
        self.results['cli_tests'] = self.test_cli_interface()
        self.results['web_tests'] = self.test_web_interface()
        self.results['stress_tests'] = self.test_stress_performance()
        self.results['dictionary_tests'] = self.test_dictionary_attack()
        
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
        test_suites = ['cli_tests', 'web_tests', 'stress_tests', 'dictionary_tests']
        
        for suite in test_suites:
            if suite in self.results and 'performance' in self.results[suite]:
                perf = self.results[suite]['performance']
                metrics['test_summary'][suite] = {
                    'success_rate': perf.get('basic_command_success_rate', 
                                           perf.get('server_startup_success', 
                                                   perf.get('large_text_success_rate',
                                                           perf.get('dictionary_success_rate', 0)))),
                    'avg_time': perf.get('avg_basic_command_time',
                                       perf.get('avg_api_response_time',
                                               perf.get('avg_large_text_time',
                                                       perf.get('avg_dictionary_time', 0))))
                }
        
        return metrics
    
    def save_results(self, filename: str = None):
        """Save test results to file"""
        if filename is None:
            filename = f"advanced_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"Advanced test results saved to: {filename}")
        return filename
    
    def print_summary(self):
        """Print a summary of advanced test results"""
        print("\n" + "="*80)
        print("ADVANCED TEST SUITE SUMMARY")
        print("="*80)
        
        print(f"Test Duration: {self.results['test_start_time']} to {self.results['test_end_time']}")
        
        # CLI Tests Summary
        if 'cli_tests' in self.results and 'performance' in self.results['cli_tests']:
            cli_perf = self.results['cli_tests']['performance']
            print(f"\nCLI Interface:")
            print(f"  Basic Commands Success Rate: {cli_perf.get('basic_command_success_rate', 0):.2%}")
            print(f"  Cipher Operations Success Rate: {cli_perf.get('cipher_operation_success_rate', 0):.2%}")
            print(f"  Error Handling Success Rate: {cli_perf.get('error_handling_success_rate', 0):.2%}")
        
        # Web Tests Summary
        if 'web_tests' in self.results and 'performance' in self.results['web_tests']:
            web_perf = self.results['web_tests']['performance']
            print(f"\nWeb Interface:")
            print(f"  Server Startup: {'Success' if web_perf.get('server_startup_success', False) else 'Failed'}")
            print(f"  API Endpoints Success Rate: {web_perf.get('api_endpoint_success_rate', 0):.2%}")
            print(f"  Cipher Operations Success Rate: {web_perf.get('cipher_operation_success_rate', 0):.2%}")
        
        # Stress Tests Summary
        if 'stress_tests' in self.results and 'performance' in self.results['stress_tests']:
            stress_perf = self.results['stress_tests']['performance']
            print(f"\nStress Testing:")
            print(f"  Large Text Success Rate: {stress_perf.get('large_text_success_rate', 0):.2%}")
            print(f"  Concurrent Operations Success Rate: {stress_perf.get('concurrent_success_rate', 0):.2%}")
            print(f"  Average Large Text Time: {stress_perf.get('avg_large_text_time', 0):.4f}s")
        
        # Dictionary Tests Summary
        if 'dictionary_tests' in self.results and 'performance' in self.results['dictionary_tests']:
            dict_perf = self.results['dictionary_tests']['performance']
            print(f"\nDictionary Attack:")
            print(f"  Success Rate: {dict_perf.get('dictionary_success_rate', 0):.2%}")
            print(f"  Key Found Rate: {dict_perf.get('key_found_rate', 0):.2%}")
            print(f"  Plaintext Found Rate: {dict_perf.get('plaintext_found_rate', 0):.2%}")
        
        print("\n" + "="*80)

def main():
    """Main advanced test execution"""
    tester = AdvancedTester()
    
    try:
        results = tester.run_all_advanced_tests()
        tester.print_summary()
        
        # Save detailed results
        filename = tester.save_results()
        print(f"\nDetailed advanced results saved to: {filename}")
        
    except KeyboardInterrupt:
        print("\nAdvanced test interrupted by user")
        tester.save_results("interrupted_advanced_test_results.json")
    except Exception as e:
        print(f"\nAdvanced test failed with error: {e}")
        tester.results['error_log'].append(str(e))
        tester.save_results("error_advanced_test_results.json")

if __name__ == "__main__":
    main() 