#!/usr/bin/env python3
"""
Comprehensive Test Suite for CipherStation
Industry-grade testing with detailed metrics and performance analysis
"""

import time
import sys
import os
import json
import statistics
import resource
import gc
from datetime import datetime
from typing import Dict, List, Tuple, Any
import random
import string

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import cipher modules
from classical_ciphers import (
    CaesarCipher, VigenereCipher, XORCipher, AtbashCipher, SubstitutionCipher,
    encode_text, decode_text, cryptanalyze_text, Cryptanalyzer
)

class ComprehensiveTester:
    def __init__(self):
        self.results = {
            'test_start_time': datetime.now().isoformat(),
            'system_info': self._get_system_info(),
            'test_results': {},
            'performance_data': {},
            'accuracy_data': {},
            'error_log': []
        }
        self.test_cases = self._generate_test_cases()
        
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        import platform
        return {
            'platform': platform.platform(),
            'python_version': sys.version,
            'architecture': platform.architecture(),
            'processor': platform.processor(),
            'memory': self._get_memory_info()
        }
    
    def _get_memory_info(self) -> Dict[str, Any]:
        """Get memory information"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return {
                'total_gb': memory.total / (1024**3),
                'available_gb': memory.available / (1024**3),
                'percent_used': memory.percent
            }
        except ImportError:
            return {'note': 'psutil not available'}
    
    def _generate_test_cases(self) -> Dict[str, List[Dict[str, Any]]]:
        """Generate comprehensive test cases"""
        test_cases = {
            'caesar': [],
            'vigenere': [],
            'xor': [],
            'atbash': [],
            'substitution': []
        }
        
        # Caesar cipher test cases
        for shift in range(26):
            test_cases['caesar'].append({
                'plaintext': 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG',
                'key': shift,
                'expected': self._caesar_encode('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', shift)
            })
        
        # Vigenère cipher test cases
        vigenere_keys = ['KEY', 'SECRET', 'PASSWORD', 'LEMON', 'ATTACK', 'DEFEND', 'MISSION', 'TARGET']
        for key in vigenere_keys:
            test_cases['vigenere'].append({
                'plaintext': 'HELLO WORLD THIS IS A TEST MESSAGE',
                'key': key,
                'expected': self._vigenere_encode('HELLO WORLD THIS IS A TEST MESSAGE', key)
            })
        
        # XOR cipher test cases
        xor_keys = ['XOR', 'KEY', 'SECRET', 'TEST', 'ABC', 'XYZ']
        for key in xor_keys:
            test_cases['xor'].append({
                'plaintext': 'HELLO WORLD',
                'key': key,
                'expected': self._xor_encode('HELLO WORLD', key)
            })
        
        # Atbash cipher test cases
        atbash_texts = ['HELLO', 'WORLD', 'TEST', 'MESSAGE', 'CRYPTOGRAPHY']
        for text in atbash_texts:
            test_cases['atbash'].append({
                'plaintext': text,
                'key': None,
                'expected': self._atbash_encode(text)
            })
        
        # Substitution cipher test cases
        substitution_keys = ['QWERTYUIOPASDFGHJKLZXCVBNM', 'ZYXWVUTSRQPONMLKJIHGFEDCBA']
        for key in substitution_keys:
            test_cases['substitution'].append({
                'plaintext': 'HELLO WORLD',
                'key': key,
                'expected': self._substitution_encode('HELLO WORLD', key)
            })
        
        return test_cases
    
    def _caesar_encode(self, text: str, shift: int) -> str:
        """Manual Caesar encoding for verification"""
        result = ""
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char_num = ord(char.upper()) - ord('A')
                encoded_num = (char_num + shift) % 26
                encoded_char = chr(encoded_num + ord('A'))
                result += encoded_char if is_upper else encoded_char.lower()
            else:
                result += char
        return result
    
    def _vigenere_encode(self, text: str, key: str) -> str:
        """Manual Vigenère encoding for verification"""
        result = ""
        key = key.upper()
        key_index = 0
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char_num = ord(char.upper()) - ord('A')
                key_char = key[key_index % len(key)]
                key_num = ord(key_char) - ord('A')
                encoded_num = (char_num + key_num) % 26
                encoded_char = chr(encoded_num + ord('A'))
                result += encoded_char if is_upper else encoded_char.lower()
                key_index += 1
            else:
                result += char
        return result
    
    def _xor_encode(self, text: str, key: str) -> str:
        """Manual XOR encoding for verification"""
        result = ""
        for i, char in enumerate(text):
            key_char = key[i % len(key)]
            result += chr(ord(char) ^ ord(key_char))
        return result
    
    def _atbash_encode(self, text: str) -> str:
        """Manual Atbash encoding for verification"""
        result = ""
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char_num = ord(char.upper()) - ord('A')
                encoded_num = 25 - char_num
                encoded_char = chr(encoded_num + ord('A'))
                result += encoded_char if is_upper else encoded_char.lower()
            else:
                result += char
        return result
    
    def _substitution_encode(self, text: str, key: str) -> str:
        """Manual substitution encoding for verification"""
        result = ""
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char_num = ord(char.upper()) - ord('A')
                if char_num < len(key):
                    encoded_char = key[char_num]
                    result += encoded_char if is_upper else encoded_char.lower()
                else:
                    result += char
            else:
                result += char
        return result
    
    def _measure_memory_usage(self) -> float:
        """Measure current memory usage in MB"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)
        except ImportError:
            # Fallback using resource module
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    
    def _time_function(self, func, *args, **kwargs) -> Tuple[float, Any]:
        """Time a function execution"""
        start_time = time.time()
        start_memory = self._measure_memory_usage()
        
        try:
            result = func(*args, **kwargs)
            end_time = time.time()
            end_memory = self._measure_memory_usage()
            
            execution_time = end_time - start_time
            memory_delta = end_memory - start_memory
            
            return execution_time, result, memory_delta
        except Exception as e:
            end_time = time.time()
            execution_time = end_time - start_time
            return execution_time, e, 0
    
    def test_caesar_cipher(self) -> Dict[str, Any]:
        """Test Caesar cipher encoding, decoding, and cracking"""
        print("Testing Caesar Cipher...")
        results = {
            'encoding_tests': [],
            'decoding_tests': [],
            'cracking_tests': [],
            'performance': {}
        }
        
        caesar = CaesarCipher()
        
        # Test encoding
        for i, test_case in enumerate(self.test_cases['caesar']):
            execution_time, result, memory_delta = self._time_function(
                caesar.encode, test_case['plaintext'], test_case['key']
            )
            
            success = result == test_case['expected']
            results['encoding_tests'].append({
                'test_id': i,
                'plaintext': test_case['plaintext'],
                'key': test_case['key'],
                'expected': test_case['expected'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test decoding
        for i, test_case in enumerate(self.test_cases['caesar']):
            execution_time, result, memory_delta = self._time_function(
                caesar.decode, test_case['expected'], test_case['key']
            )
            
            success = result == test_case['plaintext']
            results['decoding_tests'].append({
                'test_id': i,
                'ciphertext': test_case['expected'],
                'key': test_case['key'],
                'expected': test_case['plaintext'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test cracking
        cracking_times = []
        cracking_successes = []
        
        for i, test_case in enumerate(self.test_cases['caesar'][:10]):  # Test first 10
            execution_time, result, memory_delta = self._time_function(
                caesar.brute_force, test_case['expected']
            )
            
            # Check if correct plaintext is in top 3 results
            success = False
            if isinstance(result, list) and len(result) > 0:
                for shift, decoded, confidence in result[:3]:
                    if decoded.upper() == test_case['plaintext'].upper():
                        success = True
                        break
            
            results['cracking_tests'].append({
                'test_id': i,
                'ciphertext': test_case['expected'],
                'expected_plaintext': test_case['plaintext'],
                'results': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
            
            cracking_times.append(execution_time)
            cracking_successes.append(success)
        
        # Calculate performance metrics
        results['performance'] = {
            'encoding_success_rate': sum(1 for t in results['encoding_tests'] if t['success']) / len(results['encoding_tests']),
            'decoding_success_rate': sum(1 for t in results['decoding_tests'] if t['success']) / len(results['decoding_tests']),
            'cracking_success_rate': sum(cracking_successes) / len(cracking_successes) if cracking_successes else 0,
            'avg_encoding_time': statistics.mean([t['execution_time'] for t in results['encoding_tests']]),
            'avg_decoding_time': statistics.mean([t['execution_time'] for t in results['decoding_tests']]),
            'avg_cracking_time': statistics.mean(cracking_times) if cracking_times else 0,
            'total_tests': len(results['encoding_tests']) + len(results['decoding_tests']) + len(results['cracking_tests'])
        }
        
        return results
    
    def test_vigenere_cipher(self) -> Dict[str, Any]:
        """Test Vigenère cipher encoding, decoding, and cracking"""
        print("Testing Vigenère Cipher...")
        results = {
            'encoding_tests': [],
            'decoding_tests': [],
            'cracking_tests': [],
            'performance': {}
        }
        
        vigenere = VigenereCipher()
        
        # Test encoding
        for i, test_case in enumerate(self.test_cases['vigenere']):
            execution_time, result, memory_delta = self._time_function(
                vigenere.encode, test_case['plaintext'], test_case['key']
            )
            
            success = result == test_case['expected']
            results['encoding_tests'].append({
                'test_id': i,
                'plaintext': test_case['plaintext'],
                'key': test_case['key'],
                'expected': test_case['expected'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test decoding
        for i, test_case in enumerate(self.test_cases['vigenere']):
            execution_time, result, memory_delta = self._time_function(
                vigenere.decode, test_case['expected'], test_case['key']
            )
            
            success = result == test_case['plaintext']
            results['decoding_tests'].append({
                'test_id': i,
                'ciphertext': test_case['expected'],
                'key': test_case['key'],
                'expected': test_case['plaintext'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test cracking (limited due to complexity)
        cracking_times = []
        cracking_successes = []
        
        for i, test_case in enumerate(self.test_cases['vigenere'][:3]):  # Test first 3
            execution_time, result, memory_delta = self._time_function(
                vigenere.cryptanalyze, test_case['expected'], test_mode=True
            )
            
            # Check if correct key is in top 5 results
            success = False
            if isinstance(result, list) and len(result) > 0:
                for key, decoded, confidence in result[:5]:
                    if key.upper() == test_case['key'].upper():
                        success = True
                        break
            
            results['cracking_tests'].append({
                'test_id': i,
                'ciphertext': test_case['expected'],
                'expected_key': test_case['key'],
                'results': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
            
            cracking_times.append(execution_time)
            cracking_successes.append(success)
        
        # Calculate performance metrics
        results['performance'] = {
            'encoding_success_rate': sum(1 for t in results['encoding_tests'] if t['success']) / len(results['encoding_tests']),
            'decoding_success_rate': sum(1 for t in results['decoding_tests'] if t['success']) / len(results['decoding_tests']),
            'cracking_success_rate': sum(cracking_successes) / len(cracking_successes) if cracking_successes else 0,
            'avg_encoding_time': statistics.mean([t['execution_time'] for t in results['encoding_tests']]),
            'avg_decoding_time': statistics.mean([t['execution_time'] for t in results['decoding_tests']]),
            'avg_cracking_time': statistics.mean(cracking_times) if cracking_times else 0,
            'total_tests': len(results['encoding_tests']) + len(results['decoding_tests']) + len(results['cracking_tests'])
        }
        
        return results
    
    def test_xor_cipher(self) -> Dict[str, Any]:
        """Test XOR cipher encoding, decoding, and cracking"""
        print("Testing XOR Cipher...")
        results = {
            'encoding_tests': [],
            'decoding_tests': [],
            'cracking_tests': [],
            'performance': {}
        }
        
        xor = XORCipher()
        
        # Test encoding
        for i, test_case in enumerate(self.test_cases['xor']):
            execution_time, result, memory_delta = self._time_function(
                xor.encode, test_case['plaintext'], test_case['key']
            )
            
            success = result == test_case['expected']
            results['encoding_tests'].append({
                'test_id': i,
                'plaintext': test_case['plaintext'],
                'key': test_case['key'],
                'expected': test_case['expected'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test decoding
        for i, test_case in enumerate(self.test_cases['xor']):
            execution_time, result, memory_delta = self._time_function(
                xor.decode, test_case['expected'], test_case['key']
            )
            
            success = result == test_case['plaintext']
            results['decoding_tests'].append({
                'test_id': i,
                'ciphertext': test_case['expected'],
                'key': test_case['key'],
                'expected': test_case['plaintext'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test cracking (limited due to complexity)
        cracking_times = []
        cracking_successes = []
        
        for i, test_case in enumerate(self.test_cases['xor'][:3]):  # Test first 3
            execution_time, result, memory_delta = self._time_function(
                xor.brute_force_short_key, test_case['expected']
            )
            
            # Check if correct key is in top 5 results
            success = False
            if isinstance(result, list) and len(result) > 0:
                for key, decoded, confidence in result[:5]:
                    if key.upper() == test_case['key'].upper():
                        success = True
                        break
            
            results['cracking_tests'].append({
                'test_id': i,
                'ciphertext': test_case['expected'],
                'expected_key': test_case['key'],
                'results': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
            
            cracking_times.append(execution_time)
            cracking_successes.append(success)
        
        # Calculate performance metrics
        results['performance'] = {
            'encoding_success_rate': sum(1 for t in results['encoding_tests'] if t['success']) / len(results['encoding_tests']),
            'decoding_success_rate': sum(1 for t in results['decoding_tests'] if t['success']) / len(results['decoding_tests']),
            'cracking_success_rate': sum(cracking_successes) / len(cracking_successes) if cracking_successes else 0,
            'avg_encoding_time': statistics.mean([t['execution_time'] for t in results['encoding_tests']]),
            'avg_decoding_time': statistics.mean([t['execution_time'] for t in results['decoding_tests']]),
            'avg_cracking_time': statistics.mean(cracking_times) if cracking_times else 0,
            'total_tests': len(results['encoding_tests']) + len(results['decoding_tests']) + len(results['cracking_tests'])
        }
        
        return results
    
    def test_atbash_cipher(self) -> Dict[str, Any]:
        """Test Atbash cipher encoding, decoding, and cracking"""
        print("Testing Atbash Cipher...")
        results = {
            'encoding_tests': [],
            'decoding_tests': [],
            'cracking_tests': [],
            'performance': {}
        }
        
        atbash = AtbashCipher()
        
        # Test encoding
        for i, test_case in enumerate(self.test_cases['atbash']):
            execution_time, result, memory_delta = self._time_function(
                atbash.encode, test_case['plaintext']
            )
            
            success = result == test_case['expected']
            results['encoding_tests'].append({
                'test_id': i,
                'plaintext': test_case['plaintext'],
                'expected': test_case['expected'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test decoding
        for i, test_case in enumerate(self.test_cases['atbash']):
            execution_time, result, memory_delta = self._time_function(
                atbash.decode, test_case['expected']
            )
            
            success = result == test_case['plaintext']
            results['decoding_tests'].append({
                'test_id': i,
                'ciphertext': test_case['expected'],
                'expected': test_case['plaintext'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test cracking
        cracking_times = []
        cracking_successes = []
        
        for i, test_case in enumerate(self.test_cases['atbash']):
            execution_time, result, memory_delta = self._time_function(
                atbash.decode, test_case['expected']  # Atbash is self-inverse
            )
            
            success = result == test_case['plaintext']
            results['cracking_tests'].append({
                'test_id': i,
                'ciphertext': test_case['expected'],
                'expected_plaintext': test_case['plaintext'],
                'result': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
            
            cracking_times.append(execution_time)
            cracking_successes.append(success)
        
        # Calculate performance metrics
        results['performance'] = {
            'encoding_success_rate': sum(1 for t in results['encoding_tests'] if t['success']) / len(results['encoding_tests']),
            'decoding_success_rate': sum(1 for t in results['decoding_tests'] if t['success']) / len(results['decoding_tests']),
            'cracking_success_rate': sum(cracking_successes) / len(cracking_successes) if cracking_successes else 0,
            'avg_encoding_time': statistics.mean([t['execution_time'] for t in results['encoding_tests']]),
            'avg_decoding_time': statistics.mean([t['execution_time'] for t in results['decoding_tests']]),
            'avg_cracking_time': statistics.mean(cracking_times) if cracking_times else 0,
            'total_tests': len(results['encoding_tests']) + len(results['decoding_tests']) + len(results['cracking_tests'])
        }
        
        return results
    
    def test_substitution_cipher(self) -> Dict[str, Any]:
        """Test Substitution cipher encoding, decoding, and cracking"""
        print("Testing Substitution Cipher...")
        results = {
            'encoding_tests': [],
            'decoding_tests': [],
            'cracking_tests': [],
            'performance': {}
        }
        
        # Test encoding
        for i, test_case in enumerate(self.test_cases['substitution']):
            substitution = SubstitutionCipher(test_case['key'])
            execution_time, result, memory_delta = self._time_function(
                substitution.encode, test_case['plaintext']
            )
            
            success = result == test_case['expected']
            results['encoding_tests'].append({
                'test_id': i,
                'plaintext': test_case['plaintext'],
                'key': test_case['key'],
                'expected': test_case['expected'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test decoding
        for i, test_case in enumerate(self.test_cases['substitution']):
            substitution = SubstitutionCipher(test_case['key'])
            execution_time, result, memory_delta = self._time_function(
                substitution.decode, test_case['expected']
            )
            
            success = result == test_case['plaintext']
            results['decoding_tests'].append({
                'test_id': i,
                'ciphertext': test_case['expected'],
                'key': test_case['key'],
                'expected': test_case['plaintext'],
                'actual': result,
                'success': success,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Substitution cracking is very complex, so we'll test with a simple case
        simple_substitution = SubstitutionCipher('QWERTYUIOPASDFGHJKLZXCVBNM')
        test_text = 'HELLO'
        encoded = simple_substitution.encode(test_text)
        
        execution_time, result, memory_delta = self._time_function(
            SubstitutionCipher.crack, encoded, test_mode=True
        )
        
        results['cracking_tests'].append({
            'test_id': 0,
            'ciphertext': encoded,
            'expected_plaintext': test_text,
            'result': result,
            'success': isinstance(result, str) and result.upper() == test_text.upper(),
            'execution_time': execution_time,
            'memory_delta': memory_delta
        })
        
        # Calculate performance metrics
        results['performance'] = {
            'encoding_success_rate': sum(1 for t in results['encoding_tests'] if t['success']) / len(results['encoding_tests']),
            'decoding_success_rate': sum(1 for t in results['decoding_tests'] if t['success']) / len(results['decoding_tests']),
            'cracking_success_rate': sum(1 for t in results['cracking_tests'] if t['success']) / len(results['cracking_tests']),
            'avg_encoding_time': statistics.mean([t['execution_time'] for t in results['encoding_tests']]),
            'avg_decoding_time': statistics.mean([t['execution_time'] for t in results['decoding_tests']]),
            'avg_cracking_time': statistics.mean([t['execution_time'] for t in results['cracking_tests']]),
            'total_tests': len(results['encoding_tests']) + len(results['decoding_tests']) + len(results['cracking_tests'])
        }
        
        return results
    
    def test_cryptanalyzer(self) -> Dict[str, Any]:
        """Test the cryptanalyzer with various text types"""
        print("Testing Cryptanalyzer...")
        results = {
            'confidence_tests': [],
            'detection_tests': [],
            'performance': {}
        }
        
        analyzer = Cryptanalyzer()
        
        # Test confidence scoring with various text types
        test_texts = [
            ("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG", "English pangram"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Alphabet"),
            ("AAAAAAAAAAAAAAAAAAAAAAAAAA", "Repeated letters"),
            ("HELLO WORLD THIS IS A TEST MESSAGE", "Normal English"),
            ("QWERTYUIOPASDFGHJKLZXCVBNM", "Keyboard pattern"),
            ("", "Empty string"),
            ("1234567890", "Numbers only"),
            ("!@#$%^&*()", "Symbols only")
        ]
        
        for i, (text, description) in enumerate(test_texts):
            execution_time, result, memory_delta = self._time_function(
                analyzer._calculate_confidence, text
            )
            
            results['confidence_tests'].append({
                'test_id': i,
                'text': text,
                'description': description,
                'confidence': result,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Test cipher type detection
        detection_texts = [
            ("KHOORZRUOG", "Caesar cipher"),
            ("RIJVSUYVJN", "Vigenère cipher"),
            ("SVOOLDLIOW", "Atbash cipher"),
            ("HELLO WORLD", "Plain text")
        ]
        
        for i, (text, description) in enumerate(detection_texts):
            execution_time, result, memory_delta = self._time_function(
                analyzer._detect_cipher_type, text
            )
            
            results['detection_tests'].append({
                'test_id': i,
                'text': text,
                'description': description,
                'detection_result': result,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Calculate performance metrics
        results['performance'] = {
            'avg_confidence_time': statistics.mean([t['execution_time'] for t in results['confidence_tests']]),
            'avg_detection_time': statistics.mean([t['execution_time'] for t in results['detection_tests']]),
            'total_tests': len(results['confidence_tests']) + len(results['detection_tests'])
        }
        
        return results
    
    def test_integration_cryptanalyze(self) -> Dict[str, Any]:
        """Test the integrated cryptanalyze_text function"""
        print("Testing Integrated Cryptanalysis...")
        results = {
            'cryptanalysis_tests': [],
            'performance': {}
        }
        
        # Test with various cipher types
        test_cases = [
            ("KHOORZRUOG", "Caesar cipher with shift 3"),
            ("RIJVSUYVJN", "Vigenère cipher with key 'KEY'"),
            ("SVOOLDLIOW", "Atbash cipher"),
            ("HELLO WORLD", "Plain text")
        ]
        
        for i, (text, description) in enumerate(test_cases):
            execution_time, result, memory_delta = self._time_function(
                cryptanalyze_text, text, test_mode=True
            )
            
            results['cryptanalysis_tests'].append({
                'test_id': i,
                'text': text,
                'description': description,
                'result': result,
                'execution_time': execution_time,
                'memory_delta': memory_delta
            })
        
        # Calculate performance metrics
        results['performance'] = {
            'avg_cryptanalysis_time': statistics.mean([t['execution_time'] for t in results['cryptanalysis_tests']]),
            'total_tests': len(results['cryptanalysis_tests'])
        }
        
        return results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests and collect results"""
        print("Starting Comprehensive Test Suite...")
        print(f"Test started at: {self.results['test_start_time']}")
        
        # Run individual cipher tests
        self.results['test_results']['caesar'] = self.test_caesar_cipher()
        self.results['test_results']['vigenere'] = self.test_vigenere_cipher()
        self.results['test_results']['xor'] = self.test_xor_cipher()
        self.results['test_results']['atbash'] = self.test_atbash_cipher()
        self.results['test_results']['substitution'] = self.test_substitution_cipher()
        
        # Run analysis tests
        self.results['test_results']['cryptanalyzer'] = self.test_cryptanalyzer()
        self.results['test_results']['integration'] = self.test_integration_cryptanalyze()
        
        # Calculate overall metrics
        self.results['test_end_time'] = datetime.now().isoformat()
        self.results['overall_metrics'] = self._calculate_overall_metrics()
        
        return self.results
    
    def _calculate_overall_metrics(self) -> Dict[str, Any]:
        """Calculate overall performance and accuracy metrics"""
        metrics = {
            'total_tests': 0,
            'successful_tests': 0,
            'overall_success_rate': 0.0,
            'avg_execution_time': 0.0,
            'cipher_success_rates': {},
            'performance_summary': {}
        }
        
        total_time = 0.0
        total_tests = 0
        
        for cipher_type, results in self.results['test_results'].items():
            if 'performance' in results:
                perf = results['performance']
                metrics['cipher_success_rates'][cipher_type] = {
                    'encoding': perf.get('encoding_success_rate', 0),
                    'decoding': perf.get('decoding_success_rate', 0),
                    'cracking': perf.get('cracking_success_rate', 0)
                }
                
                # Calculate average times
                times = []
                if 'avg_encoding_time' in perf:
                    times.append(perf['avg_encoding_time'])
                if 'avg_decoding_time' in perf:
                    times.append(perf['avg_decoding_time'])
                if 'avg_cracking_time' in perf:
                    times.append(perf['avg_cracking_time'])
                if 'avg_confidence_time' in perf:
                    times.append(perf['avg_confidence_time'])
                if 'avg_detection_time' in perf:
                    times.append(perf['avg_detection_time'])
                if 'avg_cryptanalysis_time' in perf:
                    times.append(perf['avg_cryptanalysis_time'])
                
                if times:
                    avg_time = statistics.mean(times)
                    total_time += avg_time * perf.get('total_tests', 1)
                    total_tests += perf.get('total_tests', 0)
        
        if total_tests > 0:
            metrics['avg_execution_time'] = total_time / total_tests
            metrics['total_tests'] = total_tests
        
        return metrics
    
    def save_results(self, filename: str = None):
        """Save test results to file"""
        if filename is None:
            filename = f"comprehensive_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"Results saved to: {filename}")
        return filename
    
    def print_summary(self):
        """Print a summary of test results"""
        print("\n" + "="*80)
        print("COMPREHENSIVE TEST SUITE SUMMARY")
        print("="*80)
        
        print(f"Test Duration: {self.results['test_start_time']} to {self.results['test_end_time']}")
        print(f"Total Tests: {self.results['overall_metrics']['total_tests']}")
        print(f"Average Execution Time: {self.results['overall_metrics']['avg_execution_time']:.4f} seconds")
        
        print("\nCipher Success Rates:")
        for cipher, rates in self.results['overall_metrics']['cipher_success_rates'].items():
            print(f"  {cipher.upper()}:")
            print(f"    Encoding: {rates['encoding']:.2%}")
            print(f"    Decoding: {rates['decoding']:.2%}")
            print(f"    Cracking: {rates['cracking']:.2%}")
        
        print("\n" + "="*80)

def main():
    """Main test execution"""
    tester = ComprehensiveTester()
    
    try:
        results = tester.run_all_tests()
        tester.print_summary()
        
        # Save detailed results
        filename = tester.save_results()
        print(f"\nDetailed results saved to: {filename}")
        
        # Update the comprehensive report
        update_comprehensive_report(results)
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        tester.save_results("interrupted_test_results.json")
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        tester.results['error_log'].append(str(e))
        tester.save_results("error_test_results.json")

def update_comprehensive_report(results):
    """Update the comprehensive test report with results"""
    report_file = "COMPREHENSIVE_TEST_REPORT.md"
    
    if not os.path.exists(report_file):
        print(f"Report file {report_file} not found")
        return
    
    # Read current report
    with open(report_file, 'r') as f:
        content = f.read()
    
    # Update with actual results
    updates = []
    
    # Update system info
    system_info = results['system_info']
    updates.append(("**Memory:** [To be determined]", f"**Memory:** {system_info.get('memory', 'Unknown')}"))
    
    # Update test results
    for cipher_type, test_results in results['test_results'].items():
        if 'performance' in test_results:
            perf = test_results['performance']
            
            # Update success rates
            encoding_rate = perf.get('encoding_success_rate', 0)
            decoding_rate = perf.get('decoding_success_rate', 0)
            cracking_rate = perf.get('cracking_success_rate', 0)
            avg_time = perf.get('avg_encoding_time', 0) + perf.get('avg_decoding_time', 0) + perf.get('avg_cracking_time', 0)
            
            updates.extend([
                (f"- **Success Rate:** [To be calculated]", f"- **Success Rate:** {cracking_rate:.2%}"),
                (f"- **Average Time:** [To be measured]", f"- **Average Time:** {avg_time:.4f}s"),
                (f"- **Accuracy:** [To be measured]", f"- **Accuracy:** {encoding_rate:.2%} encoding, {decoding_rate:.2%} decoding")
            ])
    
    # Apply updates
    for old, new in updates:
        content = content.replace(old, new)
    
    # Update timestamp
    content = content.replace("**Last Updated:** [Timestamp]", f"**Last Updated:** {datetime.now().isoformat()}")
    
    # Write updated report
    with open(report_file, 'w') as f:
        f.write(content)
    
    print(f"Updated comprehensive report: {report_file}")

if __name__ == "__main__":
    main() 