#!/usr/bin/env python3
"""
Test script for improved classical cipher cracking
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from classical_ciphers import (
    encode_text, decode_text, cryptanalyze_text
)

def test_simple_cracking():
    """Test simple cracking scenarios"""
    print("🔍 Testing Improved Classical Cipher Cracking")
    print("=" * 50)
    
    # Test 1: Simple Caesar cipher
    print("\n1. Testing Caesar cipher with shift 1:")
    original = "wow"
    encoded = encode_text(original, "caesar", shift=1)
    print(f"   Original: '{original}'")
    print(f"   Encoded:  '{encoded}'")
    
    results = cryptanalyze_text(encoded, test_mode=True)
    if results.get('best_results'):
        best = results['best_results'][0]
        print(f"   Cracked:  '{best['decoded']}' (confidence: {best['confidence']:.2f})")
        print(f"   Cipher:   {best['cipher'].upper()} (key: {best['key']})")
        expected = original.upper().replace(' ', '')
        found = any(expected in r['decoded'].replace(' ', '') for r in results['best_results'][:5])
        if not found:
            print(f"[WARN] '{expected}' not found in top 5 results. This may be a hard edge case.")
        else:
            print(f"[PASS] '{expected}' found in top 5 results.")
        print("Top results:")
        for r in results['best_results'][:5]:
            print(f"Decoded: {r['decoded']} | Confidence: {r['confidence']}")
    else:
        print("[SKIP] No results found.")
    
    # Test 2: Caesar cipher with shift 3
    print("\n2. Testing Caesar cipher with shift 3:")
    original = "hello world"
    encoded = encode_text(original, "caesar", shift=3)
    print(f"   Original: '{original}'")
    print(f"   Encoded:  '{encoded}'")
    
    results = cryptanalyze_text(encoded, test_mode=True)
    if results.get('best_results'):
        best = results['best_results'][0]
        print(f"   Cracked:  '{best['decoded']}' (confidence: {best['confidence']:.2f})")
        print(f"   Cipher:   {best['cipher'].upper()} (key: {best['key']})")
        expected = original.upper().replace(' ', '')
        found = any(expected in r['decoded'].replace(' ', '') for r in results['best_results'][:5])
        if not found:
            print(f"[WARN] '{expected}' not found in top 5 results. This may be a hard edge case.")
        else:
            print(f"[PASS] '{expected}' found in top 5 results.")
        print("Top results:")
        for r in results['best_results'][:5]:
            print(f"Decoded: {r['decoded']} | Confidence: {r['confidence']}")
    else:
        print("[SKIP] No results found.")
    
    # Test 3: Vigenère cipher
    print("\n3. Testing Vigenère cipher:")
    original = "this is a test message"
    encoded = encode_text(original, "vigenere", key="SECRET")
    print(f"   Original: '{original}'")
    print(f"   Encoded:  '{encoded}'")
    
    results = cryptanalyze_text(encoded, test_mode=True)
    if results.get('best_results'):
        best = results['best_results'][0]
        print(f"   Cracked:  '{best['decoded']}' (confidence: {best['confidence']:.2f})")
        print(f"   Cipher:   {best['cipher'].upper()} (key: {best['key']})")
        expected = original.upper().replace(' ', '')
        found = any(expected in r['decoded'].replace(' ', '') for r in results['best_results'][:5])
        if not found:
            print(f"[WARN] '{expected}' not found in top 5 results. This may be a hard edge case.")
        else:
            print(f"[PASS] '{expected}' found in top 5 results.")
        print("Top results:")
        for r in results['best_results'][:5]:
            print(f"Decoded: {r['decoded']} | Confidence: {r['confidence']}")
    else:
        print("[SKIP] No results found.")
    
    # Test 4: Atbash cipher
    print("\n4. Testing Atbash cipher:")
    original = "hello world"
    encoded = encode_text(original, "atbash")
    print(f"   Original: '{original}'")
    print(f"   Encoded:  '{encoded}'")
    
    results = cryptanalyze_text(encoded, test_mode=True)
    if results.get('best_results'):
        best = results['best_results'][0]
        print(f"   Cracked:  '{best['decoded']}' (confidence: {best['confidence']:.2f})")
        print(f"   Cipher:   {best['cipher'].upper()} (key: {best['key']})")
        expected = original.upper().replace(' ', '')
        found = any(expected in r['decoded'].replace(' ', '') for r in results['best_results'][:5])
        if not found:
            print(f"[WARN] '{expected}' not found in top 5 results. This may be a hard edge case.")
        else:
            print(f"[PASS] '{expected}' found in top 5 results.")
        print("Top results:")
        for r in results['best_results'][:5]:
            print(f"Decoded: {r['decoded']} | Confidence: {r['confidence']}")
    else:
        print("[SKIP] No results found.")
    
    # Test 5: Your specific example
    print("\n5. Testing your example:")
    encoded = "Wklv lv d whvw phvvdjh."
    print(f"   Encoded:  '{encoded}'")
    
    results = cryptanalyze_text(encoded, test_mode=True)
    if results.get('best_results'):
        print(f"   Top 3 results:")
        for i, result in enumerate(results['best_results'][:3], 1):
            print(f"   {i}. {result['cipher'].upper()} (key: {result['key']}) - Confidence: {result['confidence']:.2f}")
            print(f"      Decoded: '{result['decoded']}'")
            if i < 3:
                print()
        print("Top results:")
        for r in results['best_results'][:5]:
            print(f"Decoded: {r['decoded']} | Confidence: {r['confidence']}")
    else:
        print("[SKIP] No results found.")

if __name__ == "__main__":
    test_simple_cracking() 