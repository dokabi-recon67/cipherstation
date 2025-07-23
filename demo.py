#!/usr/bin/env python3
"""
Ultimate Demo for CipherStation CLI Cracker
Showcases multi-cipher cracking, custom wordlist, and confidence scoring.
"""

def ultimate_demo():
    print("\n🔒 ULTIMATE DEMO: Multi-Cipher, Custom Wordlist, and Confidence Scoring\n")

    # 1. Caesar Cipher
    caesar_plain = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    caesar_shift = 7
    caesar_encrypted = "".join(
        chr(((ord(c) - 65 + caesar_shift) % 26) + 65) if c.isalpha() else c
        for c in caesar_plain.upper()
    )
    print(f"Caesar Encrypted: {caesar_encrypted}")

    # 2. Vigenère Cipher with custom key
    vigenere_plain = "ENIGMA MACHINE"
    vigenere_key = "SECRET"
    from classical_ciphers import VigenereCipher
    vigenere = VigenereCipher()
    vigenere_encrypted = vigenere.encode(vigenere_plain, vigenere_key)
    print(f"Vigenère Encrypted: {vigenere_encrypted} (key: {vigenere_key})")

    # 3. Atbash Cipher
    atbash_plain = "HELLO WORLD"
    atbash_encrypted = "".join(
        chr(90 - (ord(c) - 65)) if c.isalpha() else c
        for c in atbash_plain.upper()
    )
    print(f"Atbash Encrypted: {atbash_encrypted}")

    # 4. XOR Cipher (single-byte key)
    xor_plain = "SECRET DATA"
    xor_key = 42
    xor_encrypted = "".join(chr(ord(c) ^ xor_key) for c in xor_plain)
    print(f"XOR Encrypted (hex): {' '.join(hex(ord(c))[2:] for c in xor_encrypted)} (key: {xor_key})")

    # 5. Substitution Cipher (identity, for demo)
    substitution_plain = "CRYPTOGRAPHY"
    substitution_encrypted = substitution_plain  # For demo, just use identity
    print(f"Substitution Encrypted: {substitution_encrypted}")

    # Now, run the cracker on each
    from cli_cracker import AdvancedCLICracker
    cracker = AdvancedCLICracker()
    print("\n--- Cracking Caesar ---")
    cracker._print_results(cracker.crack_text(caesar_encrypted))
    print("\n--- Cracking Vigenère (with custom wordlist) ---")
    # Save custom wordlist to file
    with open("custom_words.txt", "w") as f:
        f.write("SECRET\n")
    cracker._print_results(cracker.crack_text(vigenere_encrypted, custom_wordlist_file="custom_words.txt"))
    print("\n--- Cracking Atbash ---")
    cracker._print_results(cracker.crack_text(atbash_encrypted))
    print("\n--- Cracking XOR ---")
    cracker._print_results(cracker.crack_text(xor_encrypted))
    print("\n--- Cracking Substitution ---")
    cracker._print_results(cracker.crack_text(substitution_encrypted))

    print("\n🎉 Demo complete! This shows multi-cipher, custom wordlist, and confidence scoring in action.\n")

if __name__ == "__main__":
    ultimate_demo() 