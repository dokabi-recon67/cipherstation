#!/usr/bin/env python3
"""
CipherCore - Core cryptography functions for RELAYSTATION web interface
Extracted from CipherStation CLI for web-based encryption/decryption
"""

import os
import json
import base64
import time
import hashlib
import tempfile
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type as ArgonType

# ---------------- Utility Functions ----------------
def b64(x: bytes) -> str: 
    return base64.b64encode(x).decode()

def b64d(s: str) -> bytes: 
    return base64.b64decode(s.encode())

def generate_aes_key(bits: int = 256) -> bytes:
    if bits not in (128, 192, 256):
        raise ValueError("AES bits must be 128/192/256")
    return os.urandom(bits // 8)

# ---------------- Key Generation ----------------
def gen_ed25519(priv_path: str, pub_path: str):
    """Generate Ed25519 keypair and save to files."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()))
    
    with open(pub_path, "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw))

def gen_x25519(priv_path: str, pub_path: str):
    """Generate X25519 keypair and save to files."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()))
    
    with open(pub_path, "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw))

# ---------------- KDF (Argon2id) ----------------
def derive_key(password: str, salt: bytes = None, length: int = 32,
               time_cost=3, memory_cost=64_000, parallelism=2) -> Tuple[bytes, bytes]:
    """Derive key using Argon2id."""
    if salt is None:
        salt = os.urandom(16)
    key = hash_secret_raw(password.encode(), salt,
                          time_cost=time_cost, memory_cost=memory_cost,
                          parallelism=parallelism, hash_len=length, type=ArgonType.ID)
    return key, salt

def derive_key_from_password(password: str, algorithm: str) -> Tuple[bytes, bytes]:
    """Derive appropriate key length from password for given algorithm."""
    # Determine required key length based on algorithm
    alg_lower = algorithm.lower()
    if alg_lower.startswith("aes"):
        if "128" in alg_lower:
            key_length = 16  # 128 bits
        elif "192" in alg_lower:
            key_length = 24  # 192 bits
        elif "256" in alg_lower:
            key_length = 32  # 256 bits
        else:
            key_length = 32  # Default to 256 bits
    elif alg_lower == "chacha20":
        key_length = 32  # ChaCha20 requires 32 bytes
    else:
        key_length = 32  # Default
    
    # Derive key using Argon2id
    return derive_key(password, length=key_length)

# ---------------- AEAD Primitives ----------------
def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"", desc: str = "", version: int = 2) -> dict:
    """Encrypt data using AES-GCM."""
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, aad)
    tag = ct[-16:]
    body = ct[:-16]
    
    env = {
        "version": version,
        "alg": f"AES-{len(key)*8}-GCM",
        "iv": b64(nonce),  # V2 uses "iv" instead of "nonce"
        "ciphertext": b64(body),
        "tag": b64(tag),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    
    # V2 additions
    if version >= 2:
        if aad:
            env["aad"] = b64(aad)
        if desc:
            env["desc"] = desc
    
    return env

def aes_gcm_decrypt(key: bytes, env: dict, aad: bytes = b"") -> bytes:
    """Decrypt data using AES-GCM."""
    # Handle both V1 and V2 formats
    if "iv" in env:
        nonce = b64d(env["iv"])  # V2 format
    else:
        nonce = b64d(env["nonce"])  # V1 format
    
    body = b64d(env["ciphertext"])
    tag = b64d(env["tag"])
    
    # Use AAD from envelope if available (V2)
    if "aad" in env and not aad:
        aad = b64d(env["aad"])
    
    aes = AESGCM(key)
    return aes.decrypt(nonce, body + tag, aad)

def chacha_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"", desc: str = "", version: int = 2) -> dict:
    """Encrypt data using ChaCha20-Poly1305."""
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    nonce = os.urandom(12)
    c = ChaCha20Poly1305(key)
    ct = c.encrypt(nonce, plaintext, aad)
    tag = ct[-16:]
    body = ct[:-16]
    
    env = {
        "version": version,
        "alg": "CHACHA20-POLY1305",
        "iv": b64(nonce),  # V2 uses "iv" instead of "nonce"
        "ciphertext": b64(body),
        "tag": b64(tag),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    
    # V2 additions
    if version >= 2:
        if aad:
            env["aad"] = b64(aad)
        if desc:
            env["desc"] = desc
    
    return env

def chacha_decrypt(key: bytes, env: dict, aad: bytes = b"") -> bytes:
    """Decrypt data using ChaCha20-Poly1305."""
    # Handle both V1 and V2 formats
    if "iv" in env:
        nonce = b64d(env["iv"])  # V2 format
    else:
        nonce = b64d(env["nonce"])  # V1 format
    
    body = b64d(env["ciphertext"])
    tag = b64d(env["tag"])
    
    # Use AAD from envelope if available (V2)
    if "aad" in env and not aad:
        aad = b64d(env["aad"])
    
    c = ChaCha20Poly1305(key)
    return c.decrypt(nonce, body + tag, aad)

def decrypt_envelope_dispatch(key: bytes, env: dict) -> bytes:
    """Dispatch decryption based on algorithm."""
    alg = env.get("alg", "").upper()
    if alg.startswith("AES-") and alg.endswith("-GCM"):
        return aes_gcm_decrypt(key, env)
    if alg == "CHACHA20-POLY1305":
        return chacha_decrypt(key, env)
    raise ValueError(f"Unsupported algorithm: {alg}")

# ---------------- Password-Based Encryption ----------------
def encrypt_with_password(password: str, plaintext: bytes, algorithm: str = "aes256", 
                         desc: str = "", version: int = 2) -> dict:
    """Encrypt data using password-based key derivation."""
    # Derive key from password
    key, salt = derive_key_from_password(password, algorithm)
    
    # Encrypt based on algorithm
    alg_lower = algorithm.lower()
    if alg_lower.startswith("aes"):
        env = aes_gcm_encrypt(key, plaintext, desc=desc, version=version)
    elif alg_lower == "chacha20":
        env = chacha_encrypt(key, plaintext, desc=desc, version=version)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # Add salt to envelope for key derivation during decryption
    env["salt"] = b64(salt)
    env["kdf"] = "argon2id"
    
    return env

def decrypt_with_password(password: str, env: dict, expected_algorithm: str = None) -> bytes:
    """Decrypt data using password-based key derivation."""
    # Extract salt and derive key
    if "salt" not in env:
        raise ValueError("No salt found in encrypted data")
    
    salt = b64d(env["salt"])
    alg = env.get("alg", "").upper()
    
    # Determine algorithm from envelope
    if alg.startswith("AES-") and alg.endswith("-GCM"):
        algorithm = alg.lower().replace("-gcm", "")
    elif alg == "CHACHA20-POLY1305":
        algorithm = "chacha20"
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")
    
    # Validate algorithm if expected_algorithm is provided
    if expected_algorithm:
        expected_alg_lower = expected_algorithm.lower()
        if expected_alg_lower.startswith("aes"):
            # Normalize AES algorithm names
            if "128" in expected_alg_lower:
                expected_alg_normalized = "aes128"
            elif "192" in expected_alg_lower:
                expected_alg_normalized = "aes192"
            elif "256" in expected_alg_lower:
                expected_alg_normalized = "aes256"
            else:
                expected_alg_normalized = "aes256"
        elif expected_alg_lower == "chacha20":
            expected_alg_normalized = "chacha20"
        else:
            expected_alg_normalized = expected_alg_lower
            
        # Only validate if there's a clear mismatch (allow some flexibility)
        if algorithm != expected_alg_normalized:
            # For now, let's be more lenient and just warn instead of failing
            print(f"WARNING: Algorithm mismatch: encrypted with {algorithm}, user selected {expected_alg_normalized}")
            # Don't raise error - let the decryption proceed with the correct algorithm from the envelope
    
    # Determine key length based on algorithm
    if algorithm.startswith("aes"):
        if "128" in algorithm:
            key_length = 16  # 128 bits
        elif "192" in algorithm:
            key_length = 24  # 192 bits
        elif "256" in algorithm:
            key_length = 32  # 256 bits
        else:
            key_length = 32  # Default to 256 bits
    elif algorithm == "chacha20":
        key_length = 32  # ChaCha20 requires 32 bytes
    else:
        key_length = 32  # Default
    
    # Derive key from password using the stored salt
    key = hash_secret_raw(password.encode(), salt,
                          time_cost=3, memory_cost=64_000,
                          parallelism=2, hash_len=key_length, type=ArgonType.ID)
    
    # Decrypt
    return decrypt_envelope_dispatch(key, env)

# ---------------- Web Interface Functions ----------------
def encrypt_file(in_path: str, out_path: str, key_path: str, alg: str = "aes256", 
                 desc: str = "", version: int = 2) -> Dict[str, Any]:
    """Encrypt a file and return status information."""
    try:
        # Validate inputs
        if not os.path.exists(in_path):
            return {"success": False, "error": f"Input file not found: {in_path}"}
        if not os.path.exists(key_path):
            return {"success": False, "error": f"Key file not found: {key_path}"}
        
        # Read key and data
        with open(key_path, "rb") as f:
            key_bytes = f.read()
        with open(in_path, "rb") as f:
            data = f.read()
        
        # Validate algorithm and key length
        a = alg.lower()
        if a.startswith("aes"):
            bits = int(a[3:])
            if bits not in (128, 192, 256):
                return {"success": False, "error": "AES size must be 128|192|256"}
            if len(key_bytes) * 8 != bits:
                return {"success": False, "error": f"Key length {len(key_bytes)*8} bits != selected {bits} bits"}
            env = aes_gcm_encrypt(key_bytes, data, desc=desc, version=version)
        elif a == "chacha20":
            if len(key_bytes) != 32:
                return {"success": False, "error": "ChaCha20-Poly1305 requires 32-byte key"}
            env = chacha_encrypt(key_bytes, data, desc=desc, version=version)
        else:
            return {"success": False, "error": "Unknown algorithm"}
        
        # Write encrypted envelope
        with open(out_path, "w") as f:
            json.dump(env, f, indent=2)
        
        return {
            "success": True,
            "algorithm": env["alg"],
            "bytes": len(data),
            "output_path": out_path
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

def decrypt_file(in_path: str, out_path: str, key_path: str) -> Dict[str, Any]:
    """Decrypt a file and return status information."""
    try:
        # Validate inputs
        if not os.path.exists(in_path):
            return {"success": False, "error": f"Input file not found: {in_path}"}
        if not os.path.exists(key_path):
            return {"success": False, "error": f"Key file not found: {key_path}"}
        
        # Read key and envelope
        with open(key_path, "rb") as f:
            key_bytes = f.read()
        with open(in_path) as f:
            env = json.load(f)
        
        # Decrypt
        pt = decrypt_envelope_dispatch(key_bytes, env)
        
        # Write decrypted data
        with open(out_path, "wb") as f:
            f.write(pt)
        
        return {
            "success": True,
            "algorithm": env["alg"],
            "bytes": len(pt),
            "output_path": out_path
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

def run_selftest() -> Dict[str, Any]:
    """Run comprehensive cryptographic self-tests."""
    import secrets
    
    results = []
    passed = 0
    failed = 0
    
    def _record_test(name: str, success: bool, error: str = ""):
        nonlocal passed, failed
        if success:
            passed += 1
        else:
            failed += 1
        results.append({
            "name": name,
            "status": "PASS" if success else "FAIL",
            "error": error if not success else ""
        })
    
    # Test 1: AES roundtrip
    try:
        k = os.urandom(32)
        m = secrets.token_bytes(1024)
        env = aes_gcm_encrypt(k, m)
        rt = aes_gcm_decrypt(k, env)
        _record_test("AES roundtrip", rt == m)
    except Exception as e:
        _record_test("AES roundtrip", False, str(e))
    
    # Test 2: ChaCha roundtrip
    try:
        k = os.urandom(32)
        m = secrets.token_bytes(512)
        env = chacha_encrypt(k, m)
        rt = chacha_decrypt(k, env)
        _record_test("ChaCha roundtrip", rt == m)
    except Exception as e:
        _record_test("ChaCha roundtrip", False, str(e))
    
    # Test 3: Ed25519 sign/verify
    try:
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        msg = secrets.token_bytes(200)
        sig = priv.sign(msg)
        pub.verify(sig, msg)
        _record_test("Ed25519 sign/verify", True)
    except Exception as e:
        _record_test("Ed25519 sign/verify", False, str(e))
    
    # Test 4: Hybrid (X25519 + HKDF + AEAD)
    try:
        a_priv = x25519.X25519PrivateKey.generate()
        b_priv = x25519.X25519PrivateKey.generate()
        b_pub = b_priv.public_key()
        
        # Simulate encrypt to b_pub
        shared = a_priv.exchange(b_pub)
        salt = os.urandom(16)
        info = b"cipherstation-hybrid-v1"
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
        sym = hk.derive(shared)
        msg = secrets.token_bytes(333)
        env = aes_gcm_encrypt(sym, msg)
        
        # Decrypt using b_priv + a_priv.public_key()
        shared2 = b_priv.exchange(a_priv.public_key())
        hk2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
        sym2 = hk2.derive(shared2)
        rt = aes_gcm_decrypt(sym2, env)
        _record_test("Hybrid", rt == msg)
    except Exception as e:
        _record_test("Hybrid", False, str(e))
    
    return {
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "results": results
    }

def generate_temp_key(alg: str = "aes256") -> Tuple[str, str]:
    """Generate a temporary key file and return the path."""
    if alg.lower().startswith("aes"):
        bits = int(alg.lower()[3:])
        if bits not in (128, 192, 256):
            raise ValueError("AES size must be 128|192|256")
        key = os.urandom(bits // 8)
    elif alg.lower() == "chacha20":
        key = os.urandom(32)
    else:
        raise ValueError("Unknown algorithm")
    
    # Create temporary key file
    fd, key_path = tempfile.mkstemp(suffix=".key", prefix="relaystation_")
    os.close(fd)
    
    with open(key_path, "wb") as f:
        f.write(key)
    
    return key_path, b64(key)

def cleanup_temp_files(*file_paths):
    """Clean up temporary files."""
    for path in file_paths:
        try:
            if os.path.exists(path):
                os.unlink(path)
        except Exception:
            pass  # Ignore cleanup errors 