#!/usr/bin/env python3
"""
CipherStation - single-file CLI cryptography toolkit (CS50 Final Project core).

Features:
- AES-256-GCM & ChaCha20-Poly1305 encryption/decryption
- Ed25519 & X25519 key generation (future expansion)
- Argon2id password-based key derivation
- Audit log with hash chaining
- Format detection
- Interactive menu with progress bars
- Classical ciphers (Caesar, Vigenère, XOR, Atbash, Substitution)
"""

import os, json, base64, time, hashlib, re
import typer
from typing import Optional, Tuple, Iterable
from rich import print
from rich.progress import (
    Progress, BarColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn
)
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type as ArgonType

# Import classical ciphers
try:
    from classical_ciphers import (
        CaesarCipher, VigenereCipher, XORCipher, AtbashCipher, SubstitutionCipher,
        encode_text, decode_text, cryptanalyze_text, Cryptanalyzer
    )
    CLASSICAL_CIPHERS_AVAILABLE = True
except ImportError:
    CLASSICAL_CIPHERS_AVAILABLE = False
    print("[yellow]Warning: Classical ciphers module not found. Install with: pip install classical_ciphers[/yellow]")

app = typer.Typer(help="CipherStation single-file CLI")

# ---------------- Utility ----------------
def b64(x: bytes) -> str: return base64.b64encode(x).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s.encode())

# ---------------- Key Generation ----------------
def generate_aes_key(bits: int = 256) -> bytes:
    if bits not in (128,192,256):
        raise ValueError("AES bits must be 128/192/256")
    return os.urandom(bits//8)

def write_binary(path: str, data: bytes):
    with open(path, "wb") as f: f.write(data)

def gen_ed25519(priv_path: str, pub_path: str):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    write_binary(priv_path, priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()))
    write_binary(pub_path, pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw))

def gen_x25519(priv_path: str, pub_path: str):
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    write_binary(priv_path, priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()))
    write_binary(pub_path, pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw))

# ---------------- KDF (Argon2id) ----------------
def derive_key(password: str, salt: bytes=None, length: int=32,
               time_cost=3, memory_cost=64_000, parallelism=2) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    key = hash_secret_raw(password.encode(), salt,
                          time_cost=time_cost, memory_cost=memory_cost,
                          parallelism=parallelism, hash_len=length, type=ArgonType.ID)
    return key, salt

# ---------------- AEAD Primitives ----------------
def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes=b"", desc: str="", version: int=2) -> dict:
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

def aes_gcm_decrypt(key: bytes, env: dict, aad: bytes=b"") -> bytes:
    # Handle both V1 and V2 formats
    if "iv" in env:
        nonce = b64d(env["iv"])  # V2 format
    else:
        nonce = b64d(env["nonce"])  # V1 format
    
    body = b64d(env["ciphertext"])
    tag  = b64d(env["tag"])
    
    # Use AAD from envelope if available (V2)
    if "aad" in env and not aad:
        aad = b64d(env["aad"])
    
    aes = AESGCM(key)
    return aes.decrypt(nonce, body+tag, aad)

def chacha_encrypt(key: bytes, plaintext: bytes, aad: bytes=b"", desc: str="", version: int=2) -> dict:
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

def chacha_decrypt(key: bytes, env: dict, aad: bytes=b"") -> bytes:
    # Handle both V1 and V2 formats
    if "iv" in env:
        nonce = b64d(env["iv"])  # V2 format
    else:
        nonce = b64d(env["nonce"])  # V1 format
    
    body = b64d(env["ciphertext"])
    tag  = b64d(env["tag"])
    
    # Use AAD from envelope if available (V2)
    if "aad" in env and not aad:
        aad = b64d(env["aad"])
    
    c = ChaCha20Poly1305(key)
    return c.decrypt(nonce, body+tag, aad)

def decrypt_envelope_dispatch(key: bytes, env: dict) -> bytes:
    alg = env.get("alg","").upper()
    if alg.startswith("AES-") and alg.endswith("-GCM"):
        return aes_gcm_decrypt(key, env)
    if alg == "CHACHA20-POLY1305":
        return chacha_decrypt(key, env)
    raise ValueError(f"Unsupported algorithm: {alg}")


# ---------------- Key Registry ----------------
KEY_REGISTRY_PATH = "key_registry.json"

def _load_registry():
    if not os.path.exists(KEY_REGISTRY_PATH):
        return []
    try:
        return json.load(open(KEY_REGISTRY_PATH))
    except Exception:
        return []

def _save_registry(entries):
    open(KEY_REGISTRY_PATH,"w").write(json.dumps(entries, indent=2))

def _add_registry_entry(entry):
    reg=_load_registry()
    reg.append(entry)
    _save_registry(reg)
# ---------------- Audit Log ----------------
LOG_PATH = "audit.log"

def _hash_line(prev_hash: str, payload: dict) -> str:
    h=hashlib.sha256()
    h.update(prev_hash.encode())
    h.update(json.dumps(payload, sort_keys=True).encode())
    return h.hexdigest()

def audit_append(op: str, meta: dict):
    prev="0"*64
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH,"r") as f:
            lines=f.read().strip().splitlines()
            if lines:
                try: prev=json.loads(lines[-1])["hash"]
                except: pass
    entry={"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "op": op, "meta": meta, "prev_hash": prev}
    entry["hash"]=_hash_line(prev, entry)
    with open(LOG_PATH,"a") as f:
        f.write(json.dumps(entry)+"\n")

def audit_verify() -> Tuple[bool,int]:
    if not os.path.exists(LOG_PATH): return True,0
    prev="0"*64
    for i,line in enumerate(open(LOG_PATH),1):
        obj=json.loads(line)
        exp=_hash_line(prev,{k:obj[k] for k in obj if k!="hash"})
        if obj["hash"]!=exp: return False,i
        prev=obj["hash"]
    return True,i if 'i' in locals() else 0

# ---------------- Detection ----------------
def is_base64(s: str) -> bool:
    try:
        base64.b64decode(s.encode(), validate=True); return True
    except Exception:
        return False

def detect_formats(text: str):
    results=[]
    stripped=text.strip()
    try:
        obj=json.loads(text)
        if isinstance(obj,dict) and {"alg","ciphertext","nonce","tag"}.issubset(obj):
            results.append(("cipherstation-envelope",0.95))
    except: pass
    if "-----BEGIN" in stripped:
        results.append(("pem",0.7))
    if re.fullmatch(r'[A-Za-z0-9_-]{86}', stripped):
        results.append(("fernet-like",0.4))
    if is_base64(stripped):
        results.append(("base64",0.3))
    if not results:
        results.append(("unknown",0.1))
    return sorted(results, key=lambda x:x[1], reverse=True)

# ---------------- Progress ----------------
def _progress_task(label: str, total: int, steps: Iterable[int]):
    with Progress(
        SpinnerColumn(),
        "[bold cyan]{task.description}",
        BarColumn(bar_width=30),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        TimeRemainingColumn(),
    ) as progress:
        tid = progress.add_task(label, total=total)
        start = time.time()
        for inc in steps:
            progress.update(tid, advance=inc)
        progress.update(tid, completed=total)
        end = time.time()
        print(f"[green]{label} done in {end-start:.2f}s[/green]")

def _sim_steps(n=10, delay=0.05, total=100):
    chunk = total//n
    for _ in range(n):
        time.sleep(delay)
        yield chunk

# ---------------- CLI Commands ----------------

@app.command()
def keygen(
    alg: str = typer.Argument(..., help="aes128|aes192|aes256|ed25519|x25519"),
    out: str = typer.Option(None, help="Output file for symmetric key"),
    priv: str = typer.Option(None, help="Private key path (asymmetric)"),
    pub: str = typer.Option(None, help="Public key path (asymmetric)")
):
    """
    Generate symmetric AES key or 25519 keypair.
    Records fingerprint in key_registry.json.
    """
    alg_lower = alg.lower()

    if alg_lower.startswith("aes"):
        # Parse size
        try:
            bits = int(alg_lower[3:])
        except ValueError:
            raise typer.BadParameter("Use aes128|aes192|aes256")
        if bits not in (128, 192, 256):
            raise typer.BadParameter("AES size must be 128/192/256")
        if not out:
            raise typer.BadParameter("Provide --out for AES key")
        key = os.urandom(bits // 8)
        with open(out, "wb") as f:
            f.write(key)
        fp = hashlib.sha256(key).hexdigest()[:16]
        audit_append("keygen", {"alg": f"aes{bits}"})
        try:
            _add_registry_entry({
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "type": f"aes{bits}",
                "path": out,
                "bytes": len(key),
                "fingerprint": fp
            })
        except Exception:
            pass
        print(f"[green]Generated AES-{bits} key -> {out}[/green]")
        print(f"Fingerprint: {fp}")

    elif alg_lower == "ed25519":
        if not (priv and pub):
            raise typer.BadParameter("Need --priv and --pub for ed25519")
        gen_ed25519(priv, pub)
        pub_bytes = open(pub, "rb").read()
        fp = hashlib.sha256(pub_bytes).hexdigest()[:16]
        audit_append("keygen", {"alg": "ed25519"})
        try:
            _add_registry_entry({
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "type": "ed25519",
                "path": priv,
                "pub": pub,
                "bytes": 32,
                "fingerprint": fp
            })
        except Exception:
            pass
        print("[green]Generated Ed25519 keypair[/green]")
        print(f"Public fingerprint: {fp}")

    elif alg_lower == "x25519":
        if not (priv and pub):
            raise typer.BadParameter("Need --priv and --pub for x25519")
        gen_x25519(priv, pub)
        pub_bytes = open(pub, "rb").read()
        fp = hashlib.sha256(pub_bytes).hexdigest()[:16]
        audit_append("keygen", {"alg": "x25519"})
        try:
            _add_registry_entry({
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "type": "x25519",
                "path": priv,
                "pub": pub,
                "bytes": 32,
                "fingerprint": fp
            })
        except Exception:
            pass
        print("[green]Generated X25519 keypair[/green]")
        print(f"Public fingerprint: {fp}")

    else:
        raise typer.BadParameter("Unknown algorithm (use aes128|aes192|aes256|ed25519|x25519)")


@app.command()
def derive(
    password: str = typer.Option(..., prompt=True, hide_input=True),
           out: str = typer.Option("derived.key"),
    salt_out: str = typer.Option("derived.salt"),
    time_cost: int = typer.Option(3, help="Argon2id time cost"),
    memory_cost: int = typer.Option(64_000, help="Argon2id memory (KiB)"),
    parallelism: int = typer.Option(2, help="Argon2id parallelism")
):
    """Derive a 32-byte key with Argon2id (tunable parameters)."""
    key, salt = derive_key(password, None, length=32,
                           time_cost=time_cost,
                           memory_cost=memory_cost,
                           parallelism=parallelism)
    write_binary(out, key)
    write_binary(salt_out, salt)
    audit_append("derive", {"alg": "Argon2id", "t": time_cost, "m": memory_cost, "p": parallelism})
    fp = hashlib.sha256(key).hexdigest()[:16]
    print(f"[green]Derived key -> {out} (salt -> {salt_out})[/green]\nFingerprint: {fp}")
    try:
        _add_registry_entry({
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": "derived",
            "path": out,
            "bytes": len(key),
            "fingerprint": fp,
            "salt": salt_out,
            "argon2": {"t": time_cost, "m": memory_cost, "p": parallelism}
        })
    except Exception:
        pass

@app.command()
def encrypt(
    alg: str = typer.Option("aes256", help="aes128|aes192|aes256|chacha20"),
    key: Optional[str] = typer.Option(None, help="Raw key file"),
    infile: str = typer.Option(..., help="Plaintext input file"),
    out: str = typer.Option(..., help="Output JSON envelope"),
    password: Optional[str] = typer.Option(None, help="Password (Argon2id)"),
    salt: Optional[str] = typer.Option(None, help="Salt file for password derivation"),
    generate_salt: bool = typer.Option(True, help="Generate salt if missing (with --password)"),
    progress: bool = typer.Option(False, help="Show progress bar (adds slight delay)"),
    aad: Optional[str] = typer.Option(None, help="Associated authenticated data (base64)"),
    desc: Optional[str] = typer.Option(None, help="Description for V2 envelope"),
    version: int = typer.Option(2, help="Envelope version (1 or 2)")
):
    """Encrypt file using chosen AEAD with minimal overhead."""
    if (key is None) == (password is None):
        raise typer.BadParameter("Provide exactly one of --key or --password")

    # Acquire key
    if password:
        salt_bytes = None
        if salt:
            if not os.path.exists(salt):
                raise typer.BadParameter(f"Salt file not found: {salt}")
            salt_bytes = open(salt, 'rb').read()
        elif not generate_salt:
            raise typer.BadParameter("Either provide --salt or allow --generate-salt")
        key_bytes, used_salt = derive_key(password, salt_bytes)
        if salt is None and generate_salt:
            open("salt.generated", "wb").write(used_salt)
            print("[yellow]Generated new salt: salt.generated[/yellow]")
    else:
        if not os.path.exists(key):
            raise typer.BadParameter(f"Key file not found: {key}")
        key_bytes = open(key, "rb").read()

    if not os.path.exists(infile):
        raise typer.BadParameter(f"Input file not found: {infile}")
    data = open(infile, "rb").read()

    # Process AAD if provided
    aad_bytes = b""
    if aad:
        try:
            aad_bytes = b64d(aad)
        except Exception:
            raise typer.BadParameter("Invalid AAD: must be valid base64")

    a = alg.lower()
    if a.startswith("aes"):
        bits = int(a[3:])
        if bits not in (128, 192, 256):
            raise typer.BadParameter("AES size must be 128|192|256")
        if len(key_bytes) * 8 != bits:
            print(f"[yellow]Warning: key length {len(key_bytes)*8} bits != selected {bits} bits[/yellow]")
        env = aes_gcm_encrypt(key_bytes, data, aad_bytes, desc, version)
    elif a == "chacha20":
        if len(key_bytes) != 32:
            raise typer.BadParameter("ChaCha20-Poly1305 requires 32-byte key")
        env = chacha_encrypt(key_bytes, data, aad_bytes, desc, version)
    else:
        raise typer.BadParameter("Unknown alg")

    with open(out, "w") as f:
        json.dump(env, f, indent=2)
    audit_append("encrypt", {"alg": env["alg"], "bytes": len(data)})
    if progress:
        _progress_task("Encrypting", 100, _sim_steps(n=5, delay=0.02))
    print(f"[green]Encrypted {len(data)} bytes -> {out}[/green]\n[cyan]Algorithm:[/cyan] {env['alg']}")


@app.command()
def decrypt(
    key: Optional[str] = typer.Option(None, help="Raw key path (omit if using --password)"),
    infile: str = typer.Option(..., help="JSON envelope file"),
    out: str = typer.Option(..., help="Decrypted output file"),
    password: Optional[str] = typer.Option(None, help="Password for Argon2id derivation"),
    salt: Optional[str] = typer.Option(None, help="Salt file required with --password"),
    progress: bool = typer.Option(False, help="Show progress bar (adds slight delay)")
):
    """Decrypt envelope (AES-GCM or ChaCha20-Poly1305)."""
    if not os.path.exists(infile):
        raise typer.BadParameter(f"Input file not found: {infile}")
    env = json.load(open(infile))

    if (key is None) == (password is None):
        raise typer.BadParameter("Provide exactly one of --key or --password")

    if password:
        if salt is None:
            raise typer.BadParameter("Need --salt with --password")
        if not os.path.exists(salt):
            raise typer.BadParameter(f"Salt file not found: {salt}")
        key_bytes, _ = derive_key(password, open(salt,'rb').read())
    else:
        if not os.path.exists(key):
            raise typer.BadParameter(f"Key file not found: {key}")
        key_bytes = open(key,'rb').read()

    pt = decrypt_envelope_dispatch(key_bytes, env)
    with open(out,"wb") as f:
        f.write(pt)
    audit_append("decrypt", {"alg": env["alg"], "bytes": len(pt)})
    if progress:
        _progress_task("Decrypting", 100, _sim_steps(n=5, delay=0.02))
    print(f"[green]Decrypted -> {out}[/green]")

@app.command("detect")
def detect_cmd(infile: str = typer.Argument(...)):
    """Heuristically detect format of a file's contents."""
    text=open(infile).read()
    guesses=detect_formats(text)
    for fmt,score in guesses:
        print(f"{fmt}: {score:.2f}")

@app.command("audit-verify")
def audit_verify_cmd():
    """Verify audit log hash chain and summarize."""
    ok,line=audit_verify()
    if not ok:
        print(f"[red]Audit log tampered near line {line}![/red]")
        return
    print("[green]Audit log OK[/green]")
    entries=[]
    try:
        for l in open(LOG_PATH):
            entries.append(json.loads(l))
    except Exception:
        print("[yellow]Could not parse some entries for summary.[/yellow]")
        return
    from collections import Counter
    ops=Counter(e.get("op") for e in entries)
    first=entries[0]["ts"] if entries else "-"
    last=entries[-1]["ts"] if entries else "-"
    algs=set()
    for e in entries:
        meta=e.get("meta",{})
        a=meta.get("alg")
        if a: algs.add(a)
    print("Entries:", len(entries))
    print("Operation counts:", dict(ops))
    print("Algorithms seen:", sorted(algs))
    print("First timestamp:", first)
    print("Last timestamp:", last)

# ---------------- MENU MODE ----------------
def _read_multiline(prompt: str) -> bytes:
    print(prompt + " (finish with an empty line):")
    lines=[]
    while True:
        try:
            line=input()
        except EOFError:
            break
        if line=="":
            break
        lines.append(line)
    return ("\n".join(lines)).encode()

def _rand_key(): return generate_aes_key(256)

def _choose_algorithm():
    print("\nChoose Algorithm:")
    print(" 1) AES-256-GCM (random key or existing)")
    print(" 2) ChaCha20-Poly1305 (random key or existing)")
    print(" 3) AES-256-GCM (password-derived)")
    print(" 4) ChaCha20-Poly1305 (password-derived)")
    while True:
        c=input("Enter 1-4: ").strip()
        if c in {"1","2","3","4"}: return c
        print("Invalid selection.")

def classical_cipher_menu():
    """Classical cipher submenu."""
    if not CLASSICAL_CIPHERS_AVAILABLE:
        print("[red]Classical ciphers not available.[/red]")
        return
    
    print("\n=== Classical Ciphers Menu ===")
    while True:
        print("\nClassical Cipher Options:")
        print(" 1) Encode Text")
        print(" 2) Decode Text")
        print(" 3) Crack Cipher (Auto-detect)")
        print(" 4) Run Self-Test")
        print(" 5) Back to Main Menu")
        
        choice = input("Select option (1-5): ").strip()
        
        if choice == "1":
            print("\n--- Encode Text ---")
            cipher = input("Cipher type (caesar/vigenere/xor/atbash/substitution): ").strip().lower()
            text = input("Text to encode: ").strip()
            
            if cipher == "caesar":
                shift = input("Shift (default 3): ").strip()
                shift = int(shift) if shift else 3
                try:
                    encoded = encode_text(text, "caesar", shift=shift)
                    print(f"[green]Encoded: {encoded}[/green]")
                except Exception as e:
                    print(f"[red]Error: {e}[/red]")
            
            elif cipher == "vigenere":
                key = input("Key: ").strip()
                if key:
                    try:
                        encoded = encode_text(text, "vigenere", key=key)
                        print(f"[green]Encoded: {encoded}[/green]")
                    except Exception as e:
                        print(f"[red]Error: {e}[/red]")
                else:
                    print("[red]Key required for Vigenère cipher[/red]")
            
            elif cipher == "xor":
                key = input("Key: ").strip()
                if key:
                    try:
                        encoded = encode_text(text, "xor", key=key)
                        print(f"[green]Encoded: {encoded}[/green]")
                    except Exception as e:
                        print(f"[red]Error: {e}[/red]")
                else:
                    print("[red]Key required for XOR cipher[/red]")
            
            elif cipher == "atbash":
                try:
                    encoded = encode_text(text, "atbash")
                    print(f"[green]Encoded: {encoded}[/green]")
                except Exception as e:
                    print(f"[red]Error: {e}[/red]")
            
            elif cipher == "substitution":
                key = input("Substitution key (26 letters): ").strip()
                if key and len(key) == 26:
                    try:
                        encoded = encode_text(text, "substitution", key=key)
                        print(f"[green]Encoded: {encoded}[/green]")
                    except Exception as e:
                        print(f"[red]Error: {e}[/red]")
                else:
                    print("[red]Substitution key must be exactly 26 letters[/red]")
            
            else:
                print("[red]Unknown cipher type[/red]")
        
        elif choice == "2":
            print("\n--- Decode Text ---")
            cipher = input("Cipher type (caesar/vigenere/xor/atbash/substitution): ").strip().lower()
            text = input("Text to decode: ").strip()
            
            if cipher == "caesar":
                shift = input("Shift (default 3): ").strip()
                shift = int(shift) if shift else 3
                try:
                    decoded = decode_text(text, "caesar", shift=shift)
                    print(f"[green]Decoded: {decoded}[/green]")
                except Exception as e:
                    print(f"[red]Error: {e}[/red]")
            
            elif cipher == "vigenere":
                key = input("Key: ").strip()
                if key:
                    try:
                        decoded = decode_text(text, "vigenere", key=key)
                        print(f"[green]Decoded: {decoded}[/green]")
                    except Exception as e:
                        print(f"[red]Error: {e}[/red]")
                else:
                    print("[red]Key required for Vigenère cipher[/red]")
            
            elif cipher == "xor":
                key = input("Key: ").strip()
                if key:
                    try:
                        decoded = decode_text(text, "xor", key=key)
                        print(f"[green]Decoded: {decoded}[/green]")
                    except Exception as e:
                        print(f"[red]Error: {e}[/red]")
                else:
                    print("[red]Key required for XOR cipher[/red]")
            
            elif cipher == "atbash":
                try:
                    decoded = decode_text(text, "atbash")
                    print(f"[green]Decoded: {decoded}[/green]")
                except Exception as e:
                    print(f"[red]Error: {e}[/red]")
            
            elif cipher == "substitution":
                key = input("Substitution key (26 letters): ").strip()
                if key and len(key) == 26:
                    try:
                        decoded = decode_text(text, "substitution", key=key)
                        print(f"[green]Decoded: {decoded}[/green]")
                    except Exception as e:
                        print(f"[red]Error: {e}[/red]")
                else:
                    print("[red]Substitution key must be exactly 26 letters[/red]")
            
            else:
                print("[red]Unknown cipher type[/red]")
        
        elif choice == "3":
            print("\n--- Crack Cipher ---")
            text = input("Encrypted text to crack: ").strip()
            if text:
                try:
                    print("[cyan]Analyzing...[/cyan]")
                    results = cryptanalyze_text(text)
                    
                    print(f"[green]Analysis completed in {results['analysis_time']:.3f}s[/green]")
                    print(f"[cyan]Text length: {results['input_length']} characters[/cyan]")
                    print(f"[cyan]Entropy: {results['statistics']['entropy']:.2f}[/cyan]")
                    
                    if results['best_results']:
                        print(f"\n[cyan]Best result:[/cyan]")
                        best = results['best_results'][0]
                        print(f"[green]{best['cipher'].upper()} (key: {best['key']}) - Confidence: {best['confidence']:.2f}[/green]")
                        print(f"Decoded: {best['decoded']}")
                        
                        if len(results['best_results']) > 1:
                            print(f"\n[cyan]Other possibilities:[/cyan]")
                            for i, result in enumerate(results['best_results'][1:4], 2):
                                print(f"{i}. {result['cipher'].upper()} (key: {result['key']}) - Confidence: {result['confidence']:.2f}")
                                print(f"   {result['decoded'][:50]}{'...' if len(result['decoded']) > 50 else ''}")
                    else:
                        print("[red]No results found[/red]")
                        
                except Exception as e:
                    print(f"[red]Error: {e}[/red]")
            else:
                print("[red]No text provided[/red]")
        
        elif choice == "4":
            print("\n--- Running Self-Test ---")
            try:
                classical_selftest()
            except Exception as e:
                print(f"[red]Self-test failed: {e}[/red]")
        
        elif choice == "5":
            break
        
        else:
            print("[red]Invalid option[/red]")

def menu_mode():
    print("=== CipherStation Menu v1 ===")
    while True:
        print("\nMain Menu:")
        print(" 1) Encrypt TEXT")
        print(" 2) Decrypt TEXT (paste envelope)")
        print(" 3) Encrypt FILE")
        print(" 4) Decrypt FILE")
        print(" 5) Generate Key Files")
        print(" 6) List Algorithms")
        if CLASSICAL_CIPHERS_AVAILABLE:
            print(" 7) Classical Ciphers")
            print(" 8) Quit")
        else:
            print(" 7) Quit")
        choice=input("Select option (1-8): ").strip()

        if choice=="7" and CLASSICAL_CIPHERS_AVAILABLE:
            classical_cipher_menu()
            continue
        elif choice=="7" or choice=="8":
            print("Goodbye.")
            break
        elif choice=="6":
            print("\nSupported:")
            print(" - AES-256-GCM")
            print(" - ChaCha20-Poly1305")
            print(" - Argon2id (password KDF)")
            print(" - Ed25519/X25519 keygen (CLI only for now)")
            continue
        elif choice=="5":
            print("\nGenerate Key:")
            print("1) AES-256 (writes aes.key)")
            print("2) Ed25519 keypair (ed.priv / ed.pub)")
            print("3) X25519 keypair (x.priv / x.pub)")
            ksel=input("Select 1-3: ").strip()
            if ksel=="1":
                k=_rand_key(); open("aes.key","wb").write(k)
                print("Saved aes.key (32 bytes). Fingerprint:", hashlib.sha256(k).hexdigest()[:16])
            elif ksel=="2":
                gen_ed25519("ed.priv","ed.pub")
                print("Saved ed.priv / ed.pub.")
            elif ksel=="3":
                gen_x25519("x.priv","x.pub")
                print("Saved x.priv / x.pub.")
            else:
                print("Invalid.")
            continue
        elif choice in {"1","3"}:  # Encrypt TEXT
            mode_alg=_choose_algorithm()
            user_key_bytes=None; supplied=None
            text_bytes=_read_multiline("Enter plaintext lines")
            if not text_bytes:
                print("No input.")
                continue
            if mode_alg in {"1","2"}:  # random / existing key
                if input("Use existing key file? (y/N): ").lower().startswith("y"):
                    while True:
                        kp=input("Key file path: ").strip()
                        if kp and os.path.exists(kp):
                            kb=open(kp,"rb").read()
                            if len(kb) not in (16,24,32):
                                print("Invalid key length (need 16/24/32 bytes).")
                                continue
                            user_key_bytes=kb; supplied=kp; break
                        print("Not found.")
                if user_key_bytes is not None:
                    key=user_key_bytes
                    print(f"[cyan]Using existing key {supplied}[/cyan]")
                else:
                    key=_rand_key()
                    fname=f"key_{int(time.time())}.bin"
                    open(fname,"wb").write(key)
                    print(f"[green]Generated key -> {fname}[/green]")
                print("Key fingerprint:", hashlib.sha256(key).hexdigest()[:16])
            else:  # password-derived
                pw=typer.prompt("Enter password", hide_input=True, confirmation_prompt=True)
                key,salt=derive_key(pw, None)
                sfile=f"salt_{int(time.time())}.bin"; open(sfile,"wb").write(salt)
                print(f"[cyan]Derived key; salt saved {sfile}[/cyan]")
                print("Key fingerprint:", hashlib.sha256(key).hexdigest()[:16])

            if mode_alg in {"2","4"} and len(key)!=32:
                print("ChaCha20-Poly1305 requires 32-byte key. Aborting.")
                continue

            if mode_alg in {"1","3"}:
                env=aes_gcm_encrypt(key, text_bytes)
            else:
                env=chacha_encrypt(key, text_bytes)

            _progress_task("Encrypting", 100, _sim_steps())
            preview=json.dumps(env, indent=2)
            print("\nEncrypted Envelope:\n", preview[:400] + ("..." if len(preview)>400 else ""))
            if input("Save to file? (y/N): ").lower().startswith("y"):
                fname=input("Filename (default text.enc.json): ").strip() or "text.enc.json"
                open(fname,"w").write(preview)
                print("Saved", fname)
        elif choice in {"2","4"}:  # Decrypt TEXT / FILE
            src="paste" if choice=="2" else "file"
            if src=="paste":
                buf=_read_multiline("Paste envelope JSON")
                try:
                    env=json.loads(buf.decode())
                except Exception as e:
                    print("Invalid JSON:", e); continue
            else:
                path=input("Envelope file path: ").strip()
                if not os.path.exists(path):
                    print("Not found."); continue
                try:
                    env=json.load(open(path))
                except Exception as e:
                    print("Load error:", e); continue
            alg=env.get("alg","?")
            print("Detected alg:", alg)
            using_pw=input("Use password derivation? (y/N): ").lower().startswith("y")
            if using_pw:
                salt_path=input("Salt file path: ").strip()
                if not os.path.exists(salt_path):
                    print("Salt missing."); continue
                pw=typer.prompt("Password", hide_input=True)
                key,_=derive_key(pw, open(salt_path,'rb').read())
            else:
                key_path=input("Key file path: ").strip()
                if not os.path.exists(key_path):
                    print("Key missing."); continue
                key=open(key_path,'rb').read()
            print("Key fingerprint:", hashlib.sha256(key).hexdigest()[:16])
            try:
                pt=decrypt_envelope_dispatch(key, env)
            except Exception as e:
                print("Decrypt failed:", e); continue
            _progress_task("Decrypting", 100, _sim_steps())
            print("\nPlaintext:")
            try: print(pt.decode())
            except: print(pt)
            if src=="file" and input("Save plaintext? (y/N): ").lower().startswith("y"):
                fname=input("Filename (default decrypted.out): ").strip() or "decrypted.out"
                open(fname,"wb").write(pt)
                print("Saved", fname)
        else:
            print("Invalid option.")
# end menu_mode

@app.command("menu")
def menu():
    """Launch interactive menu mode."""
    menu_mode()


@app.command("key-registry-list")
def key_registry_list():
    """List stored key fingerprints."""
    from rich.table import Table
    tbl = Table(title="Key Registry")
    for col in ("created","type","bytes","fingerprint","path"):
        tbl.add_column(col)
    entries = _load_registry()
    for e in entries:
        tbl.add_row(e.get("created",""), e.get("type",""), str(e.get("bytes","")), e.get("fingerprint",""), e.get("path",""))
    if not entries:
        print("[yellow]Registry empty.[/yellow]")
    else:
        from rich import print as rprint
        rprint(tbl)


@app.command("sign")
def sign_cmd(priv: str = typer.Option(..., help="Ed25519 private key (raw 32 bytes)"),
             infile: str = typer.Option(..., help="File to sign"),
             sig: str = typer.Option(..., help="Output signature json")):
    """Sign file with Ed25519."""
    if not os.path.exists(priv):
        raise typer.BadParameter(f"Private key file not found: {priv}")
    if not os.path.exists(infile):
        raise typer.BadParameter(f"Input file not found: {infile}")
    
    key_bytes = open(priv, "rb").read()
    if len(key_bytes) != 32:
        raise typer.BadParameter("Ed25519 raw private key must be 32 bytes.")
    
    privk = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
    data = open(infile, "rb").read()
    signature = privk.sign(data)
    
    # Create simplified signature envelope
    env = {
        "alg": "ed25519",
        "sig": b64(signature),
        "hash": hashlib.sha256(data).hexdigest(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    
    with open(sig, "w") as f:
        json.dump(env, f, indent=2)
    
    audit_append("sign", {"file": infile, "bytes": len(data)})
    print(f"[green]Signed {infile} -> {sig}[/green]")

@app.command("verify")
def verify_cmd(sig: str = typer.Option(..., help="Signature json"),
               pub: str = typer.Option(..., help="Ed25519 public key file"),
               infile: str = typer.Option(..., help="Original file to verify")):
    """Verify Ed25519 signature."""
    if not os.path.exists(sig):
        raise typer.BadParameter(f"Signature file not found: {sig}")
    if not os.path.exists(pub):
        raise typer.BadParameter(f"Public key file not found: {pub}")
    if not os.path.exists(infile):
        raise typer.BadParameter(f"Input file not found: {infile}")
    
    env = json.load(open(sig))
    if env.get("alg") != "ed25519":
        raise typer.BadParameter("Not an Ed25519 signature envelope.")
    
    # Read public key
    pub_bytes = open(pub, "rb").read()
    if len(pub_bytes) != 32:
        raise typer.BadParameter("Ed25519 public key must be 32 bytes.")
    
    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    
    # Read and verify file
    data = open(infile, "rb").read()
    file_hash = hashlib.sha256(data).hexdigest()
    
    if file_hash != env["hash"]:
        print("[red]Hash mismatch (file altered).[/red]")
        raise typer.Exit(1)
    
    try:
        pub_key.verify(b64d(env["sig"]), data)
        print("[green]Signature VALID[/green]")
        audit_append("verify", {"file": infile, "result": "valid"})
    except Exception:
        print("[red]Signature INVALID[/red]")
        audit_append("verify", {"file": infile, "result": "invalid"})
        raise typer.Exit(1)


@app.command("hybrid-encrypt")
def hybrid_encrypt(peer_pub: str = typer.Option(..., help="Peer X25519 public key file"),
                   infile: str = typer.Option(..., help="Plaintext file"),
                   out: str = typer.Option(..., help="Output hybrid envelope"),
                   alg: str = typer.Option("aes256", help="aes256|chacha20")):
    """Ephemeral X25519 + HKDF + AEAD."""
    peer_bytes = open(peer_pub,"rb").read()
    if len(peer_bytes)!=32:
        raise typer.BadParameter("X25519 public key must be 32 raw bytes.")
    peer = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    shared = eph_priv.exchange(peer)
    salt = os.urandom(16)
    info = b"cipherstation-hybrid-v1"
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    sym_key = hkdf.derive(shared)
    data = open(infile,"rb").read()
    if alg.lower()=="aes256":
        env_inner = aes_gcm_encrypt(sym_key, data)
    elif alg.lower()=="chacha20":
        env_inner = chacha_encrypt(sym_key, data)
    else:
        raise typer.BadParameter("alg must be aes256 or chacha20")
    env = {
        "version":1,
        "type":"hybrid",
        "kdf":"HKDF-SHA256",
        "salt": b64(salt),
        "info": b64(info),
        "enc_alg": env_inner["alg"],
        "ephemeral_pub": b64(eph_pub),
        "cipher": env_inner,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    open(out,"w").write(json.dumps(env, indent=2))
    audit_append("hybrid-encrypt", {"bytes": len(data), "alg": env_inner["alg"]})
    print(f"[green]Hybrid encrypted {len(data)} bytes -> {out}[/green]")

@app.command("hybrid-decrypt")
def hybrid_decrypt(priv: str = typer.Option(..., help="X25519 private key file"),
                   infile: str = typer.Option(..., help="Hybrid envelope"),
                   out: str = typer.Option(..., help="Decrypted file output")):
    env = json.load(open(infile))
    if env.get("type")!="hybrid":
        raise typer.BadParameter("Not a hybrid envelope.")
    priv_bytes = open(priv,"rb").read()
    if len(priv_bytes)!=32:
        raise typer.BadParameter("X25519 private key must be 32 bytes.")
    privk = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    eph_pub = x25519.X25519PublicKey.from_public_bytes(b64d(env["ephemeral_pub"]))
    shared = privk.exchange(eph_pub)
    salt = b64d(env["salt"])
    info = b64d(env["info"])
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    sym_key = hkdf.derive(shared)
    inner = env["cipher"]
    if inner["alg"].startswith("AES-"):
        plaintext = aes_gcm_decrypt(sym_key, inner)
    elif inner["alg"]=="CHACHA20-POLY1305":
        plaintext = chacha_decrypt(sym_key, inner)
    else:
        raise typer.BadParameter("Unsupported inner alg.")
    open(out,"wb").write(plaintext)
    audit_append("hybrid-decrypt", {"bytes": len(plaintext), "alg": inner["alg"]})
    print(f"[green]Hybrid decrypted -> {out}[/green]")


@app.command("encrypt-dir")
def encrypt_dir(alg: str = typer.Option("aes256"),
                key: str = typer.Option(...),
                in_dir: str = typer.Option(...),
                out_dir: str = typer.Option(...),
                manifest: str = typer.Option("manifest.json"),
                progress: bool = typer.Option(True, help="Show progress bar"),
                desc: Optional[str] = typer.Option(None, help="Description for encrypted files")):
    """Encrypt all files in directory with progress tracking."""
    if not os.path.isdir(in_dir):
        raise typer.BadParameter("in_dir must exist")
    if not os.path.exists(key):
        raise typer.BadParameter(f"Key file not found: {key}")
    
    os.makedirs(out_dir, exist_ok=True)
    kbytes = open(key, "rb").read()
    
    # Get list of files to encrypt
    files_to_encrypt = []
    for fname in sorted(os.listdir(in_dir)):
        path = os.path.join(in_dir, fname)
        if os.path.isfile(path):
            files_to_encrypt.append((fname, path))
    
    if not files_to_encrypt:
        print("[yellow]No files found to encrypt[/yellow]")
        return
    
    entries = []
    total_files = len(files_to_encrypt)
    
    if progress:
        with Progress(
            SpinnerColumn(),
            "[bold cyan]{task.description}",
            BarColumn(bar_width=30),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        ) as progress_bar:
            task = progress_bar.add_task("Encrypting files", total=total_files)
            
            for fname, path in files_to_encrypt:
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    
                    if alg.lower() == "aes256":
                        env = aes_gcm_encrypt(kbytes, data, desc=desc)
                    elif alg.lower() == "chacha20":
                        env = chacha_encrypt(kbytes, data, desc=desc)
                    else:
                        raise typer.BadParameter("alg must be aes256|chacha20")
                    
                    out_path = os.path.join(out_dir, fname + ".enc.json")
                    with open(out_path, "w") as f:
                        json.dump(env, f, indent=2)
                    
                    entries.append({
                        "file": fname,
                        "size": len(data),
                        "enc_file": os.path.basename(out_path)
                    })
                    
                    audit_append("encrypt-file", {"file": fname, "bytes": len(data), "alg": env["alg"]})
                    progress_bar.update(task, advance=1)
                    
                except Exception as e:
                    print(f"[red]Error encrypting {fname}: {e}[/red]")
                    continue
    else:
        # Fast path without progress bar
        for fname, path in files_to_encrypt:
            try:
                with open(path, "rb") as f:
                    data = f.read()
                
                if alg.lower() == "aes256":
                    env = aes_gcm_encrypt(kbytes, data, desc=desc)
                elif alg.lower() == "chacha20":
                    env = chacha_encrypt(kbytes, data, desc=desc)
                else:
                    raise typer.BadParameter("alg must be aes256|chacha20")
                
                out_path = os.path.join(out_dir, fname + ".enc.json")
                with open(out_path, "w") as f:
                    json.dump(env, f, indent=2)
                
                entries.append({
                    "file": fname,
                    "size": len(data),
                    "enc_file": os.path.basename(out_path)
                })
                
                audit_append("encrypt-file", {"file": fname, "bytes": len(data), "alg": env["alg"]})
                
            except Exception as e:
                print(f"[red]Error encrypting {fname}: {e}[/red]")
                continue
    
    # Create manifest
    manifest_obj = {
        "version": 1,
        "dir": in_dir,
        "alg": alg,
        "files": entries,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    
    with open(os.path.join(out_dir, manifest), "w") as f:
        json.dump(manifest_obj, f, indent=2)
    
    print(f"[green]Encrypted {len(entries)} files -> {out_dir} (manifest {manifest})[/green]")

@app.command("decrypt-dir")
def decrypt_dir(key: str = typer.Option(...),
                manifest: str = typer.Option(...),
                out_dir: str = typer.Option(...),
                progress: bool = typer.Option(True, help="Show progress bar")):
    """Decrypt files using manifest with progress tracking."""
    if not os.path.exists(manifest):
        raise typer.BadParameter(f"Manifest file not found: {manifest}")
    if not os.path.exists(key):
        raise typer.BadParameter(f"Key file not found: {key}")
    
    man = json.load(open(manifest))
    files = man.get("files", [])
    
    if not files:
        print("[yellow]No files found in manifest[/yellow]")
        return
    
    os.makedirs(out_dir, exist_ok=True)
    kbytes = open(key, "rb").read()
    count = 0
    total_files = len(files)
    
    if progress:
        with Progress(
            SpinnerColumn(),
            "[bold cyan]{task.description}",
            BarColumn(bar_width=30),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        ) as progress_bar:
            task = progress_bar.add_task("Decrypting files", total=total_files)
            
    for entry in files:
                try:
                    # Handle both old and new manifest formats
                    enc_file = entry.get("encrypted") or entry.get("enc_file")
                    orig_file = entry.get("original") or entry.get("file")
                    
                    if not enc_file or not orig_file:
                        print(f"[yellow]Invalid entry in manifest: {entry}[/yellow]")
                        continue
                    
                    enc_path = os.path.join(os.path.dirname(manifest), enc_file)
                    if not os.path.exists(enc_path):
                        print(f"[yellow]Missing {enc_file}, skipping[/yellow]")
                        continue
                    
                    with open(enc_path) as f:
                        env = json.load(f)
                    
                    if env["alg"].startswith("AES-"):
                        pt = aes_gcm_decrypt(kbytes, env)
                    elif env["alg"] == "CHACHA20-POLY1305":
                        pt = chacha_decrypt(kbytes, env)
                    else:
                        print(f"[red]Unsupported alg in {enc_file}[/red]")
                        continue
                    
                    with open(os.path.join(out_dir, orig_file), "wb") as f:
                        f.write(pt)
                    
                    count += 1
                    progress_bar.update(task, advance=1)
                    
                except Exception as e:
                    print(f"[red]Error decrypting {entry.get('file', 'unknown')}: {e}[/red]")
                    continue
    else:
        # Fast path without progress bar
        for entry in files:
            try:
                # Handle both old and new manifest formats
                enc_file = entry.get("encrypted") or entry.get("enc_file")
                orig_file = entry.get("original") or entry.get("file")
                
                if not enc_file or not orig_file:
                    print(f"[yellow]Invalid entry in manifest: {entry}[/yellow]")
                    continue
                
                enc_path = os.path.join(os.path.dirname(manifest), enc_file)
                if not os.path.exists(enc_path):
                    print(f"[yellow]Missing {enc_file}, skipping[/yellow]")
                    continue
                
                with open(enc_path) as f:
                    env = json.load(f)
                
                if env["alg"].startswith("AES-"):
                    pt = aes_gcm_decrypt(kbytes, env)
                elif env["alg"] == "CHACHA20-POLY1305":
                    pt = chacha_decrypt(kbytes, env)
                else:
                    print(f"[red]Unsupported alg in {enc_file}[/red]")
                    continue
                
                with open(os.path.join(out_dir, orig_file), "wb") as f:
                    f.write(pt)
                
                count += 1
                
            except Exception as e:
                print(f"[red]Error decrypting {entry.get('file', 'unknown')}: {e}[/red]")
                continue
    
    audit_append("decrypt-dir", {"files": count})
    print(f"[green]Decrypted {count} files -> {out_dir}[/green]")


@app.command("selftest")
def selftest():
    """Run internal crypto self-tests."""
    import secrets
    passed=[]
    failed=[]
    def _record(name, cond, err=""):
        (passed if cond else failed).append(name if cond else f"{name} ({err})")
    # AES roundtrip
    try:
        k=os.urandom(32); m=secrets.token_bytes(1024)
        env=aes_gcm_encrypt(k,m)
        rt=aes_gcm_decrypt(k,env)
        _record("AES roundtrip", rt==m)
    except Exception as e:
        _record("AES roundtrip", False, str(e))
    # ChaCha roundtrip
    try:
        k=os.urandom(32); m=secrets.token_bytes(512)
        env=chacha_encrypt(k,m); rt=chacha_decrypt(k,env)
        _record("ChaCha roundtrip", rt==m)
    except Exception as e:
        _record("ChaCha roundtrip", False, str(e))
    # Ed25519 sign/verify
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        priv=ed25519.Ed25519PrivateKey.generate()
        pub=priv.public_key()
        msg=secrets.token_bytes(200)
        sig=priv.sign(msg)
        pub.verify(sig,msg)
        _record("Ed25519 sign/verify", True)
    except Exception as e:
        _record("Ed25519 sign/verify", False, str(e))
    # Hybrid
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        a_priv=x25519.X25519PrivateKey.generate()
        b_priv=x25519.X25519PrivateKey.generate()
        b_pub=b_priv.public_key()
        # Simulate encrypt to b_pub
        shared = a_priv.exchange(b_pub)
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        salt=os.urandom(16); info=b"cipherstation-hybrid-v1"
        hk=HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
        sym=hk.derive(shared)
        msg=secrets.token_bytes(333)
        env=aes_gcm_encrypt(sym,msg)
        # Decrypt using b_priv + a_priv.public_key()
        shared2 = b_priv.exchange(a_priv.public_key())
        hk2=HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
        sym2=hk2.derive(shared2)
        rt=aes_gcm_decrypt(sym2, env)
        _record("Hybrid", rt==msg)
    except Exception as e:
        _record("Hybrid", False, str(e))
    from rich.table import Table
    tbl=Table(title="Self Test Results")
    tbl.add_column("Test")
    tbl.add_column("Status")
    for name in passed:
        tbl.add_row(name, "[green]PASS[/green]")
    for name in failed:
        tbl.add_row(name, "[red]FAIL[/red]")
    from rich import print as rprint
    rprint(tbl)
    if failed:
        print(f"[red]{len(failed)} test(s) failed.[/red]")
        raise typer.Exit(1)
    print(f"[green]All {len(passed)} tests passed.[/green]")

# ---------------- Classical Cipher Commands ----------------

@app.command("classical-encode")
def classical_encode(
    cipher: str = typer.Option(..., help="caesar|vigenere|xor|atbash|substitution"),
    text: str = typer.Option(..., help="Text to encode"),
    key: Optional[str] = typer.Option(None, help="Key for cipher (shift for Caesar, key for others)"),
    out: Optional[str] = typer.Option(None, help="Output file (optional)"),
    shift: Optional[int] = typer.Option(None, help="Shift value for Caesar cipher")
):
    """Encode text using classical ciphers."""
    if not CLASSICAL_CIPHERS_AVAILABLE:
        raise typer.BadParameter("Classical ciphers module not available")
    
    cipher = cipher.lower()
    
    try:
        if cipher == "caesar":
            if shift is None:
                shift = int(key) if key else 3
            encoded = encode_text(text, "caesar", shift=shift)
            key_info = f"shift={shift}"
        elif cipher == "vigenere":
            if not key:
                raise typer.BadParameter("Vigenère cipher requires a key")
            encoded = encode_text(text, "vigenere", key=key)
            key_info = f"key={key}"
        elif cipher == "xor":
            if not key:
                raise typer.BadParameter("XOR cipher requires a key")
            encoded = encode_text(text, "xor", key=key)
            key_info = f"key={key}"
        elif cipher == "atbash":
            encoded = encode_text(text, "atbash")
            key_info = "atbash"
        elif cipher == "substitution":
            if not key:
                raise typer.BadParameter("Substitution cipher requires a key")
            encoded = encode_text(text, "substitution", key=key)
            key_info = f"key={key}"
        else:
            raise typer.BadParameter(f"Unknown cipher: {cipher}")
        
        print(f"[green]Encoded text using {cipher.upper()} cipher ({key_info}):[/green]")
        print(f"[cyan]{encoded}[/cyan]")
        
        if out:
            with open(out, "w") as f:
                f.write(encoded)
            print(f"[green]Saved to: {out}[/green]")
        
        audit_append("classical-encode", {"cipher": cipher, "key_info": key_info})
        
    except Exception as e:
        raise typer.BadParameter(f"Encoding failed: {e}")

@app.command("classical-decode")
def classical_decode(
    cipher: str = typer.Option(..., help="caesar|vigenere|xor|atbash|substitution"),
    text: str = typer.Option(..., help="Text to decode"),
    key: Optional[str] = typer.Option(None, help="Key for cipher (shift for Caesar, key for others)"),
    out: Optional[str] = typer.Option(None, help="Output file (optional)"),
    shift: Optional[int] = typer.Option(None, help="Shift value for Caesar cipher")
):
    """Decode text using classical ciphers."""
    if not CLASSICAL_CIPHERS_AVAILABLE:
        raise typer.BadParameter("Classical ciphers module not available")
    
    cipher = cipher.lower()
    
    try:
        if cipher == "caesar":
            if shift is None:
                shift = int(key) if key else 3
            decoded = decode_text(text, "caesar", shift=shift)
            key_info = f"shift={shift}"
        elif cipher == "vigenere":
            if not key:
                raise typer.BadParameter("Vigenère cipher requires a key")
            decoded = decode_text(text, "vigenere", key=key)
            key_info = f"key={key}"
        elif cipher == "xor":
            if not key:
                raise typer.BadParameter("XOR cipher requires a key")
            decoded = decode_text(text, "xor", key=key)
            key_info = f"key={key}"
        elif cipher == "atbash":
            decoded = decode_text(text, "atbash")
            key_info = "atbash"
        elif cipher == "substitution":
            if not key:
                raise typer.BadParameter("Substitution cipher requires a key")
            decoded = decode_text(text, "substitution", key=key)
            key_info = f"key={key}"
        else:
            raise typer.BadParameter(f"Unknown cipher: {cipher}")
        
        print(f"[green]Decoded text using {cipher.upper()} cipher ({key_info}):[/green]")
        print(f"[cyan]{decoded}[/cyan]")
        
        if out:
            with open(out, "w") as f:
                f.write(decoded)
            print(f"[green]Saved to: {out}[/green]")
        
        audit_append("classical-decode", {"cipher": cipher, "key_info": key_info})
        
    except Exception as e:
        raise typer.BadParameter(f"Decoding failed: {e}")

@app.command("classical-crack")
def classical_crack(
    text: str = typer.Argument(..., help="Text to crack"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed analysis")
):
    """Crack classical ciphers with advanced frequency analysis"""
    if not CLASSICAL_CIPHERS_AVAILABLE:
        typer.echo("❌ Classical ciphers module not available")
        raise typer.Exit(1)
    
    try:
        typer.echo("🔍 Analyzing encrypted text...")
        start_time = time.time()
        
        results = cryptanalyze_text(text)
        analysis_time = time.time() - start_time
        
        typer.echo(f"✅ Cryptanalysis completed in {analysis_time:.3f}s")
        typer.echo(f"📊 Text length: {results['input_length']} characters")
        typer.echo(f"📈 Entropy: {results['statistics']['entropy']:.2f}")
        typer.echo(f"🔤 Unique characters: {results['statistics']['unique_chars']}")
        typer.echo(f"📝 Alpha ratio: {results['statistics']['alpha_ratio']:.2f}")
        
        if verbose:
            typer.echo("\n📊 Detailed Frequency Analysis:")
            # Calculate letter frequencies
            text_upper = text.upper()
            char_count = {}
            total_chars = 0
            
            for char in text_upper:
                if char.isalpha():
                    char_count[char] = char_count.get(char, 0) + 1
                    total_chars += 1
            
            # Show frequency chart
            typer.echo("Letter frequencies:")
            for char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if total_chars > 0:
                    freq = char_count.get(char, 0) / total_chars
                    bar_length = int(freq * 50)
                    bar = '█' * bar_length
                    typer.echo(f"  {char}: {bar} {freq:.3f}")
        
        if results['detected_ciphers']:
            typer.echo("\n🎯 Detected cipher types:")
            for cipher_type, confidence in results['detected_ciphers']:
                typer.echo(f"  {cipher_type.upper()}: {confidence:.2f}")
        
        if results['best_results']:
            typer.echo(f"\n🏆 Top {min(5, len(results['best_results']))} results:")
            for i, result in enumerate(results['best_results'][:5], 1):
                confidence_pct = result['confidence'] * 100
                typer.echo(f"{i}. {result['cipher'].upper()} (key: {result['key']}) - Confidence: {confidence_pct:.1f}%")
                typer.echo(f"    Decoded: {result['decoded']}")
                if i < min(5, len(results['best_results'])):
                    typer.echo()
        
    except Exception as e:
        typer.echo(f"❌ Error during cryptanalysis: {e}")
        raise typer.Exit(1)

@app.command("classical-selftest")
def classical_selftest():
    """Test classical cipher functionality."""
    if not CLASSICAL_CIPHERS_AVAILABLE:
        raise typer.BadParameter("Classical ciphers module not available")
    
    print("[cyan]Running classical cipher self-tests...[/cyan]")
    
    test_cases = [
        ("caesar", "HELLO WORLD", {"shift": 3}, "KHOORZRUOG"),
        ("vigenere", "HELLO WORLD", {"key": "KEY"}, "RIJVSUYVJN"),
        ("xor", "HELLO", {"key": "XOR"}, "QKACA"),
        ("atbash", "HELLO WORLD", {}, "SVOOLDLIOW"),
    ]
    
    passed = 0
    total = len(test_cases)
    
    for cipher, plaintext, params, expected in test_cases:
        try:
            encoded = encode_text(plaintext, cipher, **params)
            if cipher == "xor":
                # XOR produces binary, compare differently
                success = len(encoded) == len(expected)
            else:
                success = encoded == expected
            
            if success:
                print(f"[green]✓ {cipher.upper()} test passed[/green]")
                passed += 1
            else:
                print(f"[red]✗ {cipher.upper()} test failed[/red]")
                print(f"  Expected: {expected}")
                print(f"  Got: {encoded}")
        except Exception as e:
            print(f"[red]✗ {cipher.upper()} test failed: {e}[/red]")
    
    print(f"\n[cyan]Classical cipher tests: {passed}/{total} passed[/cyan]")
    
    if passed == total:
        print("[green]All classical cipher tests passed![/green]")
    else:
        print("[red]Some classical cipher tests failed.[/red]")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()

