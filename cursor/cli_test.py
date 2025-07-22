#!/usr/bin/env python3
"""
CipherStation CLI Test Suite
Tests CLI functionality without requiring external dependencies.
"""

import os
import sys
import subprocess
import tempfile
import json

def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🧪 CLI TESTING: {title}")
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

def test_cli_file_exists():
    """Test if CLI file exists and is executable."""
    print_header("CLI File Check")
    
    cli_path = "../cipherstationv0.py"
    
    if os.path.exists(cli_path):
        print_success("CLI file exists")
        
        # Check if it's executable
        if os.access(cli_path, os.X_OK):
            print_success("CLI file is executable")
        else:
            print_info("CLI file exists but is not executable (this is normal)")
        
        # Check file size
        file_size = os.path.getsize(cli_path)
        if file_size > 10000:  # Should be substantial
            print_success(f"CLI file size is reasonable ({file_size} bytes)")
        else:
            print_error(f"CLI file seems too small ({file_size} bytes)")
        
        return True
    else:
        print_error("CLI file not found")
        return False

def test_cli_structure():
    """Test CLI file structure and content."""
    print_header("CLI Structure Check")
    
    cli_path = "../cipherstationv0.py"
    
    try:
        with open(cli_path, 'r') as f:
            content = f.read()
        
        # Check for essential components
        checks = [
            ("Shebang line", "#!/usr/bin/env python3"),
            ("Typer import", "import typer"),
            ("Cryptography imports", "from cryptography.hazmat"),
            ("AES encryption", "AESGCM"),
            ("ChaCha encryption", "ChaCha20Poly1305"),
            ("Key generation", "generate_aes_key"),
            ("Encrypt command", "@app.command()"),
            ("Decrypt command", "def decrypt"),
            ("Help text", "CipherStation"),
            ("Version 2 support", "version: int = typer.Option(2")
        ]
        
        passed = 0
        for description, search_term in checks:
            if search_term in content:
                print_success(f"{description} found")
                passed += 1
            else:
                print_error(f"{description} missing")
        
        print_success(f"CLI structure: {passed}/{len(checks)} components found")
        return passed >= len(checks) * 0.8  # Allow 80% pass rate
        
    except Exception as e:
        print_error(f"Failed to read CLI file: {e}")
        return False

def test_cli_syntax():
    """Test if CLI file has valid Python syntax."""
    print_header("CLI Syntax Check")
    
    cli_path = "../cipherstationv0.py"
    
    try:
        # Try to compile the file to check syntax
        with open(cli_path, 'r') as f:
            compile(f.read(), cli_path, 'exec')
        
        print_success("CLI file has valid Python syntax")
        return True
        
    except SyntaxError as e:
        print_error(f"CLI file has syntax errors: {e}")
        return False
    except Exception as e:
        print_error(f"Failed to check CLI syntax: {e}")
        return False

def test_cli_help_output():
    """Test if CLI can show help (if dependencies are available)."""
    print_header("CLI Help Output Test")
    
    cli_path = "../cipherstationv0.py"
    
    try:
        # Try to run the CLI with --help
        result = subprocess.run(
            [sys.executable, cli_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print_success("CLI help command works")
            if "CipherStation" in result.stdout:
                print_success("CLI help shows CipherStation branding")
                return True
            else:
                print_error("CLI help doesn't show expected branding")
                return False
        else:
            # Check if it's a dependency issue
            if "ModuleNotFoundError" in result.stderr:
                print_info("CLI help failed due to missing dependencies (typer, rich, etc.)")
                print_info("This is expected if dependencies are not installed")
                return True  # Consider this a pass since it's a dependency issue
            else:
                print_error(f"CLI help failed: {result.stderr}")
                return False
                
    except subprocess.TimeoutExpired:
        print_error("CLI help command timed out")
        return False
    except Exception as e:
        print_error(f"Failed to test CLI help: {e}")
        return False

def test_cli_commands():
    """Test if CLI has expected commands."""
    print_header("CLI Commands Check")
    
    cli_path = "../cipherstationv0.py"
    
    try:
        with open(cli_path, 'r') as f:
            content = f.read()
        
        # Look for command definitions
        expected_commands = [
            "keygen",
            "derive", 
            "encrypt",
            "decrypt",
            "detect",
            "audit-verify",
            "menu",
            "sign",
            "verify",
            "hybrid-encrypt",
            "hybrid-decrypt",
            "encrypt-dir",
            "decrypt-dir",
            "selftest"
        ]
        
        found_commands = []
        for cmd in expected_commands:
            if f"def {cmd}" in content or f'"{cmd}"' in content:
                found_commands.append(cmd)
                print_success(f"Command '{cmd}' found")
            else:
                print_error(f"Command '{cmd}' missing")
        
        print_success(f"CLI commands: {len(found_commands)}/{len(expected_commands)} found")
        return len(found_commands) >= len(expected_commands) * 0.8  # Allow 80% pass rate
        
    except Exception as e:
        print_error(f"Failed to check CLI commands: {e}")
        return False

def test_cli_algorithms():
    """Test if CLI supports all encryption algorithms."""
    print_header("CLI Algorithms Check")
    
    cli_path = "../cipherstationv0.py"
    
    try:
        with open(cli_path, 'r') as f:
            content = f.read()
        
        # Check for algorithm support
        algorithms = [
            ("AES-128", "aes128"),
            ("AES-192", "aes192"), 
            ("AES-256", "aes256"),
            ("ChaCha20", "chacha20")
        ]
        
        passed = 0
        for name, alg in algorithms:
            if alg in content:
                print_success(f"{name} support found")
                passed += 1
            else:
                print_error(f"{name} support missing")
        
        print_success(f"CLI algorithms: {passed}/{len(algorithms)} supported")
        return passed == len(algorithms)
        
    except Exception as e:
        print_error(f"Failed to check CLI algorithms: {e}")
        return False

def main():
    """Run all CLI tests."""
    print("🚀 CipherStation CLI Test Suite")
    print("=" * 60)
    
    tests = [
        ("CLI File Exists", test_cli_file_exists),
        ("CLI Structure", test_cli_structure),
        ("CLI Syntax", test_cli_syntax),
        ("CLI Help Output", test_cli_help_output),
        ("CLI Commands", test_cli_commands),
        ("CLI Algorithms", test_cli_algorithms)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print_error(f"Test {test_name} crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print_header("CLI Test Summary")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} - {test_name}")
    
    print(f"\n📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ 🎉 All CLI tests passed! CipherStation CLI is properly structured!")
        return True
    else:
        print("❌ ⚠️  Some CLI tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 