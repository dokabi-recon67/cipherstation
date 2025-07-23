#!/usr/bin/env python3
"""
Advanced CipherStation Web Application
AI-powered classical cipher encoding and cryptanalysis

Features:
- Advanced cipher cracking with AI confidence scoring
- Real-time analysis and progress tracking
- Multi-dimensional cryptanalysis
- Beautiful dark theme interface
- Comprehensive result ranking
"""

import signal
import atexit
from flask import Flask, render_template, request, jsonify, send_file, url_for, flash, redirect, abort
import os
import time
import json
from datetime import datetime
import threading
from queue import Queue
import sys
from typing import List
from functools import wraps
from collections import deque
import uuid

# Add the parent directory to the path to import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from classical_ciphers import (
    encode_text, decode_text, cryptanalyze_text,
    CaesarCipher, VigenereCipher, XORCipher, AtbashCipher, SubstitutionCipher, Cryptanalyzer, submit_cracked_sample, get_cipher_share_metadata,
    add_tags_to_entry, find_similar_ciphers, search_knowledge_graph
)

# Global variables for station management
station_messages = {}
next_ticket_id = 1001

# Import modern cryptography functions from cipherstationv0
try:
    from cipherstationv0 import (
        aes_gcm_encrypt, aes_gcm_decrypt, chacha_encrypt, chacha_decrypt,
        derive_key, generate_aes_key
    )
    MODERN_CRYPTO_AVAILABLE = True
except ImportError:
    MODERN_CRYPTO_AVAILABLE = False
    print("[yellow]Warning: Modern cryptography not available. Install cipherstationv0.py[/yellow]")

app = Flask(__name__)
app.secret_key = 'cipherstation_advanced_2024'

# --- CSRF Exemption for API Endpoints (dev/local only) ---
@app.before_request
def disable_csrf_for_api():
    if request.path.startswith('/api/'):
        setattr(request, '_disable_csrf', True)

# --- Simple In-Memory Rate Limiter ---
RATE_LIMITS = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 10    # max requests per window per IP per endpoint

def rate_limited(endpoint):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr or 'unknown'
            key = f"{endpoint}:{ip}"
            now = int(time.time())
            window = now // RATE_LIMIT_WINDOW
            if key not in RATE_LIMITS:
                RATE_LIMITS[key] = {}
            if window not in RATE_LIMITS[key]:
                RATE_LIMITS[key].clear()
                RATE_LIMITS[key][window] = 0
            RATE_LIMITS[key][window] += 1
            if RATE_LIMITS[key][window] > RATE_LIMIT_MAX:
                return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator

# --- Input Size Check ---
MAX_INPUT_SIZE = 10000  # characters

def check_input_size(text):
    if text and len(text) > MAX_INPUT_SIZE:
        abort(413, description='Input too large. Limit is 10,000 characters.')

# Global variables for advanced features
cracking_queue = Queue()
cracking_results = {}
cracking_progress = {}

# --- Interactive Cracking Session Management ---
interactive_sessions = {}

# --- Concurrency Limit and Queue for Heavy Endpoints ---
from threading import Lock
MAX_CONCURRENT_CRACKS = 3
MAX_QUEUE_LENGTH = 50
current_cracks = 0
crack_lock = Lock()
crack_queue = deque()

# Helper for concurrency control with queue
from contextlib import contextmanager
@contextmanager
def crack_slot_with_queue(request_id):
    global current_cracks
    acquired = False
    try:
        with crack_lock:
            # If already running, proceed
            if current_cracks < MAX_CONCURRENT_CRACKS and (not crack_queue or crack_queue[0] == request_id):
                current_cracks += 1
                if crack_queue and crack_queue[0] == request_id:
                    crack_queue.popleft()
                acquired = True
                yield 'ready', 0
                return
            # If queue is too long, reject
            if len(crack_queue) >= MAX_QUEUE_LENGTH:
                yield 'full', len(crack_queue)
                return
            # Otherwise, add to queue
            if request_id not in crack_queue:
                crack_queue.append(request_id)
            pos = list(crack_queue).index(request_id) + 1
            yield 'queued', pos
    finally:
        if acquired:
            with crack_lock:
                current_cracks -= 1

class AdvancedCracker:
    """Advanced cracking system for web interface"""
    
    def __init__(self):
        self.analyzer = Cryptanalyzer()
        self.caesar = CaesarCipher()
        self.vigenere = VigenereCipher()
        self.xor = XORCipher()
        self.atbash = AtbashCipher()
        self.substitution = SubstitutionCipher()
    
    def crack_with_progress(self, text: str, task_id: str, custom_words: List[str] = None):
        """Legacy method for backward compatibility"""
        self.crack_with_progress_full(text, task_id, custom_words, 300, False, 
                                     ['caesar', 'vigenere', 'xor', 'atbash', 'substitution'],
                                     None, 100, 5000)

    def crack_with_progress_full(self, text: str, task_id: str, custom_words: List[str] = None, 
                                max_time: int = 300, test_mode: bool = False, 
                                enabled_ciphers: List[str] = None,
                                vigenere_max_iterations: int = None, 
                                vigenere_max_key_length: int = None,
                                substitution_max_restarts: int = 100,
                                substitution_max_iterations: int = 5000):
        """Full-capability cracking with all CLI options and real-time progress"""
        try:
            start_time = time.time()
            
            # Initialize progress
            cracking_progress[task_id] = {
                'status': 'starting',
                'progress': 0,
                'message': 'Initializing advanced analysis...',
                'results': [],
                'crack_time': None,
                'total_attempts': 0
            }
            
            if enabled_ciphers is None:
                enabled_ciphers = ['caesar', 'vigenere', 'xor', 'atbash', 'substitution']
            
            # Import CLI cracker functions
            from cli_cracker import (
                crack_caesar_advanced, crack_vigenere_advanced, crack_xor_advanced,
                crack_atbash_advanced, crack_substitution_advanced
            )
            
            all_results = []
            total_attempts = 0
            current_progress = 0
            
            def update_progress(step: str, progress: int, message: str):
                cracking_progress[task_id].update({
                    'status': step,
                    'progress': progress,
                    'message': message
                })
            
            # Step 1: Initial Analysis
            update_progress('analyzing', 5, 'Performing initial analysis...')
            
            def analysis_progress(msg):
                cracking_progress[task_id].update({
                    'status': 'analyzing',
                    'progress': 5,
                    'message': msg
                })
            
            analysis = cryptanalyze_text(text, progress=True, progress_callback=analysis_progress, custom_words=custom_words)
            
            # Step 2: Caesar Cracking (if enabled)
            if 'caesar' in enabled_ciphers:
                update_progress('cracking_caesar', 15, 'Attempting Caesar cipher cracking...')
                
                def caesar_progress(msg):
                    cracking_progress[task_id].update({
                        'status': 'cracking_caesar',
                        'progress': 15,
                        'message': f'Caesar: {msg}'
                    })
                
                caesar_results = crack_caesar_advanced(text, progress_callback=caesar_progress, verbose=False)
                all_results.extend(caesar_results)
                total_attempts += 26
            
            # Step 3: Vigenère Cracking (if enabled)
            if 'vigenere' in enabled_ciphers:
                update_progress('cracking_vigenere', 35, 'Attempting Vigenère cipher cracking...')
                
                def vigenere_progress(msg):
                    cracking_progress[task_id].update({
                        'status': 'cracking_vigenere',
                        'progress': 35,
                        'message': f'Vigenère: {msg}'
                    })
                
                vigenere_results = crack_vigenere_advanced(
                    text, 
                    progress_callback=vigenere_progress, 
                    custom_words=custom_words,
                    max_iterations=vigenere_max_iterations,
                    max_key_length=vigenere_max_key_length,
                    verbose=False
                )
                all_results.extend(vigenere_results)
                total_attempts += len(custom_words) if custom_words else 500
            
            # Step 4: XOR Cracking (if enabled)
            if 'xor' in enabled_ciphers:
                update_progress('cracking_xor', 55, 'Attempting XOR cipher cracking...')
                
                def xor_progress(msg):
                    cracking_progress[task_id].update({
                        'status': 'cracking_xor',
                        'progress': 55,
                        'message': f'XOR: {msg}'
                    })
                
                xor_results = crack_xor_advanced(text, progress_callback=xor_progress, verbose=False)
                all_results.extend(xor_results)
                total_attempts += 256
            
            # Step 5: Atbash Cracking (if enabled)
            if 'atbash' in enabled_ciphers:
                update_progress('cracking_atbash', 75, 'Attempting Atbash cipher cracking...')
                
                def atbash_progress(msg):
                    cracking_progress[task_id].update({
                        'status': 'cracking_atbash',
                        'progress': 75,
                        'message': f'Atbash: {msg}'
                    })
                
                atbash_results = crack_atbash_advanced(text, progress_callback=atbash_progress, verbose=False)
                all_results.extend(atbash_results)
                total_attempts += 1
            
            # Step 6: Substitution Cracking (if enabled)
            if 'substitution' in enabled_ciphers:
                update_progress('cracking_substitution', 85, 'Attempting Substitution cipher cracking...')
                
                def substitution_progress(msg):
                    cracking_progress[task_id].update({
                        'status': 'cracking_substitution',
                        'progress': 85,
                        'message': f'Substitution: {msg}'
                    })
                
                substitution_results = crack_substitution_advanced(
                    text, 
                    progress_callback=substitution_progress,
                    max_restarts=substitution_max_restarts,
                    max_iterations=substitution_max_iterations,
                    prompt_user=False,
                    verbose=False
                )
                all_results.extend(substitution_results)
                total_attempts += 100
            
            # Step 7: Finalize Results
            update_progress('finalizing', 95, 'Finalizing results...')
            
            # Sort by confidence
            all_results.sort(key=lambda x: x[3], reverse=True)
            
            # Convert to web format
            web_results = []
            for cipher_type, key, decoded_text, confidence in all_results[:10]:
                web_results.append({
                    'cipher_type': cipher_type,
                    'key': str(key),
                    'decoded_text': decoded_text,
                    'confidence': confidence,
                    'algorithm': 'Advanced CLI Algorithm'
                })
            
            total_time = time.time() - start_time
            
            # Update final progress
            cracking_progress[task_id].update({
                'status': 'completed',
                'progress': 100,
                'message': 'Analysis completed!',
                'results': web_results,
                'analysis': analysis,
                'custom_words_used': len(custom_words) if custom_words else 0,
                'crack_time': total_time,
                'total_attempts': total_attempts,
                'detected_ciphers': analysis.get('detected_ciphers', []) if analysis else []
            })
            
            # Store final results
            cracking_results[task_id] = {
                'original_text': text,
                'analysis': analysis,
                'results': web_results,
                'timestamp': datetime.now().isoformat(),
                'custom_words_used': len(custom_words) if custom_words else 0,
                'crack_time': total_time,
                'total_attempts': total_attempts,
                'detected_ciphers': analysis.get('detected_ciphers', []) if analysis else []
            }
            
        except Exception as e:
            cracking_progress[task_id].update({
                'status': 'error',
                'progress': 0,
                'message': f'Error: {str(e)}',
                'results': [],
                'crack_time': None
            })

# Initialize advanced cracker
advanced_cracker = AdvancedCracker()

# --- Background Cleanup Thread for 24hr Message Retention ---
def cleanup_station_messages():
    while True:
        now = time.time()
        cutoff = now - 24*3600  # 24 hours ago
        removed = 0
        to_delete = []
        for ticket_id, message_data in list(station_messages.items()):
            ts = message_data.get('timestamp')
            if ts:
                # Support both float and string timestamps
                try:
                    ts_val = float(ts)
                except Exception:
                    try:
                        ts_val = time.mktime(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").timetuple())
                    except Exception:
                        continue
                if ts_val < cutoff:
                    to_delete.append(ticket_id)
        for ticket_id in to_delete:
            del station_messages[ticket_id]
            removed += 1
        if removed > 0:
            print(f"[CLEANUP] Removed {removed} expired messages from station at {datetime.now().isoformat()}")
        else:
            print(f"[CLEANUP] No expired messages found at {datetime.now().isoformat()}")
        time.sleep(3600)  # Run every hour

# Start the cleanup thread when the app starts
cleanup_thread = threading.Thread(target=cleanup_station_messages, daemon=True)
cleanup_thread.start()

@app.route('/')
def index():
    """Homepage with advanced features"""
    return render_template('index.html')

@app.route('/classical')
def classical():
    """Classical cipher page with advanced cracking"""
    return render_template('classical.html')

@app.route('/station')
def station():
    """Cipher station with advanced analysis"""
    ticket = request.args.get('ticket')
    
    # Convert station_messages dict to list format expected by template
    messages_list = []
    for ticket_id, message_data in station_messages.items():
        message_obj = message_data.copy()
        message_obj['ticket'] = ticket_id
        messages_list.append(message_obj)
    
    # Sort by timestamp (newest first)
    messages_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return render_template('station.html', station_messages=messages_list, current_ticket=ticket)

@app.route('/api/station/messages')
def api_station_messages():
    """Get all station messages"""
    return jsonify({
        'success': True,
        'messages': station_messages
    })

@app.route('/api/station/ticket/<int:ticket_id>')
def api_station_ticket(ticket_id):
    """Get specific ticket details"""
    if ticket_id in station_messages:
        return jsonify({
            'success': True,
            'ticket': ticket_id,
            'message': station_messages[ticket_id]
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Ticket not found'
        }), 404

@app.route('/documentation')
def documentation():
    """Documentation with advanced features"""
    return render_template('documentation.html')

@app.route('/download_cli')
def download_cli():
    """CLI download page"""
    return render_template('download_cli.html')

@app.route('/help')
def help():
    """Help page"""
    return render_template('help.html')

@app.route('/selftest')
def selftest():
    """Self-test page with real cryptographic checks"""
    result = {
        'total': 0,
        'passed': 0,
        'failed': 0,
        'results': []
    }
    try:
        # Test cases: (name, function)
        tests = []
        # 1. Caesar encode/decode
        tests.append(('Caesar Encode/Decode', lambda: encode_text('HELLO', 'caesar', shift=3) == 'KHOOR' and decode_text('KHOOR', 'caesar', shift=3) == 'HELLO'))
        # 2. Vigenere encode/decode
        tests.append(('Vigenere Encode/Decode', lambda: encode_text('HELLO', 'vigenere', key='KEY') == 'RIJVS' and decode_text('RIJVS', 'vigenere', key='KEY') == 'HELLO'))
        # 3. XOR encode/decode
        tests.append(('XOR Encode/Decode', lambda: decode_text(encode_text('HELLO', 'xor', key='A'), 'xor', key='A') == 'HELLO'))
        # 4. Atbash encode/decode
        tests.append(('Atbash Encode/Decode', lambda: encode_text('HELLO', 'atbash') == 'SVOOL' and decode_text('SVOOL', 'atbash') == 'HELLO'))
        # 5. Substitution encode/decode
        sub_key = 'QWERTYUIOPASDFGHJKLZXCVBNM'
        tests.append(('Substitution Encode/Decode', lambda: decode_text(encode_text('HELLO', 'substitution', key=sub_key), 'substitution', key=sub_key) == 'HELLO'))
        # 6. Cryptanalyze Caesar
        tests.append(('Cryptanalyze Caesar', lambda: any('HELLO' in r['decoded'] for r in cryptanalyze_text('KHOOR', test_mode=True)['best_results'][:3])))
        # 7. Cryptanalyze Vigenere
        tests.append(('Cryptanalyze Vigenere', lambda: any('HELLO' in r['decoded'] for r in cryptanalyze_text('RIJVS', test_mode=True)['best_results'][:3])))
        # 8. API health (analyze)
        import requests
        api_resp = requests.post('http://localhost:5001/api/analyze', json={'text': 'KHOOR', 'test_mode': True}, timeout=3)
        tests.append(('API /api/analyze', lambda: api_resp.status_code == 200 and api_resp.json().get('success')))
        # 9. CipherShare API health
        api_resp2 = requests.get('http://localhost:5001/api/ciphershare/search?tag=caesar', timeout=3)
        tests.append(('API /api/ciphershare/search', lambda: api_resp2.status_code == 200 and api_resp2.json().get('success')))
        # Run all tests
        for name, func in tests:
            result['total'] += 1
            try:
                if func():
                    result['passed'] += 1
                    result['results'].append({'name': name, 'status': 'PASS'})
                else:
                    result['failed'] += 1
                    result['results'].append({'name': name, 'status': 'FAIL', 'error': 'Test returned False'})
            except Exception as e:
                result['failed'] += 1
                result['results'].append({'name': name, 'status': 'FAIL', 'error': str(e)})
        return render_template('selftest.html', result=result)
    except Exception as e:
        return render_template('selftest.html', error=str(e))

@app.route('/api/encode', methods=['POST'])
@rate_limited('api_encode')
def api_encode():
    """Advanced encoding API"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        cipher_type = data.get('cipher', 'caesar')  # Accept both 'cipher' and 'cipher_type'
        key = data.get('key', '')
        
        check_input_size(text)

        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        # Encode the text
        encoded = encode_text(text, cipher_type, key=key)
        
        return jsonify({
            'success': True,
            'result': encoded,
            'cipher_type': cipher_type,
            'key': key
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decode', methods=['POST'])
@rate_limited('api_decode')
def api_decode():
    """Advanced decoding API"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        cipher_type = data.get('cipher', 'caesar')  # Accept both 'cipher' and 'cipher_type'
        key = data.get('key', '')
        
        check_input_size(text)

        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        # Decode the text
        decoded = decode_text(text, cipher_type, key=key)
        
        return jsonify({
            'success': True,
            'result': decoded,
            'cipher_type': cipher_type,
            'key': key
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/crack', methods=['POST'])
@rate_limited('api_crack')
def api_crack():
    """Advanced cracking API with real-time progress and full CLI capabilities"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        custom_words_str = data.get('custom_words', '')
        custom_words = [w.strip() for w in custom_words_str.split(',') if w.strip()] if custom_words_str else None
        
        # Advanced options from CLI cracker
        max_time = data.get('max_time', 300)
        test_mode = data.get('test_mode', False)
        timeout = data.get('timeout', 300)
        
        # Cipher-specific options
        vigenere_max_iterations = data.get('vigenere_max_iterations', None)
        vigenere_max_key_length = data.get('vigenere_max_key_length', None)
        substitution_max_restarts = data.get('substitution_max_restarts', 100)
        substitution_max_iterations = data.get('substitution_max_iterations', 5000)
        
        # Cipher selection
        enabled_ciphers = data.get('enabled_ciphers', ['caesar', 'vigenere', 'xor', 'atbash', 'substitution'])
        
        check_input_size(text)

        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        # Generate unique task ID
        task_id = f"crack_{int(time.time() * 1000)}"
        
        with crack_slot_with_queue(task_id) as (status, info):
            if status == 'queued':
                return jsonify({
                    'queued': True,
                    'position': info,
                    'message': f'You are in queue. Position: {info}. Estimated wait: {info * 10}s'
                })
            elif status == 'full':
                return jsonify({'error': 'Queue full, try again later.'}), 503

        # Start cracking in background thread with full options
        thread = threading.Thread(
            target=advanced_cracker.crack_with_progress_full,
            args=(text, task_id, custom_words, max_time, test_mode, enabled_ciphers, 
                  vigenere_max_iterations, vigenere_max_key_length, substitution_max_restarts, substitution_max_iterations)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Cracking started',
            'start_time': time.time()
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/crack/progress/<task_id>')
def api_crack_progress(task_id):
    """Get cracking progress"""
    try:
        if task_id not in cracking_progress:
            return jsonify({'error': 'Task not found'}), 404
        
        progress = cracking_progress[task_id]
        
        return jsonify({
            'success': True,
            'progress': progress
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/crack/results/<task_id>')
def api_crack_results(task_id):
    """Get final cracking results"""
    try:
        if task_id not in cracking_results:
            return jsonify({'error': 'Results not found'}), 404
        
        results = cracking_results[task_id]
        
        return jsonify({
            'success': True,
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
@rate_limited('api_analyze')
def api_analyze():
    """Advanced text analysis API"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        test_mode = data.get('test_mode', False)
        timeout = data.get('timeout', 10)
        check_input_size(text)
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        request_id = str(uuid.uuid4())
        with crack_slot_with_queue(request_id) as (status, info):
            if status == 'queued':
                return jsonify({
                    'queued': True,
                    'position': info,
                    'message': f'You are in queue. Position: {info}. Estimated wait: {info * 10}s'
                })
            elif status == 'full':
                return jsonify({'error': 'Queue full, try again later.'}), 503

        # Perform comprehensive analysis with progress
        progress_log = []
        def progress_callback(msg):
            progress_log.append(msg)
        # Extract custom words from request if provided
        custom_words = data.get('custom_words', None)
        if custom_words and isinstance(custom_words, str):
            custom_words = [word.strip() for word in custom_words.split(',') if word.strip()]
        
        analysis = cryptanalyze_text(text, progress=True, test_mode=test_mode, custom_words=custom_words)
        return jsonify({
            'success': True,
            'analysis': analysis,
            'progress_log': progress_log,
            'analysis_time': analysis.get('analysis_time', None)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/benchmark', methods=['POST'])
@rate_limited('api_benchmark')
def api_benchmark():
    """Run benchmark tests"""
    try:
        test_cases = [
            ("Wklvlvdwhvwphvvdjh", "Caesar", 3),
            ("KHOORZRUOG", "Caesar", 3),
            ("SVOOLDLIOW", "Atbash", 0),
            ("TLLWYVHG", "Atbash", 0),
        ]
        
        results = []
        total_time = 0
        
        for i, (text, expected_type, expected_key) in enumerate(test_cases):
            start_time = time.time()
            
            # Perform cracking
            crack_result = cryptanalyze_text(text)
            
            test_time = time.time() - start_time
            total_time += test_time
            
            # Check if successful
            success = False
            if crack_result['best_results']:
                # Check top 10 results for a match
                for i, best in enumerate(crack_result['best_results'][:10]):
                    if best['cipher'].lower() == expected_type.lower():
                        success = True
                        break
            
            results.append({
                'test': i + 1,
                'text': text,
                'expected_type': expected_type,
                'expected_key': expected_key,
                'success': success,
                'time': test_time,
                'confidence': crack_result['best_results'][0]['confidence'] if crack_result['best_results'] else 0
            })
        
        success_rate = sum(1 for r in results if r['success']) / len(results)
        
        return jsonify({
            'success': True,
            'results': results,
            'total_time': total_time,
            'success_rate': success_rate,
            'average_time': total_time / len(results)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/encrypt-message', methods=['POST'])
@rate_limited('encrypt_message')
def encrypt_message():
    """Encrypt message endpoint for frontend"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        password = data.get('password', '')
        algorithm = data.get('algorithm', 'aes256')
        send_to_station = data.get('send_to_station', False)
        
        check_input_size(text)

        if not text or not password:
            return jsonify({'success': False, 'error': 'Text and password are required'}), 400
        
        # Convert text to bytes
        text_bytes = text.encode('utf-8')
        
        # Use modern cryptography if available
        if MODERN_CRYPTO_AVAILABLE:
            # Derive key from password using Argon2id
            key, salt = derive_key(password, None, length=32)
            
            if algorithm in ['aes128', 'aes192', 'aes256']:
                # Determine key size based on algorithm
                if algorithm == 'aes128':
                    key = key[:16]  # 16 bytes for AES-128
                elif algorithm == 'aes192':
                    key = key[:24]  # 24 bytes for AES-192
                else:  # aes256
                    key = key[:32]  # 32 bytes for AES-256
                
                # Encrypt with AES-GCM
                env = aes_gcm_encrypt(key, text_bytes, desc=f"Web interface encryption using {algorithm.upper()}")
                
            elif algorithm == 'chacha20':
                # ChaCha20-Poly1305 requires 32-byte key
                if len(key) != 32:
                    key = key[:32]
                
                # Encrypt with ChaCha20-Poly1305
                env = chacha_encrypt(key, text_bytes, desc="Web interface encryption using ChaCha20-Poly1305")
            
            else:
                return jsonify({'success': False, 'error': f'Unsupported algorithm: {algorithm}'}), 400
            
            # Return the encrypted envelope as JSON string
            encrypted_json = json.dumps(env, indent=2)
            
            response_data = {
                'success': True,
                'encrypted': encrypted_json,
                'algorithm': algorithm,
                'salt': salt.hex() if salt else None
            }
            
            # Handle station functionality
            if send_to_station:
                global next_ticket_id
                ticket_id = next_ticket_id
                next_ticket_id += 1
                
                # Store in station
                station_messages[ticket_id] = {
                    'encrypted': encrypted_json,
                    'algorithm': algorithm,
                    'salt': salt.hex() if salt else None,
                    'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    'status': 'pending'
                }
                
                response_data['ticket_id'] = ticket_id
            
            return jsonify(response_data)
        
        else:
            # Fallback to classical ciphers if modern crypto not available
            if algorithm == 'caesar':
                shift = len(password) % 26
                encrypted = encode_text(text, 'caesar', shift=shift)
            elif algorithm == 'vigenere':
                encrypted = encode_text(text, 'vigenere', key=password)
            elif algorithm == 'atbash':
                encrypted = encode_text(text, 'atbash')
            else:
                return jsonify({'success': False, 'error': f'Unsupported algorithm: {algorithm}'}), 400
            
            return jsonify({
                'success': True,
                'encrypted': encrypted,
                'algorithm': algorithm
            })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/decrypt-message', methods=['POST'])
@rate_limited('decrypt_message')
def decrypt_message():
    """Decrypt message endpoint for frontend"""
    try:
        data = request.get_json()
        encrypted_text = data.get('encrypted_text', '')
        password = data.get('password', '')
        algorithm = data.get('algorithm', 'aes256')
        salt_hex = data.get('salt', None)  # Get salt from request
        
        check_input_size(encrypted_text)

        if not encrypted_text or not password:
            return jsonify({'success': False, 'error': 'Encrypted text and password are required', 'decrypted': ''}), 400
        
        # Use modern cryptography if available
        if MODERN_CRYPTO_AVAILABLE:
            try:
                # Try to parse as JSON envelope first (modern crypto)
                env = json.loads(encrypted_text)
                
                # Convert salt from hex if provided
                salt = None
                if salt_hex:
                    try:
                        salt = bytes.fromhex(salt_hex)
                    except ValueError:
                        return jsonify({'success': False, 'error': 'Invalid salt format', 'decrypted': ''}), 400
                
                # Derive key from password using Argon2id with the same salt
                key, _ = derive_key(password, salt, length=32)
                
                # Determine algorithm from envelope
                env_alg = env.get('alg', '').upper()
                
                if 'AES' in env_alg and 'GCM' in env_alg:
                    # Determine key size based on algorithm
                    if algorithm == 'aes128':
                        key = key[:16]  # 16 bytes for AES-128
                    elif algorithm == 'aes192':
                        key = key[:24]  # 24 bytes for AES-192
                    else:  # aes256
                        key = key[:32]  # 32 bytes for AES-256
                    
                    # Decrypt with AES-GCM
                    decrypted_bytes = aes_gcm_decrypt(key, env)
                    
                elif env_alg == 'CHACHA20-POLY1305':
                    # ChaCha20-Poly1305 requires 32-byte key
                    if len(key) != 32:
                        key = key[:32]
                    
                    # Decrypt with ChaCha20-Poly1305
                    decrypted_bytes = chacha_decrypt(key, env)
                
                else:
                    return jsonify({'success': False, 'error': f'Unsupported envelope algorithm: {env_alg}', 'decrypted': ''}), 400
                
                # Convert bytes back to string
                decrypted = decrypted_bytes.decode('utf-8')
                
                return jsonify({
                    'success': True,
                    'decrypted': decrypted,
                    'algorithm': algorithm
                })
                
            except json.JSONDecodeError as e:
                # If not JSON, try classical ciphers as fallback
                if algorithm == 'caesar':
                    shift = len(password) % 26
                    decrypted = decode_text(encrypted_text, 'caesar', shift=shift)
                elif algorithm == 'vigenere':
                    decrypted = decode_text(encrypted_text, 'vigenere', key=password)
                elif algorithm == 'atbash':
                    decrypted = decode_text(encrypted_text, 'atbash')
                else:
                    return jsonify({'success': False, 'error': f'Unsupported algorithm: {algorithm}', 'decrypted': ''}), 400
                
                return jsonify({
                    'success': True,
                    'decrypted': decrypted,
                    'algorithm': algorithm
                })
            except Exception as e:
                return jsonify({'success': False, 'error': f'Decryption failed: {str(e)}', 'decrypted': ''}), 500
        
        else:
            # Fallback to classical ciphers if modern crypto not available
            if algorithm == 'caesar':
                shift = len(password) % 26
                decrypted = decode_text(encrypted_text, 'caesar', shift=shift)
            elif algorithm == 'vigenere':
                decrypted = decode_text(encrypted_text, 'vigenere', key=password)
            elif algorithm == 'atbash':
                decrypted = decode_text(encrypted_text, 'atbash')
            else:
                return jsonify({'success': False, 'error': f'Unsupported algorithm: {algorithm}', 'decrypted': ''}), 400
            
            return jsonify({
                'success': True,
                'decrypted': decrypted,
                'algorithm': algorithm
            })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'decrypted': ''}), 500

@app.route('/download/cli')
def download_cli_file():
    """Download CLI tool"""
    try:
        cli_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cli_cracker.py')
        return send_file(cli_path, as_attachment=True, download_name='cipher_cracker.py')
    except Exception as e:
        flash(f'Error downloading CLI: {str(e)}', 'error')
        return redirect(url_for('download_cli'))

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    # Check if the request is for an API endpoint
    if request.path.startswith('/api/') or request.path.startswith('/encrypt-message') or request.path.startswith('/decrypt-message'):
        return jsonify({'error': 'Endpoint not found', 'path': request.path}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    # Check if the request is for an API endpoint
    if request.path.startswith('/api/') or request.path.startswith('/encrypt-message') or request.path.startswith('/decrypt-message'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

# --- Cleanup Functions ---
def cleanup_resources():
    """Cleanup function to prevent resource leaks"""
    try:
        import gc
        gc.collect()
        
        # Clear any remaining threads
        for thread in threading.enumerate():
            if thread != threading.main_thread():
                try:
                    thread.join(timeout=1.0)
                except Exception:
                    pass
        
        # Clear queues
        while not cracking_queue.empty():
            try:
                cracking_queue.get_nowait()
            except Exception:
                break
                
        print("🧹 Cleanup completed")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    print(f"\n🛑 Received signal {signum}, shutting down gracefully...")
    cleanup_resources()
    sys.exit(0)

# Register cleanup functions
atexit.register(cleanup_resources)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == '__main__':
    print("🚀 Starting Advanced CipherStation...")
    print("🔐 AI-powered cryptanalysis system")
    print("🌐 Web interface: http://localhost:5001")
    print("📱 CLI tool: python cli_cracker.py --help")
    print("=" * 50)
    
    try:
        app.run(host='0.0.0.0', port=5001, debug=True)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        cleanup_resources()
    except Exception as e:
        print(f"❌ Server error: {e}")
        cleanup_resources()
        sys.exit(1) 