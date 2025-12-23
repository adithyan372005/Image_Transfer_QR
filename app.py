#!/usr/bin/env python3
"""
CNS Project: Secure Image & PDF Transfer
Using Huffman Compression, AES, ElGamal, QR Code (URL-based), PIN, and Database
"""

import os
import uuid
import hashlib
import sqlite3
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_file
import qrcode
from io import BytesIO
import logging

# Import our custom modules
from crypto_utils import HuffmanCompression, AESCrypto, ElGamalCrypto
from database import DatabaseManager

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize database
db_manager = DatabaseManager()

@app.route('/')
def home():
    """Home page with send/receive options"""
    return render_template('home.html')

@app.route('/send')
def send_page():
    """Send file page"""
    return render_template('send.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and encryption process"""
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in allowed_extensions:
            return jsonify({'error': 'Only images (JPG, PNG, GIF) and PDF files are allowed'}), 400
        
        # Read file data
        file_data = file.read()
        original_size = len(file_data)
        logger.info(f"File uploaded: {file.filename} ({original_size} bytes)")
        
        # Get expiry time and intended receiver name from request
        expiry_minutes = int(request.form.get('expiry', 5))
        expiry_time = datetime.now() + timedelta(minutes=expiry_minutes)
        intended_receiver_name = request.form.get('intended_receiver_name', '').strip()
        
        # Step 1: Generate ElGamal key pair
        elgamal = ElGamalCrypto()
        public_key, private_key = elgamal.generate_keypair()
        logger.info("ElGamal key pair generated")
        
        # Step 2: Compress file using Huffman coding
        huffman = HuffmanCompression()
        compressed_data = huffman.compress(file_data)
        compressed_size = len(compressed_data)
        
        # Calculate compression ratio
        if original_size > 0:
            compression_ratio = ((original_size - compressed_size) / original_size) * 100
        else:
            compression_ratio = 0.0
        
        logger.info(f"File compressed using Huffman")
        logger.info(f"Original size: {original_size} bytes")
        logger.info(f"Compressed size: {compressed_size} bytes") 
        logger.info(f"Compression ratio: {compression_ratio:.2f}%")
        
        # Step 3: Generate random AES key
        aes_crypto = AESCrypto()
        aes_key = aes_crypto.generate_key()
        logger.info("AES key generated")
        
        # Step 4: Encrypt compressed file using AES
        encrypted_file = aes_crypto.encrypt(compressed_data, aes_key)
        logger.info("File encrypted using AES")
        
        # Step 5: Encrypt AES key using ElGamal public key
        encrypted_aes_key = elgamal.encrypt(aes_key, public_key)
        logger.info("AES key encrypted using ElGamal")
        
        # Step 6: Generate SHA-256 hash of encrypted file
        hash_value = hashlib.sha256(encrypted_file).hexdigest()
        logger.info("SHA-256 hash generated")
        
        # Step 7: Generate alphanumeric PIN
        pin = generate_pin()
        hashed_pin = hashlib.sha256(pin.encode()).hexdigest()
        logger.info(f"PIN generated: {pin}")
        
        # Step 8: Generate transaction ID
        transaction_id = str(uuid.uuid4())
        
        # Step 9: Store in database
        db_manager.store_transaction(
            transaction_id=transaction_id,
            encrypted_file=base64.b64encode(encrypted_file).decode(),
            encrypted_aes_key=base64.b64encode(encrypted_aes_key).decode(),
            private_key=base64.b64encode(private_key).decode(),
            hash_value=hash_value,
            hashed_pin=hashed_pin,
            expiry_time=expiry_time,
            file_name=file.filename,
            huffman_tree=base64.b64encode(huffman.get_tree()).decode(),
            original_size=original_size,
            compressed_size=compressed_size,
            compression_ratio=compression_ratio,
            intended_receiver_name=intended_receiver_name
        )
        logger.info(f"Transaction stored with ID: {transaction_id}")
        
        # Step 10: Generate QR code with URL
        qr_url = f"{request.url_root}receive?tid={transaction_id}"
        qr_code_data = generate_qr_code(qr_url)
        logger.info("QR URL generated")
        
        return jsonify({
            'success': True,
            'transaction_id': transaction_id,
            'pin': pin,
            'qr_code': qr_code_data,
            'expiry_time': expiry_time.strftime('%Y-%m-%d %H:%M:%S'),
            'original_size': original_size,
            'compressed_size': compressed_size,
            'compression_ratio': compression_ratio
        })
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/receive')
def receive_page():
    """Receive file page"""
    transaction_id = request.args.get('tid', '')
    return render_template('receive.html', transaction_id=transaction_id)

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    """Handle file decryption process"""
    try:
        transaction_id = request.json.get('transaction_id')
        pin = request.json.get('pin')
        receiver_name = request.json.get('receiver_name', '')
        user_agent = request.headers.get('User-Agent', '')
        
        if not transaction_id or not pin:
            return jsonify({'error': 'Transaction ID and PIN are required'}), 400
        
        # Get transaction from database
        transaction = db_manager.get_transaction(transaction_id)
        if not transaction:
            return jsonify({'error': 'Invalid transaction ID'}), 404
        
        # Check if transaction is expired
        if datetime.now() > datetime.fromisoformat(transaction['expiry_time']):
            db_manager.delete_transaction(transaction_id)
            logger.info("Expired link accessed")
            return jsonify({'error': 'Link has expired'}), 410
        
        # Check PIN attempts
        if transaction['attempt_count'] >= 3:
            db_manager.delete_transaction(transaction_id)
            logger.info("Locked access - too many attempts")
            return jsonify({'error': 'Access locked due to too many invalid attempts'}), 423
        
        # Verify intended receiver name (before PIN verification for security)
        intended_receiver = transaction.get('intended_receiver_name', '').strip()
        if intended_receiver and receiver_name.strip() != intended_receiver:
            # Increment attempt count for name mismatch
            db_manager.increment_attempts(transaction_id)
            new_count = transaction['attempt_count'] + 1
            logger.info(f"Receiver name mismatch: expected '{intended_receiver}', got '{receiver_name}' - attempt {new_count}/3")
            return jsonify({
                'error': f'Receiver name does not match ({new_count}/3)',
                'attempts_remaining': 3 - new_count
            }), 401
        
        # Verify PIN
        hashed_pin = hashlib.sha256(pin.encode()).hexdigest()
        if hashed_pin != transaction['hashed_pin']:
            # Increment attempt count
            new_count = transaction['attempt_count'] + 1
            db_manager.increment_attempts(transaction_id)
            logger.info(f"Wrong PIN attempt {new_count}/3")
            return jsonify({
                'error': f'Invalid PIN ({new_count}/3)',
                'attempts_remaining': 3 - new_count
            }), 401
        
        logger.info("PIN verification successful")
        
        # Decrypt AES key using ElGamal private key
        elgamal = ElGamalCrypto()
        private_key = base64.b64decode(transaction['private_key'].encode())
        encrypted_aes_key = base64.b64decode(transaction['encrypted_aes_key'].encode())
        aes_key = elgamal.decrypt(encrypted_aes_key, private_key)
        logger.info("AES key decrypted using ElGamal")
        
        # Decrypt file using AES
        aes_crypto = AESCrypto()
        encrypted_file = base64.b64decode(transaction['encrypted_file'].encode())
        
        # Verify hash before decryption
        if hashlib.sha256(encrypted_file).hexdigest() != transaction['hash_value']:
            db_manager.delete_transaction(transaction_id)
            logger.error("Hash verification failed")
            return jsonify({'error': 'Data tampered – access denied'}), 400
        
        logger.info("Hash verification successful")
        
        compressed_data = aes_crypto.decrypt(encrypted_file, aes_key)
        logger.info("File decrypted using AES")
        
        # Decompress using Huffman
        huffman = HuffmanCompression()
        huffman_tree = base64.b64decode(transaction['huffman_tree'].encode())
        huffman.set_tree(huffman_tree)
        original_data = huffman.decompress(compressed_data)
        logger.info("File decompressed using Huffman")
        
        # Update transaction status before preparing response
        db_manager.update_transaction_status(transaction_id, 'ACCESSED', receiver_name, user_agent)
        
        # Enhanced logging for receiver access
        logger.info("Decryption successful")
        if receiver_name:
            logger.info(f"File accessed by: {receiver_name}")
        logger.info(f"Access time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if user_agent:
            logger.info(f"User agent: {user_agent}")
        
        # Prepare response based on file type
        file_name = transaction['file_name']
        file_ext = os.path.splitext(file_name)[1].lower()
        
        if file_ext == '.pdf':
            # For PDF, provide download
            response_data = {
                'success': True,
                'file_type': 'pdf',
                'file_name': file_name,
                'download_url': f'/download/{transaction_id}',
                'receiver_name': receiver_name,
                'access_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            # Store decrypted data temporarily for download
            db_manager.store_temp_file(transaction_id, original_data, file_name)
        else:
            # For images, return base64 data for display and download option
            file_data_b64 = base64.b64encode(original_data).decode()
            response_data = {
                'success': True,
                'file_type': 'image',
                'file_name': file_name,
                'file_data': file_data_b64,
                'download_url': f'/download/{transaction_id}',
                'receiver_name': receiver_name,
                'access_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            # Store decrypted data temporarily for download
            db_manager.store_temp_file(transaction_id, original_data, file_name)
        
        # Note: Transaction will be deleted after download (one-time access)
        logger.info("File prepared for access - transaction marked as ACCESSED")
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return jsonify({'error': 'Decryption failed'}), 500

@app.route('/download/<transaction_id>')
def download_file(transaction_id):
    """Download decrypted file (one-time access)"""
    try:
        file_data = db_manager.get_temp_file(transaction_id)
        if not file_data:
            return "File not found or already downloaded", 404
        
        # Get file extension to determine MIME type
        file_name = file_data['name']
        file_ext = os.path.splitext(file_name)[1].lower()
        
        if file_ext == '.pdf':
            mimetype = 'application/pdf'
        elif file_ext in ['.jpg', '.jpeg']:
            mimetype = 'image/jpeg'
        elif file_ext == '.png':
            mimetype = 'image/png'
        elif file_ext == '.gif':
            mimetype = 'image/gif'
        else:
            mimetype = 'application/octet-stream'
        
        # Clean up temp file and delete transaction (one-time access)
        db_manager.delete_temp_file(transaction_id)
        db_manager.update_transaction_status(transaction_id, 'DOWNLOADED')
        db_manager.delete_transaction(transaction_id)
        
        logger.info(f"File downloaded: {file_name}")
        logger.info("One-time access completed - all data deleted")
        
        # Return file for download
        return send_file(
            BytesIO(file_data['data']),
            as_attachment=True,
            download_name=file_name,
            mimetype=mimetype
        )
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return "Download failed", 500

@app.route('/status/<transaction_id>')
def check_status(transaction_id):
    """Check transaction status for sender"""
    try:
        transaction = db_manager.get_transaction(transaction_id)
        if not transaction:
            return jsonify({'error': 'Transaction not found or expired'}), 404
        
        response_data = {
            'transaction_id': transaction_id,
            'status': transaction['status'],
            'file_name': transaction['file_name'],
            'created_at': transaction['created_at'],
            'expiry_time': transaction['expiry_time']
        }
        
        # Add access information if available
        if transaction['status'] in ['ACCESSED', 'DOWNLOADED']:
            response_data.update({
                'receiver_name': transaction['receiver_name'],
                'access_time': transaction['access_time'],
                'user_agent': transaction['user_agent']
            })
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Status check error: {str(e)}")
        return jsonify({'error': 'Status check failed'}), 500

def generate_pin():
    """Generate 6-digit alphanumeric PIN"""
    import random
    import string
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def generate_qr_code(data):
    """Generate QR code as base64 image"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

if __name__ == '__main__':
    # Initialize database
    db_manager.init_database()
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)