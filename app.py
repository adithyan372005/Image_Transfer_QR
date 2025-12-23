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
        logger.info(f"File uploaded: {file.filename} ({len(file_data)} bytes)")
        
        # Get expiry time from request
        expiry_minutes = int(request.form.get('expiry', 5))
        expiry_time = datetime.now() + timedelta(minutes=expiry_minutes)
        
        # Step 1: Generate ElGamal key pair
        elgamal = ElGamalCrypto()
        public_key, private_key = elgamal.generate_keypair()
        logger.info("ElGamal key pair generated")
        
        # Step 2: Compress file using Huffman coding
        huffman = HuffmanCompression()
        compressed_data = huffman.compress(file_data)
        logger.info("File compressed using Huffman")
        
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
            huffman_tree=base64.b64encode(huffman.get_tree()).decode()
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
            'expiry_time': expiry_time.strftime('%Y-%m-%d %H:%M:%S')
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
        
        # Prepare response based on file type
        file_name = transaction['file_name']
        file_ext = os.path.splitext(file_name)[1].lower()
        
        if file_ext == '.pdf':
            # For PDF, provide download
            response_data = {
                'success': True,
                'file_type': 'pdf',
                'file_name': file_name,
                'download_url': f'/download/{transaction_id}'
            }
            # Store decrypted data temporarily for download
            db_manager.store_temp_file(transaction_id, original_data)
        else:
            # For images, return base64 data for display
            file_data_b64 = base64.b64encode(original_data).decode()
            response_data = {
                'success': True,
                'file_type': 'image',
                'file_name': file_name,
                'file_data': file_data_b64
            }
        
        # Delete transaction data (one-time access)
        db_manager.delete_transaction(transaction_id)
        logger.info("Decryption successful - transaction data deleted")
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return jsonify({'error': 'Decryption failed'}), 500

@app.route('/download/<transaction_id>')
def download_file(transaction_id):
    """Download decrypted PDF file"""
    try:
        file_data = db_manager.get_temp_file(transaction_id)
        if not file_data:
            return "File not found or expired", 404
        
        # Clean up temp file
        db_manager.delete_temp_file(transaction_id)
        
        # Return file for download
        return send_file(
            BytesIO(file_data['data']),
            as_attachment=True,
            download_name=file_data['name'],
            mimetype='application/pdf'
        )
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return "Download failed", 500

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