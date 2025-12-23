# CNS Project: Secure Image & PDF Transfer

A complete web application for secure file transfer using advanced cryptographic techniques including Huffman Compression, AES encryption, ElGamal cryptography, QR codes, and PIN-based access control.

## 🔐 Security Features

- **Huffman Compression**: Efficient file compression before encryption
- **AES-256 Encryption**: Military-grade symmetric encryption for files
- **ElGamal Cryptography**: Asymmetric encryption for secure key exchange
- **QR Code Transfer**: URL-based QR codes compatible with Google Lens
- **PIN Protection**: 6-character alphanumeric PIN for access control
- **Time-Limited Access**: Configurable expiry times (2, 5, or 10 minutes)
- **One-Time Access**: Files automatically deleted after successful decryption
- **Tamper Detection**: SHA-256 hash verification
- **Attempt Limiting**: Maximum 3 wrong PIN attempts before lockout

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Installation

1. **Clone or download the project files**
   ```bash
   # If you have git
   git clone <repository-url>
   cd secure-file-transfer
   
   # Or extract the downloaded ZIP file
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the application**
   - Open your browser and go to: `http://localhost:5000`
   - The application will automatically create the SQLite database on first run

### For Mobile Testing (Optional)

To test QR code scanning from mobile devices:

1. **Install ngrok** (for external access)
   ```bash
   # Download from https://ngrok.com/download
   # Or use package manager
   ```

2. **Expose local server**
   ```bash
   # In a new terminal window
   ngrok http 5000
   ```

3. **Use the ngrok URL** (e.g., `https://xxxx.ngrok-free.app`) to access from mobile

## 📱 How to Use

### Sending a File

1. Click **"Send File"** on the home page
2. Select an image (JPG, PNG, GIF) or PDF file (max 10MB)
3. Choose expiry time (2, 5, or 10 minutes)
4. Click **"Encrypt & Generate QR"**
5. Share the QR code and PIN with the recipient

### Receiving a File

1. Scan the QR code with Google Lens or any QR scanner
2. Browser will automatically open the receive page
3. Enter the 6-character PIN provided by the sender
4. Click **"Decrypt File"** to access the file
5. For images: view directly in browser
6. For PDFs: download to your device

## 🏗️ Technical Architecture

### Backend (Python/Flask)

- `app.py`: Main Flask application with API endpoints
- `crypto_utils.py`: Cryptographic implementations
- `database.py`: SQLite database management
- `templates/`: HTML templates for the web interface

### Database Schema

**Transactions Table:**
- `transaction_id`: Unique UUID for each transfer
- `encrypted_file`: AES-encrypted and compressed file data
- `encrypted_aes_key`: ElGamal-encrypted AES key
- `private_key`: ElGamal private key for decryption
- `hash_value`: SHA-256 hash for integrity verification
- `hashed_pin`: SHA-256 hash of the access PIN
- `attempt_count`: Number of failed PIN attempts
- `expiry_time`: When the transfer expires
- `file_name`: Original filename
- `huffman_tree`: Serialized Huffman tree for decompression

### Security Flow

#### Sender Side:
1. File upload and validation
2. ElGamal key pair generation
3. Huffman compression
4. AES encryption with random key
5. ElGamal encryption of AES key
6. SHA-256 hash generation
7. PIN generation and hashing
8. Database storage
9. QR code generation with URL

#### Receiver Side:
1. QR code scan opens URL with transaction ID
2. PIN validation (max 3 attempts)
3. Transaction expiry check
4. ElGamal decryption of AES key
5. Hash verification for tamper detection
6. AES decryption of file
7. Huffman decompression
8. File display/download
9. Automatic data deletion

## 🔒 Security Guarantees

- **No Plain Text Storage**: AES keys and PINs are never stored in plain text
- **Forward Secrecy**: Each transfer uses unique keys
- **Data Integrity**: SHA-256 hashing prevents tampering
- **Access Control**: PIN protection with attempt limiting
- **Privacy**: Automatic deletion after access
- **Session-Based**: No user accounts or persistent data

## 📂 Project Structure

```
secure-file-transfer/
├── app.py                 # Main Flask application
├── crypto_utils.py        # Cryptographic utilities
├── database.py           # Database management
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── templates/           # HTML templates
│   ├── base.html       # Base template
│   ├── home.html       # Home page
│   ├── send.html       # Send file page
│   └── receive.html    # Receive file page
└── secure_transfer.db   # SQLite database (auto-created)
```

## 🛠️ Development Notes

### Supported File Types
- **Images**: JPG, JPEG, PNG, GIF
- **Documents**: PDF
- **Size Limit**: 10MB per file

### Browser Compatibility
- Chrome/Chromium (recommended)
- Firefox
- Safari
- Edge
- Mobile browsers (iOS Safari, Chrome Mobile)

### Performance Considerations
- Compression ratio depends on file type
- Large files may take longer to process
- Mobile devices may have slower encryption/decryption

## 🔧 Configuration

### Environment Variables (Optional)
```bash
export FLASK_ENV=development    # For development mode
export FLASK_DEBUG=1           # Enable debug mode
```

### Database Location
- Default: `secure_transfer.db` in project directory
- Can be changed in `database.py`

## 🧪 Testing

### Manual Testing Steps

1. **Upload Test**:
   - Upload various file types and sizes
   - Test different expiry times
   - Verify QR generation and PIN display

2. **Security Test**:
   - Test wrong PIN attempts (should lock after 3)
   - Test expired links (should deny access)
   - Test tampered data detection

3. **Mobile Test**:
   - Scan QR with Google Lens
   - Test on different mobile browsers
   - Verify responsive design

### Logs

The application logs all cryptographic operations to the console:
- File compression/decompression
- Encryption/decryption steps
- Security events (wrong PINs, expired links)
- Access attempts and results

## 🎓 Academic Focus

This project demonstrates:
- **Applied Cryptography**: Real-world implementation of multiple algorithms
- **System Security**: Defense in depth with multiple security layers
- **Database Security**: Secure storage of encrypted data
- **Web Security**: Session-based security without user accounts
- **Mobile Integration**: QR code compatibility with modern devices

## ⚠️ Important Notes

- This is an academic project for educational purposes
- Not intended for production use without additional security hardening
- Files are temporarily stored on the server (encrypted)
- Use only for demonstration and learning purposes
- Always use HTTPS in production environments

## 🐛 Troubleshooting

### Common Issues

1. **"Module not found" errors**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Database errors**:
   - Delete `secure_transfer.db` and restart the application

3. **QR code not scannable**:
   - Ensure good lighting and steady hands
   - Try different QR scanner apps

4. **File too large**:
   - Compress images before upload
   - Use PDF compression tools

5. **Mobile access issues**:
   - Use ngrok for external access
   - Check firewall settings

### Debug Mode

Run with debug information:
```bash
FLASK_DEBUG=1 python app.py
```

## 📞 Support

For academic or technical questions:
- Check the console logs for detailed error information
- Verify all dependencies are correctly installed
- Ensure Python version compatibility (3.8+)

---

**CNS Project - Secure File Transfer System**  
*Demonstrating practical cryptography implementation*