# CNS Project: Secure File Transfer System

A comprehensive web application demonstrating advanced cryptographic techniques for secure file transfer. Features dual-mode operation with traditional PIN-based transfers and modern session-based end-to-end encryption.

## 🏗️ Architecture Overview

This system implements two distinct transfer modes:

### 1. **Legacy Mode: PIN-Based Transfers**
- Server-side encryption with PIN protection
- QR code contains direct access URL
- Suitable for quick, simple transfers

### 2. **Session Mode: End-to-End Encryption**
- Client-side key generation (private keys never leave client)
- Server acts as encrypted relay only
- True end-to-end encryption with forward secrecy

## 🔐 Security Features

### Core Cryptography
- **Huffman Compression**: Efficient file compression with detailed statistics
- **AES-256 Encryption**: Military-grade symmetric encryption
- **ElGamal Cryptography**: Asymmetric encryption for key exchange
- **SHA-256 Hashing**: Data integrity verification

### Access Control
- **PIN Protection**: 6-character alphanumeric PINs (legacy mode)
- **Session-based Security**: No persistent authentication required
- **Attempt Limiting**: Maximum 3 failed attempts before lockout
- **Time-Limited Access**: Configurable expiry times
- **One-Time Download**: Automatic data deletion after access

### Privacy & Security
- **Forward Secrecy**: Unique keys for each transfer
- **No Plain Text Storage**: All sensitive data encrypted at rest
- **Tamper Detection**: Hash verification prevents data modification
- **Optional Receiver Verification**: Name-based recipient validation
- **Comprehensive Logging**: Security audit trail

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Installation

1. **Download or clone the project**
   ```bash
   git clone <repository-url>
   cd secure-file-transfer
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
   - Open browser to: `http://localhost:5000`
   - Database auto-creates on first run

### Mobile Testing (Optional)

For QR code scanning from mobile devices:

1. **Install ngrok** for external access
   ```bash
   # Download from https://ngrok.com/download
   ngrok http 5000
   ```

2. **Use the ngrok URL** for mobile access

## 📱 How to Use

### Mode 1: Legacy PIN-Based Transfer

#### Sending a File
1. Click **"Send File"** on home page
2. Select image (JPG, PNG, GIF) or PDF file (max 10MB)
3. Optionally set intended receiver name
4. Choose expiry time (2, 5, or 10 minutes)
5. Click **"Encrypt & Generate QR"**
6. View compression statistics and real-time status
7. Share QR code and PIN with recipient

#### Receiving a File
1. Scan QR code with any QR scanner
2. Browser opens receive page automatically
3. Enter the 6-character PIN
4. Optionally enter your name for logging
5. Click **"Decrypt File"** to access
6. Download file (one-time access only)

### Mode 2: Session-Based E2E Encryption

#### Creating a Session
1. Click **"Session Send"** on home page
2. Enter sender name and expiry time
3. Click **"Create Session"**
4. Share QR code with recipient
5. Wait for receiver to join and generate keys

#### Joining a Session
1. Scan QR code to join session
2. System generates key pair locally
3. Private key never leaves your device
4. Notify sender when ready

#### Transferring Files
1. **Sender**: Upload file after receiver joins
2. File encrypted with receiver's public key
3. **Receiver**: Decrypt using local private key
4. Download decrypted file

## 🔧 Technical Architecture

### Backend Components
- **app.py**: Flask application with dual-mode routing
- **crypto_utils.py**: Cryptographic implementations
  - `HuffmanCompression`: File compression/decompression
  - `AESCrypto`: Symmetric encryption
  - `ElGamalCrypto`: Asymmetric encryption
- **database.py**: SQLite database management

### Frontend Templates
- **base.html**: Common layout and styling
- **home.html**: Mode selection homepage
- **send.html**: Legacy mode file sender
- **receive.html**: Legacy mode file receiver
- **session_sender.html**: E2E mode sender interface
- **session_receiver.html**: E2E mode receiver interface

### Database Schema

#### Transactions Table (Legacy Mode)
```sql
CREATE TABLE transactions (
    transaction_id TEXT PRIMARY KEY,
    encrypted_file TEXT NOT NULL,
    encrypted_aes_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    hashed_pin TEXT NOT NULL,
    attempt_count INTEGER DEFAULT 0,
    expiry_time TEXT NOT NULL,
    file_name TEXT NOT NULL,
    huffman_tree TEXT NOT NULL,
    original_size INTEGER DEFAULT 0,
    compressed_size INTEGER DEFAULT 0,
    compression_ratio REAL DEFAULT 0.0,
    status TEXT DEFAULT 'ACTIVE',
    intended_receiver_name TEXT,
    receiver_name TEXT,
    access_time TEXT,
    user_agent TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
```

#### Sessions Table (E2E Mode)
```sql
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL,
    server_url TEXT NOT NULL,
    public_key_p TEXT,
    public_key_g TEXT,
    public_key_y TEXT,
    encrypted_file TEXT,
    encrypted_aes_key TEXT,
    hash_value TEXT,
    file_name TEXT,
    huffman_tree TEXT,
    original_size INTEGER DEFAULT 0,
    compressed_size INTEGER DEFAULT 0,
    compression_ratio REAL DEFAULT 0.0,
    status TEXT DEFAULT 'WAITING_FOR_RECEIVER',
    attempt_count INTEGER DEFAULT 0,
    expiry_time TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    receiver_joined_at TEXT,
    key_generated_at TEXT,
    file_uploaded_at TEXT,
    accessed_at TEXT
)
```

### Security Flow

#### Legacy Mode Flow
1. **File Upload**: User selects file and expiry
2. **Compression**: Huffman encoding reduces file size
3. **Key Generation**: Server generates ElGamal key pair
4. **AES Encryption**: File encrypted with random AES key
5. **Key Encryption**: AES key encrypted with ElGamal public key
6. **Hash Generation**: SHA-256 hash for integrity
7. **PIN Creation**: Random alphanumeric PIN generated
8. **Storage**: All data stored encrypted in database
9. **QR Generation**: URL with transaction ID encoded
10. **Access**: Receiver scans QR, enters PIN, downloads file

#### Session Mode Flow (End-to-End)
1. **Session Creation**: Sender creates session with QR code
2. **Receiver Join**: Receiver scans QR and joins session
3. **Key Generation**: Receiver generates ElGamal keys locally
4. **Public Key Share**: Only public key sent to server
5. **File Upload**: Sender uploads file after receiver ready
6. **Client Encryption**: File encrypted with receiver's public key
7. **Server Relay**: Server stores encrypted data only
8. **Client Decryption**: Receiver decrypts using local private key
9. **Download**: File available for one-time download

## 🛡️ Security Guarantees

### Data Protection
- **End-to-End Encryption**: Session mode ensures server cannot decrypt files
- **Forward Secrecy**: Each transfer uses unique cryptographic keys
- **Data Integrity**: SHA-256 hashing prevents tampering
- **Secure Deletion**: Automatic cleanup after download
- **No Persistent Storage**: No user accounts or long-term data retention

### Access Control
- **Multi-Factor**: PIN + optional name verification
- **Rate Limiting**: Maximum 3 attempts before lockout
- **Time Bounds**: Configurable expiry prevents stale access
- **One-Time Use**: Files deleted immediately after download
- **Audit Trail**: Comprehensive logging for security analysis

### Privacy
- **Anonymous Usage**: No user registration required
- **Minimal Metadata**: Only essential transfer information stored
- **Local Key Storage**: Private keys never transmitted (session mode)
- **Automatic Cleanup**: All data purged after successful transfer

## 📂 Project Structure

```
secure-file-transfer/
├── app.py                     # Main Flask application
├── crypto_utils.py            # Cryptographic utilities
├── database.py               # Database management
├── requirements.txt          # Python dependencies
├── README.md                # This documentation
├── templates/               # HTML templates
│   ├── base.html           # Base template with common layout
│   ├── home.html           # Mode selection homepage
│   ├── send.html           # Legacy mode send interface
│   ├── receive.html        # Legacy mode receive interface
│   ├── session_sender.html # E2E mode sender interface
│   └── session_receiver.html # E2E mode receiver interface
└── secure_transfer.db       # SQLite database (auto-created)
```

## 🔧 API Endpoints

### Legacy Mode Endpoints
- `POST /upload` - Upload and encrypt file with PIN
- `POST /decrypt` - Decrypt file with PIN
- `GET /download/<transaction_id>` - Download decrypted file
- `GET /status/<transaction_id>` - Check transfer status

### Session Mode Endpoints
- `POST /create_session` - Create new E2E session
- `GET /join_session` - Join existing session
- `POST /generate_keypair` - Generate receiver key pair
- `GET /get_public_key/<session_id>` - Retrieve public key
- `POST /session_upload` - Upload file to session
- `POST /session_decrypt` - Decrypt session file
- `GET /session_download/<session_id>` - Download session file
- `GET /session_status/<session_id>` - Check session status

## 🛠️ Development Notes

### Supported File Types
- **Images**: JPG, JPEG, PNG, GIF
- **Documents**: PDF
- **Size Limit**: 10MB per file

### Browser Compatibility
- Chrome/Chromium (recommended)
- Firefox, Safari, Edge
- Mobile browsers (iOS Safari, Chrome Mobile)

### Performance Considerations
- Compression efficiency varies by file type
- Large files require more processing time
- Mobile devices may have slower crypto operations

### Environment Configuration
```bash
# Development mode
export FLASK_ENV=development
export FLASK_DEBUG=1

# Run application
python app.py
```

## 🧪 Testing

### Manual Test Cases

1. **Legacy Mode Testing**:
   - Upload various file types and sizes
   - Test PIN validation and attempt limiting
   - Verify expiry time enforcement
   - Test receiver name validation

2. **Session Mode Testing**:
   - Create sessions with different expiry times
   - Test key generation and public key sharing
   - Verify end-to-end encryption flow
   - Test concurrent sessions

3. **Security Testing**:
   - Attempt access with wrong PINs
   - Test expired link handling
   - Verify data integrity checking
   - Test tamper detection

4. **Mobile Testing**:
   - QR code scanning with different apps
   - Test responsive design on various devices
   - Verify mobile browser compatibility

### Logs and Monitoring

The application provides comprehensive logging:
- Cryptographic operations (compression, encryption, decryption)
- Security events (failed attempts, expired access, tampering)
- Transfer statistics (file sizes, compression ratios)
- Access patterns (timestamps, user agents)

## 🎓 Educational Value

This project demonstrates:

### Applied Cryptography
- **Symmetric Encryption**: AES-256 implementation
- **Asymmetric Encryption**: ElGamal key exchange
- **Data Compression**: Huffman coding algorithm
- **Hash Functions**: SHA-256 for integrity verification

### Security Engineering
- **Defense in Depth**: Multiple security layers
- **Forward Secrecy**: Ephemeral key management
- **Access Control**: Multi-factor authentication
- **Secure Development**: Input validation, error handling

### System Architecture
- **Database Security**: Encrypted data storage
- **Web Security**: Session management, CSRF protection
- **Mobile Integration**: QR code standards compliance
- **API Design**: RESTful endpoint architecture

## ⚠️ Important Notes

- **Academic Purpose**: Designed for educational demonstration
- **Not Production Ready**: Requires additional hardening for production use
- **HTTPS Required**: Always use HTTPS in production environments
- **Regular Updates**: Keep dependencies updated for security
- **Data Retention**: Temporary server storage of encrypted files

## 🐛 Troubleshooting

### Common Issues

1. **Module Import Errors**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Database Corruption**:
   ```bash
   rm secure_transfer.db
   python app.py  # Will recreate database
   ```

3. **QR Code Scanning Issues**:
   - Ensure adequate lighting
   - Try different QR scanner apps
   - Use Google Lens for best compatibility

4. **File Upload Failures**:
   - Check file size limit (10MB)
   - Verify file type is supported
   - Ensure stable network connection

5. **Mobile Access Problems**:
   - Use ngrok for external access testing
   - Check firewall and network settings
   - Verify mobile browser compatibility

### Debug Mode

Enable detailed logging:
```bash
FLASK_DEBUG=1 python app.py
```

### Performance Optimization

For better performance:
- Use production WSGI server (gunicorn, uWSGI)
- Enable database connection pooling
- Implement file size optimization
- Add caching for static assets

## 📞 Support & Contribution

### Getting Help
- Check console logs for detailed error information
- Verify all dependencies are correctly installed
- Ensure Python version compatibility (3.8+)
- Review browser console for client-side errors

### Educational Use
This project serves as a comprehensive example of:
- Modern cryptographic implementations
- Secure web application development
- Database security best practices
- Mobile-first responsive design

---

**CNS Project - Dual Mode Secure File Transfer**  
*Demonstrating Advanced Cryptography & End-to-End Security*