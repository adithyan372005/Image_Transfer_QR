#!/usr/bin/env python3
"""
Cryptographic utilities for CNS project
Implements Huffman Compression, AES, and ElGamal encryption
"""

import heapq
import pickle
import secrets
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class HuffmanNode:
    def __init__(self, char, freq, left=None, right=None):
        self.char = char
        self.freq = freq
        self.left = left
        self.right = right
    
    def __lt__(self, other):
        return self.freq < other.freq


class HuffmanCompression:
    def __init__(self):
        self.tree = None
        self.codes = {}
    
    def _build_frequency_table(self, data):
        """Build frequency table for input data"""
        freq_table = {}
        for byte in data:
            freq_table[byte] = freq_table.get(byte, 0) + 1
        return freq_table
    
    def _build_huffman_tree(self, freq_table):
        """Build Huffman tree from frequency table"""
        if len(freq_table) <= 1:
            # Special case: single character or empty data
            char = list(freq_table.keys())[0] if freq_table else 0
            return HuffmanNode(char, freq_table.get(char, 0))
        
        heap = []
        for char, freq in freq_table.items():
            heapq.heappush(heap, HuffmanNode(char, freq))
        
        while len(heap) > 1:
            left = heapq.heappop(heap)
            right = heapq.heappop(heap)
            merged = HuffmanNode(None, left.freq + right.freq, left, right)
            heapq.heappush(heap, merged)
        
        return heap[0]
    
    def _generate_codes(self, root, code="", codes=None):
        """Generate Huffman codes for each character"""
        if codes is None:
            codes = {}
        
        if root is not None:
            if root.char is not None:  # Leaf node
                codes[root.char] = code if code else "0"  # Handle single character case
            else:
                self._generate_codes(root.left, code + "0", codes)
                self._generate_codes(root.right, code + "1", codes)
        
        return codes
    
    def compress(self, data):
        """Compress data using Huffman coding"""
        if not data:
            self.tree = None
            self.codes = {}
            return b''
        
        # Build frequency table
        freq_table = self._build_frequency_table(data)
        
        # Build Huffman tree
        self.tree = self._build_huffman_tree(freq_table)
        
        # Generate codes
        self.codes = self._generate_codes(self.tree)
        
        # Encode data
        encoded_bits = ""
        for byte in data:
            encoded_bits += self.codes[byte]
        
        # Pad to make it byte-aligned
        padding = 8 - len(encoded_bits) % 8
        if padding != 8:
            encoded_bits += "0" * padding
        
        # Convert to bytes
        compressed = bytearray()
        for i in range(0, len(encoded_bits), 8):
            byte_str = encoded_bits[i:i+8]
            compressed.append(int(byte_str, 2))
        
        # Store padding info in first byte
        result = bytearray([padding])
        result.extend(compressed)
        
        return bytes(result)
    
    def decompress(self, compressed_data):
        """Decompress data using stored Huffman tree"""
        if not compressed_data or self.tree is None:
            return b''
        
        if self.tree.char is not None:  # Single character case
            # Extract length info and reconstruct
            padding = compressed_data[0]
            bit_count = (len(compressed_data) - 1) * 8 - padding
            return bytes([self.tree.char] * (bit_count if bit_count > 0 else self.tree.freq))
        
        # Extract padding info
        padding = compressed_data[0]
        compressed_data = compressed_data[1:]
        
        # Convert to bits
        encoded_bits = ""
        for byte in compressed_data:
            encoded_bits += format(byte, '08b')
        
        # Remove padding
        if padding > 0:
            encoded_bits = encoded_bits[:-padding]
        
        # Decode using tree
        decoded = bytearray()
        current = self.tree
        
        for bit in encoded_bits:
            if bit == "0":
                current = current.left
            else:
                current = current.right
            
            if current.char is not None:  # Leaf node
                decoded.append(current.char)
                current = self.tree
        
        return bytes(decoded)
    
    def get_tree(self):
        """Serialize Huffman tree for storage"""
        return pickle.dumps((self.tree, self.codes))
    
    def set_tree(self, tree_data):
        """Deserialize Huffman tree from storage"""
        self.tree, self.codes = pickle.loads(tree_data)


class AESCrypto:
    def __init__(self):
        self.key_size = 32  # 256-bit key
    
    def generate_key(self):
        """Generate random AES key"""
        return get_random_bytes(self.key_size)
    
    def encrypt(self, data, key):
        """Encrypt data using AES in CBC mode"""
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return cipher.iv + ciphertext
    
    def decrypt(self, encrypted_data, key):
        """Decrypt data using AES in CBC mode"""
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        return unpad(padded_plaintext, AES.block_size)


class ElGamalCrypto:
    def __init__(self):
        self.key_size = 2048  # bits
    
    def _generate_prime(self, bits):
        """Generate a random prime number"""
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
            if self._is_prime(num):
                return num
    
    def _is_prime(self, n, k=10):
        """Miller-Rabin primality test"""
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False
        
        # Write n-1 as d * 2^r
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Perform k rounds of testing
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _find_generator(self, p):
        """Find a generator for the cyclic group Z*p"""
        # For simplicity, use a small generator that works for most primes
        for g in [2, 3, 5, 7, 11, 13, 17, 19, 23]:
            if pow(g, (p - 1) // 2, p) != 1:
                return g
        
        # If small generators don't work, find one randomly
        for _ in range(100):
            g = random.randrange(2, p)
            if pow(g, (p - 1) // 2, p) != 1:
                return g
        
        return 2  # Fallback
    
    def generate_keypair(self):
        """Generate ElGamal key pair"""
        # Generate large prime p
        p = self._generate_prime(self.key_size // 8)  # Smaller for demo purposes
        
        # Find generator g
        g = self._find_generator(p)
        
        # Generate private key x
        x = random.randrange(1, p - 1)
        
        # Calculate public key y = g^x mod p
        y = pow(g, x, p)
        
        public_key = (p, g, y)
        private_key = (p, g, x)
        
        return self._serialize_key(public_key), self._serialize_key(private_key)
    
    def _serialize_key(self, key):
        """Serialize key tuple to bytes"""
        return pickle.dumps(key)
    
    def _deserialize_key(self, key_bytes):
        """Deserialize key from bytes"""
        return pickle.loads(key_bytes)
    
    def encrypt(self, data, public_key_bytes):
        """Encrypt data using ElGamal public key"""
        p, g, y = self._deserialize_key(public_key_bytes)
        
        # Convert data to integer
        data_int = int.from_bytes(data, byteorder='big')
        
        # If data is too large, split into blocks
        max_block_size = (p.bit_length() - 1) // 8
        if len(data) > max_block_size:
            # For simplicity in this demo, we'll use a different approach
            # Encrypt the data in smaller chunks
            blocks = []
            for i in range(0, len(data), max_block_size):
                block = data[i:i + max_block_size]
                blocks.append(self._encrypt_block(block, (p, g, y)))
            return pickle.dumps(blocks)
        else:
            return self._encrypt_block(data, (p, g, y))
    
    def _encrypt_block(self, data, public_key):
        """Encrypt a single block of data"""
        p, g, y = public_key
        
        # Convert data to integer
        data_int = int.from_bytes(data, byteorder='big')
        
        # Ensure data_int < p
        if data_int >= p:
            raise ValueError("Data too large for key size")
        
        # Generate random k
        k = random.randrange(1, p - 1)
        
        # Calculate ciphertext
        c1 = pow(g, k, p)
        c2 = (data_int * pow(y, k, p)) % p
        
        return pickle.dumps((c1, c2))
    
    def decrypt(self, encrypted_data, private_key_bytes):
        """Decrypt data using ElGamal private key"""
        p, g, x = self._deserialize_key(private_key_bytes)
        
        try:
            # Try to unpickle as blocks first
            blocks = pickle.loads(encrypted_data)
            if isinstance(blocks, list):
                # Multiple blocks
                decrypted_data = b''
                for block_data in blocks:
                    decrypted_data += self._decrypt_block(block_data, (p, g, x))
                return decrypted_data
            else:
                # Single block (backwards compatibility)
                return self._decrypt_block(encrypted_data, (p, g, x))
        except:
            # Single block
            return self._decrypt_block(encrypted_data, (p, g, x))
    
    def _decrypt_block(self, encrypted_block, private_key):
        """Decrypt a single block of data"""
        p, g, x = private_key
        c1, c2 = pickle.loads(encrypted_block)
        
        # Calculate shared secret
        s = pow(c1, x, p)
        
        # Calculate modular inverse of s
        s_inv = pow(s, p - 2, p)  # Using Fermat's little theorem
        
        # Recover plaintext
        plaintext_int = (c2 * s_inv) % p
        
        # Convert back to bytes
        byte_length = (plaintext_int.bit_length() + 7) // 8
        if byte_length == 0:
            return b'\x00'
        
        return plaintext_int.to_bytes(byte_length, byteorder='big')