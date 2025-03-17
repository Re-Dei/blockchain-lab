import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SecureMessaging:
    """
    Implements secure messaging between client and server using hybrid encryption:
    - RSA for key exchange
    - AES for bulk data encryption
    """
    
    def __init__(self):
        # RSA key size - 2048 bits provides good security
        self.rsa_key_size = 2048
        # AES key size - 256 bits for strong encryption
        self.aes_key_size = 32  # 256 bits = 32 bytes
        # AES initialization vector size
        self.iv_size = 16       # 128 bits = 16 bytes
        
    def generate_rsa_key_pair(self):
        """Generate a new RSA key pair for asymmetric encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def serialize_public_key(self, public_key):
        """Convert RSA public key to PEM format for transmission"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem
    
    def deserialize_public_key(self, pem):
        """Convert PEM format back to RSA public key object"""
        public_key = serialization.load_pem_public_key(
            pem,
            backend=default_backend()
        )
        return public_key
    
    def serialize_private_key(self, private_key):
        """Convert RSA private key to PEM format (for storage)"""
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem
    
    def deserialize_private_key(self, pem):
        """Convert PEM format back to RSA private key object"""
        private_key = serialization.load_pem_private_key(
            pem,
            password=None,
            backend=default_backend()
        )
        return private_key
    
    def generate_aes_key(self):
        """Generate a random AES key for symmetric encryption"""
        return os.urandom(self.aes_key_size)
    
    def encrypt_with_rsa(self, public_key, data):
        """Encrypt data using RSA public key"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt_with_rsa(self, private_key, ciphertext):
        """Decrypt data using RSA private key"""
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    def encrypt_with_aes(self, key, plaintext):
        """Encrypt data using AES-256 in CBC mode with a random IV"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        # Generate a random IV (initialization vector)
        iv = os.urandom(self.iv_size)
        
        # Create an encryptor object
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad the plaintext (PKCS7 padding)
        padder = self._get_pkcs7_padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV and ciphertext
        return iv + ciphertext
    
    def decrypt_with_aes(self, key, data):
        """Decrypt data using AES-256 in CBC mode"""
        # Extract IV from the first 16 bytes
        iv = data[:self.iv_size]
        ciphertext = data[self.iv_size:]
        
        # Create a decryptor object
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the plaintext
        unpadder = self._get_pkcs7_unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def _get_pkcs7_padder(self):
        """Get a PKCS7 padder for AES block size"""
        from cryptography.hazmat.primitives.padding import PKCS7
        return PKCS7(algorithms.AES.block_size).padder()
    
    def _get_pkcs7_unpadder(self):
        """Get a PKCS7 unpadder for AES block size"""
        from cryptography.hazmat.primitives.padding import PKCS7
        return PKCS7(algorithms.AES.block_size).unpadder()
    
    def encode_for_transmission(self, data):
        """Encode binary data as base64 for transmission"""
        return base64.b64encode(data).decode('utf-8')
    
    def decode_from_transmission(self, encoded_data):
        """Decode base64 data from transmission"""
        return base64.b64decode(encoded_data)


class SecureClient:
    """Client implementation for secure messaging"""
    
    def __init__(self):
        self.crypto = SecureMessaging()
        # Generate client's RSA key pair
        self.private_key, self.public_key = self.crypto.generate_rsa_key_pair()
        # Store for server's public key (populated during handshake)
        self.server_public_key = None
        # Session key for AES encryption (populated during handshake)
        self.session_key = None
        
    def initiate_handshake(self):
        """Step 1: Client initiates handshake by sending its public key"""
        client_public_pem = self.crypto.serialize_public_key(self.public_key)
        return self.crypto.encode_for_transmission(client_public_pem)
        
    def complete_handshake(self, server_response):
        """Step 3: Client processes server response to complete handshake"""
        # Decode server's response
        decoded_response = self.crypto.decode_from_transmission(server_response)
        response_data = json.loads(decoded_response)
        
        # Get server's public key
        server_public_pem = self.crypto.decode_from_transmission(response_data['server_public_key'])
        self.server_public_key = self.crypto.deserialize_public_key(server_public_pem)
        
        # Decrypt the session key using client's private key
        encrypted_session_key = self.crypto.decode_from_transmission(response_data['encrypted_session_key'])
        self.session_key = self.crypto.decrypt_with_rsa(self.private_key, encrypted_session_key)
        
        return True
        
    def encrypt_message(self, message):
        """Encrypt a message using the session key"""
        if not self.session_key:
            raise ValueError("Handshake not completed. Session key not available.")
            
        # Encrypt with AES
        encrypted_data = self.crypto.encrypt_with_aes(self.session_key, message)
        # Encode for transmission
        return self.crypto.encode_for_transmission(encrypted_data)
        
    def decrypt_message(self, encrypted_message):
        """Decrypt a message using the session key"""
        if not self.session_key:
            raise ValueError("Handshake not completed. Session key not available.")
            
        # Decode from transmission format
        decoded_data = self.crypto.decode_from_transmission(encrypted_message)
        # Decrypt with AES
        return self.crypto.decrypt_with_aes(self.session_key, decoded_data)


class SecureServer:
    """Server implementation for secure messaging"""
    
    def __init__(self):
        self.crypto = SecureMessaging()
        # Generate server's RSA key pair
        self.private_key, self.public_key = self.crypto.generate_rsa_key_pair()
        # Store for client public keys (populated during handshake)
        self.client_keys = {}
        # Session keys for each client
        self.session_keys = {}
        
    def process_handshake(self, client_id, client_public_key_encoded):
        """Step 2: Server processes client handshake and responds"""
        # Decode client's public key
        client_public_pem = self.crypto.decode_from_transmission(client_public_key_encoded)
        client_public_key = self.crypto.deserialize_public_key(client_public_pem)
        
        # Store client's public key
        self.client_keys[client_id] = client_public_key
        
        # Generate a session key for this client
        session_key = self.crypto.generate_aes_key()
        self.session_keys[client_id] = session_key
        
        # Encrypt session key with client's public key
        encrypted_session_key = self.crypto.encrypt_with_rsa(client_public_key, session_key)
        
        # Prepare response
        response = {
            'server_public_key': self.crypto.encode_for_transmission(
                self.crypto.serialize_public_key(self.public_key)
            ),
            'encrypted_session_key': self.crypto.encode_for_transmission(encrypted_session_key)
        }
        
        # Encode response for transmission
        return self.crypto.encode_for_transmission(json.dumps(response).encode('utf-8'))
        
    def encrypt_message(self, client_id, message):
        """Encrypt a message for a specific client using their session key"""
        if client_id not in self.session_keys:
            raise ValueError(f"No session established with client {client_id}")
            
        # Get session key for this client
        session_key = self.session_keys[client_id]
        
        # Encrypt with AES
        encrypted_data = self.crypto.encrypt_with_aes(session_key, message)
        # Encode for transmission
        return self.crypto.encode_for_transmission(encrypted_data)
        
    def decrypt_message(self, client_id, encrypted_message):
        """Decrypt a message from a specific client using their session key"""
        if client_id not in self.session_keys:
            raise ValueError(f"No session established with client {client_id}")
            
        # Get session key for this client
        session_key = self.session_keys[client_id]
        
        # Decode from transmission format
        decoded_data = self.crypto.decode_from_transmission(encrypted_message)
        # Decrypt with AES
        return self.crypto.decrypt_with_aes(session_key, decoded_data)