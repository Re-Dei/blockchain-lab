# app.py
"""
Secure Messaging System Backend
Flask-based API with WebSockets for real-time communication
Uses AES for message encryption and RSA for secure key exchange
"""

import os
import base64
import json
import uuid
from datetime import datetime
import logging

# Flask imports
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend/build')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory data stores (would use database in production)
users = {}  # username -> user_data
sessions = {}  # session_id -> session_data
channels = {
    'general': {
        'name': 'General',
        'description': 'General discussion channel',
        'messages': []
    }
}


class CryptoManager:
    """
    Handles encryption/decryption operations and key management
    """
    def __init__(self):
        self.aes_key = None
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.peer_public_keys = {}  # user_id -> public_key
    
    def generate_aes_key(self):
        """Generate a random AES-256 key"""
        self.aes_key = os.urandom(32)  # 256 bits
        return self.aes_key
    
    def generate_rsa_keys(self):
        """Generate RSA key pair for asymmetric encryption"""
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        return self.rsa_private_key, self.rsa_public_key
    
    def serialize_public_key(self):
        """Convert RSA public key to string for transmission"""
        if not self.rsa_public_key:
            raise ValueError("RSA public key not generated yet")
        
        key_bytes = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(key_bytes).decode('utf-8')
    
    def deserialize_public_key(self, key_b64, user_id=None):
        """Convert base64 string back to RSA public key"""
        key_bytes = base64.b64decode(key_b64)
        public_key = serialization.load_pem_public_key(
            key_bytes,
            backend=default_backend()
        )
        
        if user_id:
            self.peer_public_keys[user_id] = public_key
            
        return public_key
    
    def encrypt_aes_key_for_user(self, user_id):
        """Encrypt AES key using user's RSA public key"""
        if user_id not in self.peer_public_keys or not self.aes_key:
            raise ValueError(f"Public key for {user_id} or AES key not available")
        
        encrypted_key = self.peer_public_keys[user_id].encrypt(
            self.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode('utf-8')
    
    def decrypt_aes_key_with_rsa(self, encrypted_key_b64):
        """Decrypt AES key using own RSA private key"""
        if not self.rsa_private_key:
            raise ValueError("RSA private key not available")
        
        encrypted_key = base64.b64decode(encrypted_key_b64)
        self.aes_key = self.rsa_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self.aes_key
    
    def encrypt_with_aes(self, plaintext):
        """Encrypt data using AES-256 in GCM mode"""
        if not self.aes_key:
            raise ValueError("AES key not available")
        
        # Convert string to bytes if necessary
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate a random 96-bit IV (recommended for GCM)
        iv = os.urandom(12)
        
        # Create an encryptor object
        encryptor = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        # Encrypt the plaintext
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Return IV, ciphertext, and authentication tag
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }
    
    def decrypt_with_aes(self, encrypted_data):
        """Decrypt data using AES-256 in GCM mode"""
        if not self.aes_key:
            raise ValueError("AES key not available")
        
        # Decode the base64 components
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        # Create a decryptor object
        decryptor = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        # Decrypt the ciphertext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Try to decode as UTF-8, but handle errors
        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            # If it's binary data and not text, return the bytes directly
            return plaintext


# Initialize server crypto manager
server_crypto = CryptoManager()
server_crypto.generate_rsa_keys()
server_crypto.generate_aes_key()


# Helper functions
def get_user_by_session(session_id):
    """Get user data for a session"""
    if session_id not in sessions:
        return None
    
    username = sessions[session_id]['username']
    return users.get(username)


# API Routes
@app.route('/')
def serve_frontend():
    """Serve the frontend app"""
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.json
    username = data.get('username')
    password = data.get('password')  # In production, use proper password hashing
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if username in users:
        return jsonify({'error': 'Username already exists'}), 409
    
    # Create user with a new crypto manager
    user_crypto = CryptoManager()
    user_crypto.generate_rsa_keys()
    
    users[username] = {
        'username': username,
        'password': password,  # In production, hash this!
        'crypto': user_crypto,
        'public_key': user_crypto.serialize_public_key()
    }
    
    return jsonify({'success': True, 'username': username}), 201


@app.route('/api/login', methods=['POST'])
def login():
    """Login a user"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = users.get(username)
    if not user or user['password'] != password:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Create session
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        'username': username,
        'created_at': datetime.now().isoformat()
    }
    
    # Store the client's public key if provided
    client_public_key = data.get('public_key')
    if client_public_key:
        server_crypto.deserialize_public_key(client_public_key, username)
    
    # Return session token and server public key
    return jsonify({
        'session_id': session_id,
        'username': username,
        'server_public_key': server_crypto.serialize_public_key()
    }), 200


@app.route('/api/channels', methods=['GET'])
def get_channels():
    """Get list of available channels"""
    session_id = request.headers.get('X-Session-ID')
    if not get_user_by_session(session_id):
        return jsonify({'error': 'Unauthorized'}), 401
    
    channel_list = [
        {
            'id': channel_id,
            'name': channel_data['name'],
            'description': channel_data['description']
        }
        for channel_id, channel_data in channels.items()
    ]
    
    return jsonify({'channels': channel_list}), 200


@app.route('/api/channels/<channel_id>/messages', methods=['GET'])
def get_messages(channel_id):
    """Get messages for a channel"""
    session_id = request.headers.get('X-Session-ID')
    if not get_user_by_session(session_id):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if channel_id not in channels:
        return jsonify({'error': 'Channel not found'}), 404
    
    # Return last 50 messages
    messages = channels[channel_id]['messages'][-50:]
    
    return jsonify({'messages': messages}), 200


# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on('join')
def handle_join(data):
    """Handle client joining a channel"""
    session_id = data.get('session_id')
    channel_id = data.get('channel_id')
    
    user = get_user_by_session(session_id)
    if not user or channel_id not in channels:
        emit('error', {'message': 'Unauthorized or channel not found'})
        return
    
    join_room(channel_id)
    logger.info(f"User {user['username']} joined channel {channel_id}")
    
    # Notify other users
    emit('user_joined', {
        'username': user['username'],
        'timestamp': datetime.now().isoformat()
    }, room=channel_id, include_self=False)


@socketio.on('leave')
def handle_leave(data):
    """Handle client leaving a channel"""
    session_id = data.get('session_id')
    channel_id = data.get('channel_id')
    
    user = get_user_by_session(session_id)
    if not user or channel_id not in channels:
        return
    
    leave_room(channel_id)
    logger.info(f"User {user['username']} left channel {channel_id}")
    
    # Notify other users
    emit('user_left', {
        'username': user['username'],
        'timestamp': datetime.now().isoformat()
    }, room=channel_id, include_self=False)


@socketio.on('key_exchange')
def handle_key_exchange(data):
    """Handle AES key exchange"""
    session_id = data.get('session_id')
    user = get_user_by_session(session_id)
    
    if not user:
        emit('error', {'message': 'Unauthorized'})
        return
    
    try:
        # Get user's public key if not already stored
        if user['username'] not in server_crypto.peer_public_keys:
            server_crypto.deserialize_public_key(user['public_key'], user['username'])
        
        # Encrypt server's AES key with user's public key
        encrypted_aes_key = server_crypto.encrypt_aes_key_for_user(user['username'])
        
        # Send encrypted key to client
        emit('key_exchange_response', {
            'encrypted_key': encrypted_aes_key,
            'success': True
        })
        
        logger.info(f"Key exchange completed with user {user['username']}")
        
    except Exception as e:
        logger.error(f"Key exchange error: {str(e)}")
        emit('error', {'message': f'Key exchange error: {str(e)}'})


@socketio.on('message')
def handle_message(data):
    """Handle encrypted message"""
    session_id = data.get('session_id')
    channel_id = data.get('channel_id')
    encrypted_content = data.get('content')
    
    user = get_user_by_session(session_id)
    if not user or channel_id not in channels:
        emit('error', {'message': 'Unauthorized or channel not found'})
        return
    
    try:
        # Decrypt the message
        decrypted_content = server_crypto.decrypt_with_aes(encrypted_content)
        
        # Create message object
        message = {
            'id': str(uuid.uuid4()),
            'channel_id': channel_id,
            'username': user['username'],
            'content': decrypted_content,
            'timestamp': datetime.now().isoformat()
        }
        
        # Store message
        channels[channel_id]['messages'].append(message)
        
        # Re-encrypt with server's AES key and broadcast to channel
        message_copy = message.copy()
        message_copy['content'] = server_crypto.encrypt_with_aes(message['content'])
        
        emit('new_message', message_copy, room=channel_id)
        logger.info(f"Message sent from {user['username']} to channel {channel_id}")
        
    except Exception as e:
        logger.error(f"Message handling error: {str(e)}")
        emit('error', {'message': f'Message handling error: {str(e)}'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting server on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=True)