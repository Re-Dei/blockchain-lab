# test_secure_messaging.py
"""
Test suite for secure messaging implementation.
Contains unit tests, integration tests, and end-to-end tests.
"""

import unittest
import pytest
import json
import os
import base64
import time
from unittest.mock import MagicMock, patch
import threading
import requests
import socketio
from flask import Flask
from flask_socketio import SocketIO
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Import our application
from server import app, socketio as app_socketio, CryptoManager, server_crypto, users, sessions, channels


@pytest.fixture
def client():
    """Flask test client fixture"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def crypto_manager():
    """CryptoManager fixture"""
    cm = CryptoManager()
    cm.generate_rsa_keys()
    cm.generate_aes_key()
    return cm


class TestCryptoManager(unittest.TestCase):
    """Unit tests for the CryptoManager class"""
    
    def setUp(self):
        self.crypto_manager = CryptoManager()
    
    def test_aes_key_generation(self):
        """Test AES key generation"""
        key = self.crypto_manager.generate_aes_key()
        self.assertEqual(len(key), 32)  # 256-bit key
        self.assertIs(key, self.crypto_manager.aes_key)
    
    def test_rsa_key_generation(self):
        """Test RSA key pair generation"""
        private_key, public_key = self.crypto_manager.generate_rsa_keys()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertIs(private_key, self.crypto_manager.rsa_private_key)
        self.assertIs(public_key, self.crypto_manager.rsa_public_key)
    
    def test_public_key_serialization(self):
        """Test RSA public key serialization and deserialization"""
        self.crypto_manager.generate_rsa_keys()
        serialized = self.crypto_manager.serialize_public_key()
        self.assertTrue(isinstance(serialized, str))
        
        # Test deserialization
        peer_public_key = self.crypto_manager.deserialize_public_key(serialized, "test_user")
        self.assertIsNotNone(peer_public_key)
        self.assertIn("test_user", self.crypto_manager.peer_public_keys)
    
    def test_aes_encryption_decryption(self):
        """Test AES encryption and decryption"""
        self.crypto_manager.generate_aes_key()
        
        # Test with string data
        plaintext = "This is a secret message"
        encrypted = self.crypto_manager.encrypt_with_aes(plaintext)
        
        # Verify encrypted data structure
        self.assertIn('iv', encrypted)
        self.assertIn('ciphertext', encrypted)
        self.assertIn('tag', encrypted)
        
        # Decrypt and verify
        decrypted = self.crypto_manager.decrypt_with_aes(encrypted)
        self.assertEqual(plaintext, decrypted)
        
        # Test with binary data
        binary_data = os.urandom(1024)  # 1KB of random data
        encrypted = self.crypto_manager.encrypt_with_aes(binary_data)
        decrypted = self.crypto_manager.decrypt_with_aes(encrypted)
        self.assertEqual(binary_data, decrypted.encode('latin1'))  # Using latin1 for binary data
    
    def test_rsa_encryption_decryption(self):
        """Test RSA encryption and decryption of AES key"""
        # Setup two crypto managers to simulate client and server
        client_cm = CryptoManager()
        server_cm = CryptoManager()
        
        # Generate keys
        client_cm.generate_rsa_keys()
        server_cm.generate_rsa_keys()
        client_cm.generate_aes_key()
        
        # Exchange public keys
        client_public_key = client_cm.serialize_public_key()
        server_cm.deserialize_public_key(client_public_key, "client")
        
        # Encrypt AES key with client's public key
        encrypted_key = server_cm.encrypt_aes_key_for_user("client")
        self.assertIsNotNone(encrypted_key)
        
        # Decrypt AES key with client's private key
        decrypted_key = client_cm.decrypt_aes_key_with_rsa(encrypted_key)
        self.assertEqual(len(decrypted_key), 32)  # 256-bit key
    
    def test_encrypt_decrypt_large_data(self):
        """Test encryption and decryption of large data"""
        self.crypto_manager.generate_aes_key()
        
        # Generate 1MB of random data
        large_data = os.urandom(1024 * 1024).hex()
        
        # Encrypt and decrypt
        encrypted = self.crypto_manager.encrypt_with_aes(large_data)
        decrypted = self.crypto_manager.decrypt_with_aes(encrypted)
        
        self.assertEqual(large_data, decrypted)


class TestAPIRoutes:
    """Tests for the API routes"""
    
    def test_register_endpoint(self, client):
        """Test user registration"""
        # Clean up existing test user if present
        users.pop('testuser', None)
        
        # Register new user
        response = client.post('/api/register', json={
            'username': 'testuser',
            'password': 'testpassword'
        })
        
        assert response.status_code == 201
        assert response.json['success'] is True
        assert response.json['username'] == 'testuser'
        assert 'testuser' in users
        
        # Test duplicate registration
        response = client.post('/api/register', json={
            'username': 'testuser',
            'password': 'testpassword'
        })
        
        assert response.status_code == 409
        assert 'error' in response.json
    
    def test_login_endpoint(self, client):
        """Test user login"""
        # Register user first if not exists
        if 'testuser' not in users:
            client.post('/api/register', json={
                'username': 'testuser',
                'password': 'testpassword'
            })
        
        # Test login
        response = client.post('/api/login', json={
            'username': 'testuser',
            'password': 'testpassword'
        })
        
        assert response.status_code == 200
        assert 'session_id' in response.json
        assert 'server_public_key' in response.json
        assert response.json['username'] == 'testuser'
        
        # Test invalid credentials
        response = client.post('/api/login', json={
            'username': 'testuser',
            'password': 'wrongpassword'
        })
        
        assert response.status_code == 401
        assert 'error' in response.json
    
    def test_channels_endpoint(self, client):
        """Test getting channels list"""
        # Login to get a session ID
        login_resp = client.post('/api/login', json={
            'username': 'testuser',
            'password': 'testpassword'
        })
        session_id = login_resp.json['session_id']
        
        # Test getting channels
        response = client.get('/api/channels', headers={
            'X-Session-ID': session_id
        })
        
        assert response.status_code == 200
        assert 'channels' in response.json
        assert len(response.json['channels']) > 0
        
        # Test unauthorized access
        response = client.get('/api/channels', headers={
            'X-Session-ID': 'invalid-session'
        })
        
        assert response.status_code == 401
    
    def test_messages_endpoint(self, client):
        """Test getting channel messages"""
        # Login to get a session ID
        login_resp = client.post('/api/login', json={
            'username': 'testuser',
            'password': 'testpassword'
        })
        session_id = login_resp.json['session_id']
        
        # Test getting messages for a valid channel
        response = client.get('/api/channels/general/messages', headers={
            'X-Session-ID': session_id
        })
        
        assert response.status_code == 200
        assert 'messages' in response.json
        
        # Test invalid channel
        response = client.get('/api/channels/nonexistent/messages', headers={
            'X-Session-ID': session_id
        })
        
        assert response.status_code == 404


@pytest.mark.usefixtures('client')
class TestWebSocketEvents:
    """Tests for WebSocket events"""
    
    @pytest.fixture(autouse=True)
    def setup(self, client):
        """Set up test environment"""
        # Register test users
        if 'testuser1' not in users:
            client.post('/api/register', json={
                'username': 'testuser1',
                'password': 'testpassword'
            })
        
        if 'testuser2' not in users:
            client.post('/api/register', json={
                'username': 'testuser2',
                'password': 'testpassword'
            })
        
        # Log in both users
        resp1 = client.post('/api/login', json={
            'username': 'testuser1',
            'password': 'testpassword'
        })
        self.session_id1 = resp1.json['session_id']
        
        resp2 = client.post('/api/login', json={
            'username': 'testuser2',
            'password': 'testpassword'
        })
        self.session_id2 = resp2.json['session_id']
    
    @pytest.mark.integration
    def test_join_channel(self):
        """Test joining a channel"""
        client1 = socketio.SimpleClient()
        client1.connect('http://localhost:5000')
        
        # Track received events
        received_events = []
        
        @client1.on('user_joined')
        def on_user_joined(data):
            received_events.append(('user_joined', data))
        
        # Join a channel
        client1.emit('join', {
            'session_id': self.session_id1,
            'channel_id': 'general'
        })
        
        # Allow time for event processing
        time.sleep(0.5)
        
        # Clean up
        client1.disconnect()
    
    @pytest.mark.integration
    def test_key_exchange(self):
        """Test AES key exchange"""
        client1 = socketio.SimpleClient()
        client1.connect('http://localhost:5000')
        
        # Track received events
        received_events = []
        
        @client1.on('key_exchange_response')
        def on_key_exchange_response(data):
            received_events.append(('key_exchange_response', data))
        
        # Perform key exchange
        client1.emit('key_exchange', {
            'session_id': self.session_id1
        })
        
        # Allow time for event processing
        time.sleep(0.5)
        
        # Verify response
        assert len(received_events) == 1
        event_name, event_data = received_events[0]
        assert event_name == 'key_exchange_response'
        assert 'encrypted_key' in event_data
        assert event_data['success'] is True
        
        # Clean up
        client1.disconnect()
    
    @pytest.mark.integration
    def test_message_sending(self):
        """Test sending and receiving encrypted messages"""
        # Connect two clients
        client1 = socketio.SimpleClient()
        client2 = socketio.SimpleClient()
        client1.connect('http://localhost:5000')
        client2.connect('http://localhost:5000')
        
        # Track received events
        client2_received = []
        
        @client2.on('new_message')
        def on_new_message(data):
            client2_received.append(('new_message', data))
        
        # Join the same channel
        client1.emit('join', {
            'session_id': self.session_id1,
            'channel_id': 'general'
        })
        client2.emit('join', {
            'session_id': self.session_id2,
            'channel_id': 'general'
        })
        
        # Allow time for joining
        time.sleep(0.5)
        
        # Exchange keys
        client1.emit('key_exchange', {
            'session_id': self.session_id1
        })
        
        # Allow time for key exchange
        time.sleep(0.5)
        
        # Encrypt a test message
        crypto = users['testuser1']['crypto']
        encrypted_message = crypto.encrypt_with_aes("Hello, secure world!")
        
        # Send the encrypted message
        client1.emit('message', {
            'session_id': self.session_id1,
            'channel_id': 'general',
            'content': encrypted_message
        })
        
        # Allow time for message processing
        time.sleep(0.5)
        
        # Verify client2 received the message
        assert len(client2_received) == 1
        event
        
        
# run the tests
if __name__ == '__main__':
    unittest.main()