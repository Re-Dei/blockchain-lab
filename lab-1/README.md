# Blockchain Lab - Secure Messaging with AES

This project demonstrates secure messaging using AES algorithm. The application consists of a frontend built with React and a backend built with Flask and Flask-SocketIO.

## Features

- **AES Encryption**: Messages are encrypted using AES before being sent and decrypted upon receipt.
- **Real-time Communication**: Real-time messaging is implemented using Socket.IO.

## Setup

### Prerequisites

- pnpm
- Python 3
- Flask
- Flask-SocketIO
- `crypto-js` for frontend encryption
- `cryptography` library for backend encryption

### Installation

1. Clone the repository:

```sh
git clone https://github.com/Re-Dei/blockchain-lab.git
cd blockchain-lab
```

2. Install backend dependencies:

```sh
cd lab-1/apps/backend
pip install -r requirements.txt
```

3. Install frontend dependencies:

```sh
cd ../frontend
pnpm install
```

### Running the Application

1. Start (dev):

```sh
pnpm dev
```

### Usage

1. Open your browser and navigate to `http://localhost:5173`.
2. Enter a channel name to join a room.
3. Once both users have joined the room, AES keys are generated and exchanged.
4. AES algorithm is used to encrypt messages.
5. Users can send and receive encrypted messages in real-time.

## Project Structure

- `backend`: Contains the Flask backend code.
- `frontend`: Contains the React frontend code.

## Security

- **AES Encryption**: Used for encrypting and decrypting messages.

## Dependencies

### Backend

- Flask
- Flask-SocketIO
- cryptography

### Frontend

- React
- Socket.IO
- crypto-js

## Why AES?
### AES vs. RSA: A Comparison

#### 1. Overview
| Feature  | AES (Advanced Encryption Standard) | RSA (Rivest-Shamir-Adleman) |
|----------|-----------------------------------|----------------------------|
| Type     | Symmetric Encryption             | Asymmetric Encryption      |
| Key Usage | Same key for encryption & decryption | Public key for encryption, private key for decryption |
| Speed    | Fast                             | Slow                      |
| Security | Strong (especially AES-256)      | Secure but depends on key size (e.g., 2048-bit RSA) |

#### 2. How They Work
##### AES:
- Uses a **single secret key** for both encryption and decryption.
- Operates on fixed-size blocks (e.g., **128-bit blocks**).
- Supports key sizes of **128, 192, or 256 bits**.
- Uses **substitution, permutation, and key expansion** for security.

##### RSA:
- Uses a **public-private key pair**.
- Public key encrypts, private key decrypts.
- Based on the difficulty of **factoring large prime numbers**.
- Common key sizes: **1024-bit (insecure), 2048-bit (standard), 4096-bit (high security)**.

#### 3. Performance
| Factor  | AES | RSA |
|---------|-----|-----|
| Speed   | Very Fast | Slow |
| Key Size | Short (128-256 bits) | Large (2048-4096 bits) |
| CPU Usage | Low | High |

#### 4. Use Cases
| Use Case  | AES | RSA |
|-----------|-----|-----|
| Encrypting large files | ✅ Yes | ❌ No (Too Slow) |
| Secure key exchange | ❌ No | ✅ Yes |
| SSL/TLS handshake | ❌ No | ✅ Yes |
| Secure database storage | ✅ Yes | ❌ No |

#### 5. Which One to Use?
- **Use AES** for encrypting **large amounts of data** (e.g., files, databases).
- **Use RSA** for **key exchange and authentication** (e.g., SSL/TLS, digital signatures).
- Often, **both** are used together: **RSA encrypts an AES key**, and AES encrypts the actual data.

#### 6. Conclusion
- **AES is best for bulk encryption** (fast & secure).
- **RSA is best for secure key exchange** (but slow for large data).
- Hence AES is used.
