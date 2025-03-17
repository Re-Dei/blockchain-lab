# Blockchain Lab - Secure Messaging with AES and RSA

This project demonstrates secure messaging using AES and RSA encryption algorithms. The application consists of a frontend built with React and a backend built with Flask and Flask-SocketIO.

## Features

- **AES Encryption**: Messages are encrypted using AES before being sent and decrypted upon receipt.
- **RSA Key Exchange**: RSA keys are used to securely exchange the AES key between the client and the server.
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

1. Start the backend server (dev):

```sh
pnpm dev
```

### Usage

1. Open your browser and navigate to `http://localhost:5173`.
2. Enter a channel name to join a room.
3. Once both users have joined the room, RSA keys are generated and exchanged.
4. The AES key is encrypted with each user's public RSA key and sent to them.
5. Users can send and receive encrypted messages in real-time.

## Project Structure

- `backend`: Contains the Flask backend code.
- `frontend`: Contains the React frontend code.

## Security

- **AES Encryption**: Used for encrypting and decrypting messages.
- **RSA Key Exchange**: Used for securely exchanging the AES key between the client and the server.

## Dependencies

### Backend

- Flask
- Flask-SocketIO
- cryptography

### Frontend

- React
- Socket.IO
- crypto-js

## License

This project is licensed under the MIT License.
