import { useState, useEffect } from 'react'
import io from 'socket.io-client'
import './index.css'
import CryptoJS from 'crypto-js'

const socket = io('http://127.0.0.1:5000')
let aesKey: string

function App() {
  const [channel, setChannel] = useState('')
  const [message, setMessage] = useState('')
  const [messages, setMessages] = useState<{ channel: string, message: string, sender: string }[]>([])
  const [joined, setJoined] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    socket.on('receive_message', (data) => {
      const decryptedMessage = decryptMessage(aesKey, data.message)
      setMessages((prevMessages) => [...prevMessages, { ...data, message: decryptedMessage }])
      console.log(data)
    })

    socket.on('room_joined', (data) => {
      if (data.success) {
        if (data.key) {
          aesKey = data.key
        }
        setJoined(true)
        setError('')
      } else {
        setError(data.error)
      }
    })

    socket.on('user_joined', (data) => {
      setMessages((prevMessages) => [...prevMessages, { channel: data.channel, message: data.message, sender: 'system' }])
    })
  }, [])

  const joinRoom = () => {
    if (channel.trim() !== '') {
      socket.emit('join_room', { channel })
    }
  }

  const sendMessage = () => {
    const encryptedMessage = encryptMessage(aesKey, message)
    socket.emit('send_message', { channel, message: encryptedMessage })
    setMessage('')
  }

  const encryptMessage = (key: string, plaintext: string) => {
    const iv = CryptoJS.lib.WordArray.random(16)
    const encrypted = CryptoJS.AES.encrypt(plaintext, CryptoJS.enc.Hex.parse(key), {
      iv: iv,
      padding: CryptoJS.pad.Pkcs7,
      mode: CryptoJS.mode.CBC
    })
    return iv.concat(encrypted.ciphertext).toString(CryptoJS.enc.Hex)
  }

  const decryptMessage = (key: string, ciphertext: string) => {
    const ciphertextBytes = CryptoJS.enc.Hex.parse(ciphertext)
    const iv = CryptoJS.lib.WordArray.create(ciphertextBytes.words.slice(0, 4))
    const encrypted = CryptoJS.lib.WordArray.create(ciphertextBytes.words.slice(4))
    const decrypted = CryptoJS.AES.decrypt(CryptoJS.lib.CipherParams.create({ ciphertext: encrypted }), CryptoJS.enc.Hex.parse(key), {
      iv: iv,
      padding: CryptoJS.pad.Pkcs7,
      mode: CryptoJS.mode.CBC
    })
    return decrypted.toString(CryptoJS.enc.Utf8)
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen w-screen bg-black">
      {!joined ? (
        <div className="bg-neutral-500 p-6 rounded shadow-md w-full max-w-md">
          <h1 className="text-3xl font-bold mb-4">Join a Room</h1>
          <input
            type="text"
            placeholder="Enter channel name"
            value={channel}
            onChange={(e) => setChannel(e.target.value)}
            className="w-full p-2 mb-4 border rounded"
          />
          <button
            onClick={joinRoom}
            className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
          >
            Join
          </button>
          {error && <p className="text-red-500 mt-4">{error}</p>}
        </div>
      ) : (
        <div className="bg-neutral-500 p-6 rounded shadow-md w-full max-w-md">
          <h1 className="text-3xl font-bold mb-4">Chat Room: {channel}</h1>
          <input
            type="text"
            placeholder="Enter message"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            className="w-full p-2 mb-4 border rounded"
          />
          <button
            onClick={sendMessage}
            className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
          >
            Send
          </button>
          <ul className="mt-6 w-full max-w-md">
            {messages.filter(msg => msg.channel === channel).map((msg, index) => (
              <li
                key={index}
                className={`p-2 mb-2 rounded shadow ${msg.sender === socket.id ? 'bg-green-500' : 'bg-blue-500'}`}
              >
                {msg.message}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

export default App
