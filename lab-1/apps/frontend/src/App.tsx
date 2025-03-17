import { useState, useEffect } from 'react'
import io from 'socket.io-client'
import './index.css'

const socket = io('http://127.0.0.1:5000')

function App() {
  const [channel, setChannel] = useState('')
  const [message, setMessage] = useState('')
  const [messages, setMessages] = useState<{ channel: string, message: string, sender: string }[]>([])
  const [joined, setJoined] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    socket.on('receive_message', (data) => {
      setMessages((prevMessages) => [...prevMessages, data])
      console.log(data)
    })

    socket.on('room_joined', (data) => {
      if (data.success) {
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
    socket.emit('send_message', { channel, message })
    setMessage('')
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
