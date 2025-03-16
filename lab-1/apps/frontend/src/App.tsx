import { useState, useEffect } from 'react'
import io from 'socket.io-client'
import './index.css'

const socket = io('http://127.0.0.1:5000')

function App() {
  const [channel, setChannel] = useState('')
  const [message, setMessage] = useState('')
  const [messages, setMessages] = useState<{ channel: string, message: string }[]>([])

  useEffect(() => {
    socket.on('receive_message', (data) => {
      setMessages((prevMessages) => [...prevMessages, data])
      console.log(data)
    })
  }, [])

  const sendMessage = () => {
    socket.emit('send_message', { channel, message })
    setMessage('')
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen w-screen bg-black">
      <h1 className="text-3xl font-bold mb-4">Chat App</h1>
      <div className="bg-neutral-500 p-6 rounded shadow-md w-full max-w-md">
        <input
          type="text"
          placeholder="Enter channel name"
          value={channel}
          onChange={(e) => setChannel(e.target.value)}
          className="w-full p-2 mb-4 border rounded"
        />
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
      </div>
      <ul className="mt-6 w-full max-w-md">
        {messages.filter(msg => msg.channel === channel).map((msg, index) => (
          <li key={index} className="bg-blue p-2 mb-2 rounded shadow">
            {msg.message}
          </li>
        ))}
      </ul>
    </div>
  )
}

export default App
