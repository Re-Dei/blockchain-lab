from flask import Flask, request
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, leave_room

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*")

rooms = {}

@app.route("/")
def home():
    return {"message": "Hello from Flask backend!"}

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    for room, users in rooms.items():
        if request.sid in users:
            users.remove(request.sid)
            if not users:
                del rooms[room]
            break
    print('Client disconnected')

@socketio.on('join_room')
def handle_join_room(data: dict):
    room = data['channel']
    if room not in rooms:
        rooms[room] = []
    if len(rooms[room]) < 2:
        join_room(room)
        rooms[room].append(request.sid)
        socketio.emit('room_joined', {'channel': room, 'success': True}, room=request.sid)
        socketio.emit('user_joined', {'channel': room, 'message': 'A user has joined the room'}, room=room)
    else:
        socketio.emit('room_joined', {'channel': room, 'success': False, 'error': 'Room is full'}, room=request.sid)

@socketio.on('send_message')
def handle_send_message(data: dict):
    print(data['message'])
    room = data['channel']
    data['sender'] = request.sid
    socketio.emit('receive_message', data, room=room)

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5000)