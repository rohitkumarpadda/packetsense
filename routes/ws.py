"""
routes/ws.py — WebSocket event handlers.
"""

from flask_socketio import emit


def register_ws_handlers(socketio):
    """Register SocketIO event handlers."""

    @socketio.on("connect")
    def handle_connect():
        print("[INFO] Client connected via WebSocket")
        emit("connection_response", {"status": "connected"})

    @socketio.on("disconnect")
    def handle_disconnect():
        print("[INFO] Client disconnected")
