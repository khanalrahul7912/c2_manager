"""Production WSGI entrypoint.

Usage with gunicorn + gevent (recommended):
    gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
             --workers 1 --bind 0.0.0.0:8000 wsgi:app

Usage with plain gunicorn (no WebSocket):
    gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:app

For cPanel Passenger, use passenger_wsgi.py instead.
"""

from app import create_app
from app.extensions import socketio

app = create_app()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=8000)
