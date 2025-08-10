import socket
import threading
import webbrowser
from flask import Flask, render_template, jsonify
from monitor.monitor import start_monitoring
import time

app = Flask(__name__)

logs = []
alerts = []

def log_callback(log):
    logs.append(log)

def alert_callback(alert):
    # Make sure alerts have both timestamp and message
    alerts.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "message": alert
    })

def start_background_monitor():
    thread = threading.Thread(target=start_monitoring, args=(log_callback, alert_callback), daemon=True)
    thread.start()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP

def find_free_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/logs')
def get_logs():
    return jsonify(logs=logs)

@app.route('/alerts')
def get_alerts():
    return jsonify(alerts=alerts)

if __name__ == '__main__':
    start_background_monitor()
    host_ip = get_local_ip()
    port = find_free_port()
    url = f"http://{host_ip}:{port}/"
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    app.run(debug=False, host=host_ip, port=port)
