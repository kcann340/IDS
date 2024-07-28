from flask import Flask, request, jsonify, render_template
import pyshark
import pandas as pd
from datetime import datetime
from preprocessor import Preprocessor
from models import anomaly_model, malware_model
import sqlite3
from collections import defaultdict, deque

app = Flask(__name__)

# Database setup
conn = sqlite3.connect('network_traffic.db')
c = conn.cursor()

# Create tables if they don't exist
c.execute('''CREATE TABLE IF NOT EXISTS CapturedData (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    packet_size INTEGER,
    flags TEXT,
    ttl INTEGER,
    payload TEXT,
    duration INTEGER,
    src_port INTEGER,
    dst_port INTEGER,
    service TEXT,
    land INTEGER,
    wrong_fragment INTEGER,
    urgent INTEGER,
    hot INTEGER,
    num_failed_logins INTEGER,
    logged_in INTEGER,
    num_compromised INTEGER,
    root_shell INTEGER,
    su_attempted INTEGER,
    num_root INTEGER,
    num_file_creations INTEGER,
    num_shells INTEGER,
    num_access_files INTEGER,
    num_outbound_cmds INTEGER,
    is_host_login INTEGER,
    is_guest_login INTEGER,
    count INTEGER,
    srv_count INTEGER,
    serror_rate REAL,
    srv_serror_rate REAL,
    rerror_rate REAL,
    srv_rerror_rate REAL,
    same_srv_rate REAL,
    diff_srv_rate REAL,
    srv_diff_host_rate REAL,
    dst_host_count INTEGER,
    dst_host_srv_count INTEGER,
    dst_host_same_srv_rate REAL,
    dst_host_diff_srv_rate REAL,
    dst_host_same_src_port_rate REAL,
    dst_host_srv_diff_host_rate REAL,
    dst_host_serror_rate REAL,
    dst_host_srv_serror_rate REAL,
    dst_host_rerror_rate REAL,
    dst_host_srv_rerror_rate REAL
)''')

c.execute('''CREATE TABLE IF NOT EXISTS ModelPredictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_data_id INTEGER,
    anomaly_score REAL,
    malware_score REAL,
    is_anomaly INTEGER,
    is_malware INTEGER,
    FOREIGN KEY(captured_data_id) REFERENCES CapturedData(id)
)''')

conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    c.execute("SELECT * FROM CapturedData ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    data = [dict((c.description[i][0], value) for i, value in enumerate(row)) for row in rows]
    return jsonify(data)

@app.route('/api/alerts')
def get_alerts():
    c.execute("SELECT * FROM ModelPredictions WHERE is_anomaly=1 OR is_malware=1 ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    alerts = [dict((c.description[i][0], value) for i, value in enumerate(row)) for row in rows]
    return jsonify(alerts)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

# Close the database connection when the script exits
import atexit
atexit.register(lambda: conn.close())
