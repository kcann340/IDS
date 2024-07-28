import pyshark
import pandas as pd
from datetime import datetime
from preprocessor import Preprocessor
from models import anomaly_model, malware_model
import sqlite3
from collections import defaultdict, deque
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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

# Dictionary to maintain session-based data
session_data = defaultdict(lambda: {
    'num_compromised': 0,
    'root_shell': 0,
    'su_attempted': 0,
    'num_root': 0,
    'num_file_creations': 0,
    'num_shells': 0,
    'num_access_files': 0,
    'num_outbound_cmds': 0,
    'is_host_login': 0,
    'is_guest_login': 0,
    'count': 0,
    'srv_count': 0,
    'serror_rate': 0.0,
    'srv_serror_rate': 0.0,
    'rerror_rate': 0.0,
    'srv_rerror_rate': 0.0,
    'same_srv_rate': 0.0,
    'diff_srv_rate': 0.0,
    'srv_diff_host_rate': 0.0,
    'dst_host_count': 0,
    'dst_host_srv_count': 0,
    'dst_host_same_srv_rate': 0.0,
    'dst_host_diff_srv_rate': 0.0,
    'dst_host_same_src_port_rate': 0.0,
    'dst_host_srv_diff_host_rate': 0.0,
    'dst_host_serror_rate': 0.0,
    'dst_host_srv_serror_rate': 0.0,
    'dst_host_rerror_rate': 0.0,
    'dst_host_srv_rerror_rate': 0.0,
    'packet_history': deque(maxlen=100)  # Store the last 100 packets for rate calculations
})

def update_session_data(packet, data):
    session_key = (data['source_ip'], data['destination_ip'])
    session = session_data[session_key]

    # Update session data with actual logic
    if 'compromised' in packet.layers:
        session['num_compromised'] += 1
    session['count'] += 1

    if data['service'] == session['service']:
        session['srv_count'] += 1

    # Update rate calculations using packet history
    session['packet_history'].append(data)
    packet_count = len(session['packet_history'])
    session['serror_rate'] = sum(1 for pkt in session['packet_history'] if pkt['flags'] == 'SYN') / packet_count
    session['srv_serror_rate'] = sum(1 for pkt in session['packet_history'] if pkt['flags'] == 'SYN' and pkt['service'] == session['service']) / packet_count
    session['rerror_rate'] = sum(1 for pkt in session['packet_history'] if pkt['flags'] == 'RST') / packet_count
    session['srv_rerror_rate'] = sum(1 for pkt in session['packet_history'] if pkt['flags'] == 'RST' and pkt['service'] == session['service']) / packet_count
    session['same_srv_rate'] = sum(1 for pkt in session['packet_history'] if pkt['service'] == data['service']) / packet_count
    session['diff_srv_rate'] = sum(1 for pkt in session['packet_history'] if pkt['service'] != data['service']) / packet_count
    session['srv_diff_host_rate'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] != data['destination_ip']) / packet_count
    session['dst_host_count'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] == data['destination_ip'])
    session['dst_host_srv_count'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] == data['destination_ip'] and pkt['service'] == data['service'])
    session['dst_host_same_srv_rate'] = session['dst_host_srv_count'] / session['dst_host_count'] if session['dst_host_count'] > 0 else 0
    session['dst_host_diff_srv_rate'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] == data['destination_ip'] and pkt['service'] != data['service']) / session['dst_host_count'] if session['dst_host_count'] > 0 else 0
    session['dst_host_same_src_port_rate'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] == data['destination_ip'] and pkt['src_port'] == data['src_port']) / session['dst_host_count'] if session['dst_host_count'] > 0 else 0
    session['dst_host_srv_diff_host_rate'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] == data['destination_ip'] and pkt['service'] == data['service'] and pkt['source_ip'] != data['source_ip']) / session['dst_host_srv_count'] if session['dst_host_srv_count'] > 0 else 0
    session['dst_host_serror_rate'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] == data['destination_ip'] and pkt['flags'] == 'SYN') / session['dst_host_count'] if session['dst_host_count'] > 0 else 0
    session['dst_host_srv_serror_rate'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] == data['destination_ip'] and pkt['service'] == data['service'] and pkt['flags'] == 'SYN') / session['dst_host_srv_count'] if session['dst_host_srv_count'] > 0 else 0
    session['dst_host_rerror_rate'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] == data['destination_ip'] and pkt['flags'] == 'RST') / session['dst_host_count'] if session['dst_host_count'] > 0 else 0
    session['dst_host_srv_rerror_rate'] = sum(1 for pkt in session['packet_history'] if pkt['destination_ip'] == data['destination_ip'] and pkt['service'] == data['service'] and pkt['flags'] == 'RST') / session['dst_host_srv_count'] if session['dst_host_srv_count'] > 0 else 0

    # Update data dictionary with session information
    data.update({
        'num_compromised': session['num_compromised'],
        'root_shell': session['root_shell'],
        'su_attempted': session['su_attempted'],
        'num_root': session['num_root'],
        'num_file_creations': session['num_file_creations'],
        'num_shells': session['num_shells'],
        'num_access_files': session['num_access_files'],
        'num_outbound_cmds': session['num_outbound_cmds'],
        'is_host_login': session['is_host_login'],
        'is_guest_login': session['is_guest_login'],
        'count': session['count'],
        'srv_count': session['srv_count'],
        'serror_rate': session['serror_rate'],
        'srv_serror_rate': session['srv_serror_rate'],
        'rerror_rate': session['rerror_rate'],
        'srv_rerror_rate': session['srv_rerror_rate'],
        'same_srv_rate': session['same_srv_rate'],
        'diff_srv_rate': session['diff_srv_rate'],
        'srv_diff_host_rate': session['srv_diff_host_rate'],
        'dst_host_count': session['dst_host_count'],
        'dst_host_srv_count': session['dst_host_srv_count'],
        'dst_host_same_srv_rate': session['dst_host_same_srv_rate'],
        'dst_host_diff_srv_rate': session['dst_host_diff_srv_rate'],
        'dst_host_same_src_port_rate': session['dst_host_same_src_port_rate'],
        'dst_host_srv_diff_host_rate': session['dst_host_srv_diff_host_rate'],
        'dst_host_serror_rate': session['dst_host_serror_rate'],
        'dst_host_srv_serror_rate': session['dst_host_srv_serror_rate'],
        'dst_host_rerror_rate': session['dst_host_rerror_rate'],
        'dst_host_srv_rerror_rate': session['dst_host_srv_rerror_rate']
    })

def capture_packets(interface='eth0'):
    capture = pyshark.LiveCapture(interface=interface)

    for packet in capture.sniff_continuously():
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': packet.ip.src if hasattr(packet, 'ip') else None,
                'destination_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
                'protocol': packet.transport_layer.lower() if hasattr(packet, 'transport_layer') else None,
                'packet_size': int(packet.length) if hasattr(packet, 'length') else None,
                'flags': packet.tcp.flags if hasattr(packet, 'tcp') else None,
                'ttl': packet.ip.ttl if hasattr(packet, 'ip') else None,
                'payload': bytes(packet.tcp.payload) if hasattr(packet, 'tcp') else None,
                'duration': packet.sniff_time.timestamp() - packet.sniff_time.timestamp() if hasattr(packet, 'sniff_time') else None,
                'src_port': int(packet[packet.transport_layer].srcport) if hasattr(packet[packet.transport_layer], 'srcport') else None,
                'dst_port': int(packet[packet.transport_layer].dstport) if hasattr(packet[packet.transport_layer], 'dstport') else None,
                'service': packet.highest_layer if hasattr(packet, 'highest_layer') else None,
                'land': 1 if packet.ip.src == packet.ip.dst else 0 if hasattr(packet, 'ip') else None,
                'wrong_fragment': int(packet.ip.frag_offset) if hasattr(packet, 'ip') and packet.ip.frag_offset != '0' else 0,
                'urgent': int(packet.tcp.urgent_pointer) if hasattr(packet, 'tcp') else 0,
                'hot': session_data[(packet.ip.src, packet.ip.dst)]['hot'],
                'num_failed_logins': session_data[(packet.ip.src, packet.ip.dst)]['num_failed_logins'],
                'logged_in': 1 if 'login' in packet.layers else 0,
                'num_compromised': session_data[(packet.ip.src, packet.ip.dst)]['num_compromised'],
                'root_shell': session_data[(packet.ip.src, packet.ip.dst)]['root_shell'],
                'su_attempted': session_data[(packet.ip.src, packet.ip.dst)]['su_attempted'],
                'num_root': session_data[(packet.ip.src, packet.ip.dst)]['num_root'],
                'num_file_creations': session_data[(packet.ip.src, packet.ip.dst)]['num_file_creations'],
                'num_shells': session_data[(packet.ip.src, packet.ip.dst)]['num_shells'],
                'num_access_files': session_data[(packet.ip.src, packet.ip.dst)]['num_access_files'],
                'num_outbound_cmds': session_data[(packet.ip.src, packet.ip.dst)]['num_outbound_cmds'],
                'is_host_login': session_data[(packet.ip.src, packet.ip.dst)]['is_host_login'],
                'is_guest_login': 1 if 'guest' in packet.layers else 0,
                'count': session_data[(packet.ip.src, packet.ip.dst)]['count'],
                'srv_count': session_data[(packet.ip.src, packet.ip.dst)]['srv_count'],
                'serror_rate': session_data[(packet.ip.src, packet.ip.dst)]['serror_rate'],
                'srv_serror_rate': session_data[(packet.ip.src, packet.ip.dst)]['srv_serror_rate'],
                'rerror_rate': session_data[(packet.ip.src, packet.ip.dst)]['rerror_rate'],
                'srv_rerror_rate': session_data[(packet.ip.src, packet.ip.dst)]['srv_rerror_rate'],
                'same_srv_rate': session_data[(packet.ip.src, packet.ip.dst)]['same_srv_rate'],
                'diff_srv_rate': session_data[(packet.ip.src, packet.ip.dst)]['diff_srv_rate'],
                'srv_diff_host_rate': session_data[(packet.ip.src, packet.ip.dst)]['srv_diff_host_rate'],
                'dst_host_count': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_count'],
                'dst_host_srv_count': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_srv_count'],
                'dst_host_same_srv_rate': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_same_srv_rate'],
                'dst_host_diff_srv_rate': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_diff_srv_rate'],
                'dst_host_same_src_port_rate': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_same_src_port_rate'],
                'dst_host_srv_diff_host_rate': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_srv_diff_host_rate'],
                'dst_host_serror_rate': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_serror_rate'],
                'dst_host_srv_serror_rate': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_srv_serror_rate'],
                'dst_host_rerror_rate': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_rerror_rate'],
                'dst_host_srv_rerror_rate': session_data[(packet.ip.src, packet.ip.dst)]['dst_host_srv_rerror_rate'],
            }
            
            # Update session data with new packet
            update_session_data(packet, data)
            
            # Process packet
            process_packet(data)
        except Exception as e:
            print(f"Error processing packet: {e}")

# Function to process captured packet data
def process_packet(data):
    try:
        # Insert captured data into the database
        c.execute('''INSERT INTO CapturedData (timestamp, source_ip, destination_ip, protocol, packet_size, flags, ttl, payload)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (data['timestamp'], data['source_ip'], data['destination_ip'], data['protocol'], data['packet_size'], data['flags'], data['ttl'], data['payload']))
        captured_data_id = c.lastrowid
        conn.commit()

        # Convert data to DataFrame
        df = pd.DataFrame([data])

        # Preprocess the data
        preprocessor = Preprocessor()
        X, _ = preprocessor.transform(df)

        # Get model predictions
        anomaly_prediction = anomaly_model.predict(X)
        malware_prediction = malware_model.predict(X)

        # Log data and predictions
        log_data(captured_data_id, anomaly_prediction[0], malware_prediction[0])

        # Check if packet is a threat
        if is_threat(anomaly_prediction[0], malware_prediction[0]):
            alert_system(data, anomaly_prediction[0], malware_prediction[0])
    
    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to log data and predictions into the database
def log_data(captured_data_id, anomaly_prediction, malware_prediction):
    try:
        c.execute('''INSERT INTO ModelPredictions (preprocessed_data_id, anomaly_score, malware_score, is_anomaly, is_malware)
                     VALUES (?, ?, ?, ?, ?)''',
                  (captured_data_id, anomaly_prediction, malware_prediction, int(anomaly_prediction > 0.5), int(malware_prediction > 0.5)))
        conn.commit()
    except Exception as e:
        print(f"Error logging data: {e}")

# Function to check if a packet is a threat
def is_threat(anomaly_prediction, malware_prediction):
    return anomaly_prediction > 0.5 or malware_prediction > 0.5

# Function to alert the system of a detected threat
import requests


def alert_system(data, anomaly_prediction, malware_prediction):
    # Send alert to Telegram
    bot_token = '7218572972:AAGXSdLmQjFutsTUqRtuLUgl8Za7iQXvWvY'
    chat_id = '422112373' 
    message = f"ALERT: Anomaly detected with score {anomaly_prediction}, Malware detected with score {malware_prediction}\nDetails: {data}"
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    params = {'chat_id': chat_id, 'text': message}
    try:
        response = requests.get(url, params=params)
        if response.status_code != 200:
            raise ValueError(f"Request to Telegram returned an error {response.status_code}, the response is:\n{response.text}")
        print(f"ALERT: Anomaly detected with score {anomaly_prediction}, Malware detected with score {malware_prediction}")
    except Exception as e:
        print(f"Failed to send Telegram alert: {e}")

if __name__ == '__main__':
    capture_packets(interface='eth0')

# Close the database connection when the script exits
import atexit
atexit.register(lambda: conn.close())




