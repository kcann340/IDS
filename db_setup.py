import sqlite3

def create_db():
    conn = sqlite3.connect('network_traffic.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS CapturedData (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        packet_size INTEGER,
        raw_data BLOB
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS PreprocessedData (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        captured_data_id INTEGER,
        duration REAL,
        protocol_type TEXT,
        service TEXT,
        flag TEXT,
        src_bytes INTEGER,
        dst_bytes INTEGER,
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
        dst_host_srv_rerror_rate REAL,
        FOREIGN KEY (captured_data_id) REFERENCES CapturedData (id)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ModelPredictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        preprocessed_data_id INTEGER,
        anomaly_score REAL,
        malware_score REAL,
        is_anomaly INTEGER,
        is_malware INTEGER,
        FOREIGN KEY (preprocessed_data_id) REFERENCES PreprocessedData (id)
    )
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_db()
