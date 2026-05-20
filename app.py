from flask import Flask, render_template, redirect, url_for, request, session, jsonify, send_file, Response
import numpy as np
import ipaddress
import struct
import pandas as pd
from io import BytesIO
from datetime import datetime, timedelta, timezone
import os
import time
import json
import random
import pickle
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, extract, text

app = Flask(__name__)
app.secret_key = 'your_secure_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///predictions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database setup
db = SQLAlchemy(app)

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    input_method = db.Column(db.String(20))
    prediction_type = db.Column(db.String(20))
    details = db.Column(db.Text)
    is_attack = db.Column(db.Boolean, default=False, index=True)

    def serialize(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'type': self.prediction_type,
            'input_method': self.input_method,
            'is_attack': self.is_attack
        }

def initialize_database():
    with app.app_context():
        db.create_all()
        print("Database initialized")
        
#initialize_database()

# Custom template filter
@app.template_filter('format_time')
def format_time_filter(timestamp):
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp)
        elif isinstance(timestamp, datetime):
            dt = timestamp
        else:
            return str(timestamp)

        # Convert to local timezone
        local_tz = datetime.now(timezone.utc).astimezone().tzinfo
        dt_local = dt.replace(tzinfo=timezone.utc).astimezone(tz=local_tz)

        return dt_local.strftime('%H:%M %m/%d/%Y')
    except (ValueError, TypeError) as e:
        print(f"Time format error: {str(e)}")
        return str(timestamp)

# Helper functions
def convert_ip_to_float(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return float(struct.unpack("!I", ip_obj.packed)[0]) if ip_obj.version == 4 else 0.0
    except ValueError:
        return 0.0

protocol_map = {'icmp': 0, 'udp': 1, 'tcp': 2}
flags_map = {'syn': 0, 'ack': 1, 'fin': 2, 'psh': 3}

def convert_protocol(protocol):
    return protocol_map.get(str(protocol).lower(), 0)

def convert_flags(flags):
    return flags_map.get(str(flags).lower(), 0)

recommendations = {
    "Normal": "No immediate action required. Continue monitoring network traffic.",
    "DDoS": "1. Activate DDoS mitigation services\n2. Block suspicious IPs\n3. Increase bandwidth capacity\n4. Notify your ISP",
    "Ransomware": "1. Isolate infected systems\n2. Disconnect from network\n3. Restore from clean backups\n4. Update all security patches",
    "Brute Force": "1. Implement account lockout policy\n2. Enable multi-factor authentication\n3. Change all affected passwords\n4. Monitor login attempts"
}

def get_recommendation(prediction):
    return recommendations.get(prediction, "No specific recommendations available.")

label_map = {0: "Normal", 1: "DDoS", 2: "Ransomware", 3: "Brute Force"}
def get_prediction_label(prediction):
    return label_map.get(prediction, "Unknown")

def convert_to_serializable(obj):
    if isinstance(obj, (np.integer, np.floating)):
        return obj.item()
    if isinstance(obj, (datetime, pd.Timestamp)):
        return obj.isoformat()
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj

# Load ML model
with open("cyberpredict.pkl", 'rb') as model_file:
    model = pickle.load(model_file)

# SSE setup
subscribers = []

def notify_subscribers(prediction, input_method, details=None):
    is_attack = prediction != "Normal"
    new_pred = Prediction(
        input_method=input_method,
        prediction_type=prediction,
        details=json.dumps(details, default=convert_to_serializable),
        is_attack=is_attack
    )
    db.session.add(new_pred)
    db.session.commit()

    # Prepare dashboard data
    counts = {
        'total': Prediction.query.count(),
        'normal': Prediction.query.filter_by(prediction_type="Normal").count(),
        'attacks': Prediction.query.filter_by(is_attack=True).count(),
        'ddos': Prediction.query.filter_by(prediction_type="DDoS").count(),
        'ransomware': Prediction.query.filter_by(prediction_type="Ransomware").count(),
        'brute_force': Prediction.query.filter_by(prediction_type="Brute Force").count()
    }

    recent = [p.serialize() for p in Prediction.query.filter_by(is_attack=True)
        .order_by(Prediction.timestamp.desc())
        .limit(5)
        .all()]

    daily_attacks = db.session.query(
        func.strftime('%Y-%m-%d', Prediction.timestamp).label('day'),
        func.count('*').label('count')
    ).filter(Prediction.is_attack == True
    ).group_by('day'
    ).order_by('day'
    ).all()

    msg = json.dumps({
        'prediction': prediction,
        'counts': counts,
        'recent': recent,
        'daily_attacks': {
            'days': [day.day for day in daily_attacks],
            'counts': [day.count for day in daily_attacks]
        }
    }, default=convert_to_serializable)

    for sub in subscribers[:]:
        try: sub.callback(f"data: {msg}\n\n")
        except: subscribers.remove(sub)

@app.route('/dashboard_updates')
def dashboard_updates():
    def event_stream():
        queue = []
        subscriber = {'callback': lambda msg: queue.append(msg)}
        subscribers.append(subscriber)
        try:
            while True:
                if queue: yield queue.pop(0)
                else: time.sleep(0.1)
        finally:
            if subscriber in subscribers:
                subscribers.remove(subscriber)
    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    counts = {
        'total': Prediction.query.count(),
        'normal': Prediction.query.filter_by(prediction_type="Normal").count(),
        'attacks': Prediction.query.filter_by(is_attack=True).count(),
        'ddos': Prediction.query.filter_by(prediction_type="DDoS").count(),
        'ransomware': Prediction.query.filter_by(prediction_type="Ransomware").count(),
        'brute_force': Prediction.query.filter_by(prediction_type="Brute Force").count()
    }

    recent = [p.serialize() for p in Prediction.query.filter_by(is_attack=True)
        .order_by(Prediction.timestamp.desc())
        .limit(5)
        .all()]

    daily_attacks = db.session.query(
        func.strftime('%Y-%m-%d', Prediction.timestamp).label('day'),
        func.count('*').label('count')
    ).filter(Prediction.is_attack == True
    ).group_by('day'
    ).order_by('day'
    ).all()

    return render_template('dashboard.html',
        counts=counts,
        recent=recent,
        attack_days=[day.day for day in daily_attacks],
        attack_counts=[day.count for day in daily_attacks],
        attack_distribution={
            'DDoS': counts['ddos'],
            'Ransomware': counts['ransomware'],
            'Brute Force': counts['brute_force']
        }
    )

@app.route('/predict_manual', methods=['POST'])
def predict_manual():
    try:
        data = request.get_json()
        features = [
            convert_ip_to_float(data['source_ip']),
            convert_ip_to_float(data['destination_ip']),
            convert_protocol(data['protocol']),
            float(data['packet_length']),
            float(data['duration']),
            float(data['source_port']),
            float(data['destination_port']),
            float(data['bytes_sent']),
            float(data['bytes_received']),
            convert_flags(data['flags']),
            float(data['flow_packets_per_second']),
            float(data['flow_bytes_per_second']),
            float(data['avg_packet_size']),
            float(data['total_fwd_packets']),
            float(data['total_bwd_packets']),
            float(data['fwd_header_length']),
            float(data['bwd_header_length']),
            float(data['sub_flow_fwd_bytes']),
            float(data['sub_flow_bwd_bytes'])
        ]
        prediction = get_prediction_label(model.predict([features])[0])
        notify_subscribers(prediction, "manual", data)
        return jsonify({
            'prediction': prediction,
            'recommendation': get_recommendation(prediction)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/predict_realtime', methods=['POST'])
def predict_realtime():
    try:
        data = request.get_json()
        features = [
            convert_ip_to_float(data['source_ip']),
            convert_ip_to_float(data['destination_ip']),
            convert_protocol(data['protocol']),
            float(data['packet_length']),
            float(data['duration']),
            float(data['source_port']),
            float(data['destination_port']),
            float(data['bytes_sent']),
            float(data['bytes_received']),
            convert_flags(data['flags']),
            float(data['flow_packets_per_second']),
            float(data['flow_bytes_per_second']),
            float(data['avg_packet_size']),
            float(data['total_fwd_packets']),
            float(data['total_bwd_packets']),
            float(data['fwd_header_length']),
            float(data['bwd_header_length']),
            float(data['sub_flow_fwd_bytes']),
            float(data['sub_flow_bwd_bytes'])
        ]
        prediction = get_prediction_label(model.predict([features])[0])
        notify_subscribers(prediction, "realtime", data) # Notify regardless of prediction

        if prediction != "Normal":
            return jsonify({
                'prediction': prediction,
                'recommendation': get_recommendation(prediction)
            })
        return jsonify({'prediction': 'Normal', 'status': 'logged'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/preview_csv', methods=['POST'])
def preview_csv():
    if 'csv_file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['csv_file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    try:
        df = pd.read_csv(file, nrows=5)
        return jsonify({
            'preview': df.to_dict('records'),
            'columns': df.columns.tolist(),
            'model_columns': [
                'source_ip', 'destination_ip', 'protocol', 'packet_length', 'duration',
                'source_port', 'destination_port', 'bytes_sent', 'bytes_received', 'flags',
                'flow_packets_per_second', 'flow_bytes_per_second', 'avg_packet_size',
                'total_fwd_packets', 'total_bwd_packets', 'fwd_header_length',
                'bwd_header_length', 'sub_flow_fwd_bytes', 'sub_flow_bwd_bytes'
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/process_csv', methods=['POST'])
def process_csv():
    try:
        if 'csv_file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['csv_file']
        column_mapping = json.loads(request.form.get('column_mapping'))
        
        df = pd.read_csv(file).rename(columns=column_mapping)
        df = df[[col for col in column_mapping.values() if col in df.columns]]
        
        # Convert features
        conversion_functions = {
            'source_ip': convert_ip_to_float,
            'destination_ip': convert_ip_to_float,
            'protocol': convert_protocol,
            'flags': convert_flags
        }
        
        for col, func in conversion_functions.items():
            if col in df.columns:
                df[col] = df[col].apply(func)
        
        # Convert numeric columns
        numeric_cols = [col for col in df.columns if col not in conversion_functions]
        df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric, errors='coerce')
        df = df.dropna()
        
        if df.empty:
            return jsonify({'error': 'No valid records after processing'}), 400
        
        predictions = model.predict(df.values)
        df['prediction'] = [get_prediction_label(p) for p in predictions]
        df['recommendation'] = df['prediction'].apply(get_recommendation)
        
        return jsonify({
            'stats': {
                'total_records': len(df),
                'normal_count': int(sum(df['prediction'] == 'Normal')),
                'attack_count': int(sum(df['prediction'] != 'Normal')),
                'attack_types': df[df['prediction'] != 'Normal']['prediction'].value_counts().astype(int).to_dict()
            },
            'sample_results': df.head().applymap(convert_to_serializable).to_dict('records'),
            'all_results': df.applymap(convert_to_serializable).to_dict('records')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/export_results', methods=['POST'])
def export_results():
    try:
        data = request.get_json()
        if not data or 'results' not in data:
            return jsonify({'error': 'No results data provided'}), 400
        
        df = pd.DataFrame(data['results'])
        output = BytesIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'predictions_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/prediction')
def prediction():
    return render_template('prediction.html')

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)