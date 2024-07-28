

import joblib
from tensorflow.keras.models import load_model

# Load the trained anomaly detection model (stacking ensemble)
anomaly_model = joblib.load('/Users/kcann/Desktop/IDS_CAPSTONE/stacking_ensemble_model.joblib')

# Load the trained malware detection model (Keras model)
malware_model = load_model('/Users/kcann/Desktop/IDS_CAPSTONE/malware_detection_model-2.keras')

print("Models loaded successfully")
