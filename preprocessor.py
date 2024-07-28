import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import VarianceThreshold
from tensorflow.keras.utils import to_categorical


class Preprocessor:
    def __init__(self):
        self.label_encoder = LabelEncoder()
        self.preprocessor = None
        self.selector = None
        self.scaler = StandardScaler()
        self.num_classes = None
        self.feature_names = None
        self.selected_features = None

    def fit(self, training_data, testing_data):
        combined_labels = pd.concat([training_data['labels'], testing_data['labels']])
        self.label_encoder.fit(combined_labels)
        self.num_classes = len(np.unique(combined_labels))

        categorical_features = training_data.select_dtypes(include=['object']).columns
        numeric_features = training_data.select_dtypes(exclude=['object']).columns.difference(['labels'])

        self.preprocessor = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), numeric_features),
                ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_features)
            ])
        self.preprocessor.fit(training_data.drop(columns=['labels']))

        self.feature_names = (self.preprocessor.named_transformers_['cat'].get_feature_names_out(categorical_features).tolist() +
                              numeric_features.tolist())

        X_train_combined = self.preprocessor.transform(training_data.drop(columns=['labels']))
        self.selector = VarianceThreshold(threshold=0.01)
        self.selector.fit(X_train_combined)
        self.selected_features = np.array(self.feature_names)[self.selector.get_support()]

        X_train_selected = self.selector.transform(X_train_combined)
        self.scaler.fit(X_train_selected)

    def transform(self, data):
        if 'labels' not in data.columns:
            data['labels'] = 'unknown'

        labels = self.label_encoder.transform(data['labels'])
        labels_categorical = to_categorical(labels, num_classes=self.num_classes)

        X_combined = self.preprocessor.transform(data.drop(columns=['labels']))
        X_selected = self.selector.transform(X_combined)
        X_scaled = self.scaler.transform(X_selected)

        return X_scaled, labels_categorical

    def process_packet(self, packet):
        packet_df = self.packet_to_dataframe(packet)
        X, _ = self.transform(packet_df)
        return X

    def packet_to_dataframe(self, packet):
        data = {
            'duration': [packet.duration],
            'protocol_type': [packet.protocol],
            'service': [packet.service],
            'flag': [packet.flag],
            'src_bytes': [packet.src_bytes],
            'dst_bytes': [packet.dst_bytes],
            'wrong_fragment': [packet.wrong_fragment],
            'urgent': [packet.urgent],
            'hot': [packet.hot],
            'num_failed_logins': [packet.num_failed_logins],
            'logged_in': [packet.logged_in],
            'num_compromised': [packet.num_compromised],
            'root_shell': [packet.root_shell],
            'su_attempted': [packet.su_attempted],
            'num_root': [packet.num_root],
            'num_file_creations': [packet.num_file_creations],
            'num_shells': [packet.num_shells],
            'num_access_files': [packet.num_access_files],
            'num_outbound_cmds': [packet.num_outbound_cmds],
            'is_host_login': [packet.is_host_login],
            'is_guest_login': [packet.is_guest_login],
            'count': [packet.count],
            'srv_count': [packet.srv_count],
            'serror_rate': [packet.serror_rate],
            'srv_serror_rate': [packet.srv_serror_rate],
            'rerror_rate': [packet.rerror_rate],
            'srv_rerror_rate': [packet.srv_rerror_rate],
            'same_srv_rate': [packet.same_srv_rate],
            'diff_srv_rate': [packet.diff_srv_rate],
            'srv_diff_host_rate': [packet.srv_diff_host_rate],
            'dst_host_count': [packet.dst_host_count],
            'dst_host_srv_count': [packet.dst_host_srv_count],
            'dst_host_same_srv_rate': [packet.dst_host_same_srv_rate],
            'dst_host_diff_srv_rate': [packet.dst_host_diff_srv_rate],
            'dst_host_same_src_port_rate': [packet.dst_host_same_src_port_rate],
            'dst_host_srv_diff_host_rate': [packet.dst_host_srv_diff_host_rate],
            'dst_host_serror_rate': [packet.dst_host_serror_rate],
            'dst_host_srv_serror_rate': [packet.dst_host_srv_serror_rate],
            'dst_host_rerror_rate': [packet.dst_host_rerror_rate],
            'dst_host_srv_rerror_rate': [packet.dst_host_srv_rerror_rate],
        }
        return pd.DataFrame(data)
  