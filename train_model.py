#!/usr/bin/env python3
"""
NIDS - ML Model Trainer
Author: S.Md.Afzal
GitHub: github.com/SYEDMAHAMMEDAFZAL
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

def generate_training_data(samples=2000):
    np.random.seed(42)
    data = []

    # Normal traffic
    for _ in range(samples // 2):
        data.append({
            'duration':        np.random.uniform(0, 2),
            'packet_size':     np.random.uniform(40, 1500),
            'packets_per_sec': np.random.uniform(1, 50),
            'bytes_per_sec':   np.random.uniform(100, 50000),
            'port_dst':        np.random.choice([80, 443, 53, 8080]),
            'protocol':        np.random.choice([6, 17]),
            'flag_syn':        0,
            'flag_rst':        0,
            'connections':     np.random.randint(1, 10),
            'label':           0  # Normal
        })

    # Attack traffic
    attack_types = ['portscan', 'bruteforce', 'ddos', 'backdoor']
    for _ in range(samples // 2):
        attack = np.random.choice(attack_types)
        if attack == 'portscan':
            data.append({
                'duration':        np.random.uniform(0, 0.1),
                'packet_size':     np.random.uniform(40, 80),
                'packets_per_sec': np.random.uniform(100, 1000),
                'bytes_per_sec':   np.random.uniform(4000, 80000),
                'port_dst':        np.random.randint(1, 65535),
                'protocol':        6,
                'flag_syn':        1,
                'flag_rst':        1,
                'connections':     np.random.randint(50, 500),
                'label':           1
            })
        elif attack == 'bruteforce':
            data.append({
                'duration':        np.random.uniform(0, 0.5),
                'packet_size':     np.random.uniform(60, 200),
                'packets_per_sec': np.random.uniform(50, 200),
                'bytes_per_sec':   np.random.uniform(3000, 40000),
                'port_dst':        np.random.choice([22, 3389, 21, 3306]),
                'protocol':        6,
                'flag_syn':        1,
                'flag_rst':        0,
                'connections':     np.random.randint(20, 200),
                'label':           1
            })
        elif attack == 'ddos':
            data.append({
                'duration':        np.random.uniform(0, 0.01),
                'packet_size':     np.random.uniform(40, 60),
                'packets_per_sec': np.random.uniform(1000, 10000),
                'bytes_per_sec':   np.random.uniform(40000, 600000),
                'port_dst':        np.random.choice([80, 443]),
                'protocol':        np.random.choice([6, 17]),
                'flag_syn':        1,
                'flag_rst':        0,
                'connections':     np.random.randint(500, 5000),
                'label':           1
            })
        else:  # backdoor
            data.append({
                'duration':        np.random.uniform(10, 100),
                'packet_size':     np.random.uniform(40, 100),
                'packets_per_sec': np.random.uniform(0.1, 2),
                'bytes_per_sec':   np.random.uniform(10, 200),
                'port_dst':        np.random.choice([4444, 1234, 9999, 6666]),
                'protocol':        6,
                'flag_syn':        0,
                'flag_rst':        0,
                'connections':     np.random.randint(1, 5),
                'label':           1
            })

    return pd.DataFrame(data)

def train():
    print('[*] Generating training data...')
    df = generate_training_data(2000)

    features = ['duration','packet_size','packets_per_sec',
                'bytes_per_sec','port_dst','protocol',
                'flag_syn','flag_rst','connections']
    X = df[features]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42)

    print('[*] Training Random Forest model...')
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f'\n[+] Model Accuracy: {acc*100:.2f}%')
    print('\n[+] Classification Report:')
    print(classification_report(y_test, y_pred,
          target_names=['Normal', 'Attack']))

    os.makedirs('model', exist_ok=True)
    with open('model/nids_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    with open('model/features.pkl', 'wb') as f:
        pickle.dump(features, f)

    print('[✓] Model saved to model/nids_model.pkl')

if __name__ == '__main__':
    train()
