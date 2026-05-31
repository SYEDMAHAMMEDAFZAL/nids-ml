#!/usr/bin/env python3
"""
NIDS - Real Time Detector
Author: S.Md.Afzal
GitHub: github.com/SYEDMAHAMMEDAFZAL
"""

import pickle
import random
import time
import datetime
import json
import os
import numpy as np

with open('model/nids_model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('model/features.pkl', 'rb') as f:
    features = pickle.load(f)

ATTACK_TYPES = {
    (1000, 65535, 1): 'PORT SCAN',
    (22, 1,    1):    'BRUTE FORCE',
    (80, 1,    1):    'DDoS',
    (4444, 0,  0):    'BACKDOOR',
}

def classify_attack(sample):
    port = sample['port_dst']
    syn  = sample['flag_syn']
    pps  = sample['packets_per_sec']
    if pps > 500:    return 'DDoS ATTACK'
    if port > 1024 and syn == 1 and sample['connections'] > 50: return 'PORT SCAN'
    if port in [22,21,3389,3306] and syn == 1: return 'BRUTE FORCE'
    if port in [4444,1234,9999,6666]: return 'BACKDOOR / REVERSE SHELL'
    return 'UNKNOWN ATTACK'

def simulate_traffic():
    is_attack = random.random() > 0.5
    if not is_attack:
        return {
            'duration':        round(random.uniform(0,2), 3),
            'packet_size':     round(random.uniform(40,1500), 1),
            'packets_per_sec': round(random.uniform(1,50), 2),
            'bytes_per_sec':   round(random.uniform(100,50000), 2),
            'port_dst':        random.choice([80,443,53,8080]),
            'protocol':        random.choice([6,17]),
            'flag_syn':        0,
            'flag_rst':        0,
            'connections':     random.randint(1,10),
        }, False
    else:
        attack = random.choice(['scan','brute','ddos','back'])
        if attack == 'scan':
            return {'duration':0.05,'packet_size':60,'packets_per_sec':500,
                    'bytes_per_sec':30000,'port_dst':random.randint(1,65535),
                    'protocol':6,'flag_syn':1,'flag_rst':1,'connections':200}, True
        elif attack == 'brute':
            return {'duration':0.3,'packet_size':120,'packets_per_sec':100,
                    'bytes_per_sec':12000,'port_dst':random.choice([22,3389,21]),
                    'protocol':6,'flag_syn':1,'flag_rst':0,'connections':80}, True
        elif attack == 'ddos':
            return {'duration':0.01,'packet_size':50,'packets_per_sec':5000,
                    'bytes_per_sec':250000,'port_dst':80,
                    'protocol':6,'flag_syn':1,'flag_rst':0,'connections':2000}, True
        else:
            return {'duration':50,'packet_size':70,'packets_per_sec':0.5,
                    'bytes_per_sec':35,'port_dst':4444,
                    'protocol':6,'flag_syn':0,'flag_rst':0,'connections':2}, True

def run_detection(count=50):
    os.makedirs('detections', exist_ok=True)
    results = []
    print('\n[*] Starting NIDS Detection Engine...\n')

    for i in range(count):
        sample, is_attack = simulate_traffic()
        X = [[sample[f] for f in features]]
        prediction = model.predict(X)[0]
        confidence = max(model.predict_proba(X)[0]) * 100

        label = 'ATTACK' if prediction == 1 else 'NORMAL'
        attack_type = classify_attack(sample) if prediction == 1 else 'N/A'
        severity = ('CRITICAL' if attack_type in ['DDoS ATTACK','BACKDOOR / REVERSE SHELL']
                    else 'HIGH' if attack_type == 'BRUTE FORCE'
                    else 'MEDIUM' if attack_type == 'PORT SCAN'
                    else 'INFO')

        result = {
            'timestamp':   datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'label':       label,
            'attack_type': attack_type,
            'severity':    severity,
            'confidence':  round(confidence, 2),
            'port_dst':    sample['port_dst'],
            'pps':         sample['packets_per_sec'],
            'connections': sample['connections'],
        }
        results.append(result)

        if prediction == 1:
            print(f"[!] {result['timestamp']}  {attack_type:<28}  "
                  f"{severity:<10}  Conf: {confidence:.1f}%  Port: {sample['port_dst']}")
        else:
            print(f"[✓] {result['timestamp']}  NORMAL TRAFFIC               "
                  f"INFO        Conf: {confidence:.1f}%")
        time.sleep(0.05)

    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = f'detections/nids_{ts}.json'
    with open(path, 'w') as f:
        json.dump(results, f, indent=2)

    attacks = [r for r in results if r['label'] == 'ATTACK']
    print(f'\n[+] Detected {len(attacks)}/{count} attacks → saved to {path}')
    return results

if __name__ == '__main__':
    run_detection(50)
