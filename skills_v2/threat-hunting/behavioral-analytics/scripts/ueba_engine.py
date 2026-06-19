#!/usr/bin/env python3
"""User and Entity Behavioral Analytics Engine"""
import json
import argparse
import pandas as pd
import numpy as np
from datetime import datetime

class UEBAEngine:
    def __init__(self, log_file):
        self.logs = pd.read_csv(log_file, parse_dates=['timestamp']) if log_file else pd.DataFrame()
        self.baselines = {}
        self.anomalies = []

    def build_baseline(self, days=30):
        cutoff = pd.Timestamp.now() - pd.Timedelta(days=days)
        historical = self.logs[self.logs['timestamp'] >= cutoff]
        
        for user in historical['user'].unique():
            user_data = historical[historical['user'] == user]
            login_hours = user_data['timestamp'].dt.hour
            
            self.baselines[user] = {
                'mean_hour': login_hours.mean(),
                'std_hour': login_hours.std(),
                'mean_logins_per_day': user_data.groupby(user_data['timestamp'].dt.date).size().mean(),
                'std_logins_per_day': user_data.groupby(user_data['timestamp'].dt.date).size().std(),
                'common_locations': user_data['location'].value_counts().head(5).to_dict(),
                'common_devices': user_data['device_id'].value_counts().head(5).to_dict()
            }

    def score_activity(self, user, timestamp, location, device_id, event_type):
        base = self.baselines.get(user)
        if not base:
            return {'score': 0.5, 'reason': 'No baseline established'}
        
        hour = pd.Timestamp(timestamp).hour
        score = 0.0
        reasons = []
        
        hour_z = abs(hour - base['mean_hour']) / (base['std_hour'] or 1)
        if hour_z > 2:
            score += 0.3 * min(hour_z / 4, 1)
            reasons.append(f"Unusual hour (z={hour_z:.2f})")
        
        if location not in base['common_locations']:
            score += 0.25
            reasons.append(f"New location: {location}")
        
        if device_id and str(device_id) not in base['common_devices']:
            score += 0.15
            reasons.append(f"New device: {device_id}")
        
        return {'score': min(score, 1.0), 'reasons': reasons}

    def analyze_session(self, session_data):
        user = session_data['user']
        score_result = self.score_activity(
            user, session_data['timestamp'],
            session_data.get('location', 'unknown'),
            session_data.get('device_id', 'unknown'),
            session_data.get('event_type', 'login')
        )
        
        if score_result['score'] > 0.7:
            self.anomalies.append({
                'user': user,
                'timestamp': session_data['timestamp'],
                'risk_score': score_result['score'],
                'reasons': score_result['reasons'],
                'details': session_data
            })

    def run(self):
        self.build_baseline()
        for _, session in self.logs.iterrows():
            self.analyze_session(session.to_dict())
        return json.dumps(self.anomalies, indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-file', required=True)
    args = parser.parse_args()
    engine = UEBAEngine(args.log_file)
    print(engine.run())
