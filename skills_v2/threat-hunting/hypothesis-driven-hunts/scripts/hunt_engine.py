#!/usr/bin/env python3
"""Hypothesis-Driven Threat Hunting Engine"""
import json
import argparse
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

class HuntEngine:
    def __init__(self, hypothesis_file):
        with open(hypothesis_file) as f:
            self.hypothesis = json.load(f)
        self.findings = []

    def t_statistic_test(self, sample, population_mean, population_std, n):
        from scipy import stats
        se = population_std / np.sqrt(n)
        t_stat = (np.mean(sample) - population_mean) / se
        p_value = 2 * (1 - stats.t.cdf(abs(t_stat), df=n-1))
        return {'t_stat': t_stat, 'p_value': p_value, 'significant': p_value < 0.05}

    def evaluate_hypothesis(self, observed_data, baseline_data):
        baseline_mean = np.mean(baseline_data)
        baseline_std = np.std(baseline_data)
        n = len(observed_data)
        result = self.t_statistic_test(observed_data, baseline_mean, baseline_std, n)
        alert_count = sum(
            1 for x in observed_data
            if abs(x - baseline_mean) > 3 * baseline_std
        )
        self.findings.append({
            'hypothesis_id': self.hypothesis['hypothesis_id'],
            'adversary': self.hypothesis['adversary'],
            'statistical_significance': result['significant'],
            'p_value': result['p_value'],
            'alert_count': int(alert_count),
            'total_observations': int(n),
            'anomaly_rate': round(alert_count / n * 100, 2) if n > 0 else 0
        })

    def generate_report(self):
        return pd.DataFrame(self.findings).to_json(orient='records', indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hypothesis', required=True)
    parser.add_argument('--observed', required=True)
    parser.add_argument('--baseline', required=True)
    args = parser.parse_args()
    engine = HuntEngine(args.hypothesis)
    obs = pd.read_csv(args.observed)
    base = pd.read_csv(args.baseline)
    engine.evaluate_hypothesis(obs.values.flatten(), base.values.flatten())
    print(engine.generate_report())
