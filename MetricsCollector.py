import pandas as pd
import time
from Config import *

class MetricsCollector:
    def __init__(self):
        self.results = []
    
    def record_attempt(self, username, protections, result, latency_ms):
        self.results.append({
            'timestamp': time.time(),
            'group_seed': GROUP_SEED,
            'username': username,
            'hash_mode': protections.get('hash_mode', False),
            'rate_limiting': protections.get('rate_limiting', False),
            'lockout': protections.get('lockout', False),
            'captcha': protections.get('captcha', False),
            'totp': protections.get('totp', False),
            'result': result,
            'latency_ms': latency_ms
        })
    
    def save_to_csv(self, filename='attempts.csv'):
        df = pd.DataFrame(self.results)
        df.to_csv(filename, index=False)
    
    def get_stats(self):
        df = pd.DataFrame(self.results)
        return {
            'total_attempts': len(df),
            'success_rate': (df['result'] == 'OK').mean(),
            'avg_latency_ms': df['latency_ms'].mean(),
            'attempts_per_sec': len(df) / (df['timestamp'].max() - df['timestamp'].min())
        }