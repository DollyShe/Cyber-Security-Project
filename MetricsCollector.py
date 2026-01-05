import pandas as pd
from datetime import datetime
from Config import *

class MetricsCollector:
    def __init__(self):
        self.results = []
    
    def record_attempt(self, username, protections, result, latency_ms):
        self.results.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3],
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

        # Convert string timestamps → datetime
        df['timestamp'] = pd.to_datetime(
            df['timestamp'],
            format="%Y-%m-%d %H:%M:%S,%f"
        )
        duration_sec = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
        stats = "========== Overall Statistics ==========\n"
        stats += f"total_attempts: {len(df)}\n"
        stats += f"success_rate: {(df['result'] == 'OK').mean()}\n"
        stats += f"avg_latency_ms: {df['latency_ms'].mean()}\n"
        stats += f"attempts_per_sec: {len(df) / duration_sec if duration_sec > 0 else 0}"
        return stats