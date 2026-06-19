# Deep Technical Procedures

## Behavioral Feature Engineering

```python
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def extract_behavioral_features(logs_df):
    features = pd.DataFrame(index=logs_df['user'].unique())
    
    # Temporal features
    user_logins = logs_df.groupby('user')['timestamp'].apply(list)
    features['login_hour_entropy'] = user_logins.apply(
        lambda x: -sum((pd.Series([t.hour for t in x]).value_counts(normalize=True) * 
                       np.log(pd.Series([t.hour for t in x]).value_counts(normalize=True))).fillna(0))
    )
    
    # Volume features
    features['login_count'] = logs_df.groupby('user').size()
    features['unique_locations'] = logs_df.groupby('user')['location'].nunique()
    features['unique_devices'] = logs_df.groupby('user')['device_id'].nunique()
    
    # Risk features
    features['failed_login_ratio'] = (
        logs_df[logs_df['status'] == 'FAILED'].groupby('user').size() /
        features['login_count']
    ).fillna(0)
    
    # Off-hours activity
    features['off_hours_ratio'] = (
        logs_df[logs_df['timestamp'].dt.hour.isin(range(0, 6))].groupby('user').size() /
        features['login_count']
    ).fillna(0)
    
    return features
```

## Anomaly Detection Model

```python
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class UEBAAnomalyDetector:
    def __init__(self, contamination=0.01):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=200,
            max_samples='auto'
        )
        self.scaler = StandardScaler()
        
    def fit(self, features):
        scaled = self.scaler.fit_transform(features)
        self.model.fit(scaled)
        
    def predict(self, features):
        scaled = self.scaler.transform(features)
        scores = self.model.score_samples(scaled)
        labels = self.model.predict(scaled)
        return {'anomaly_score': -scores, 'is_anomaly': labels == -1}
```

## Statistical Outlier Detection

```python
def modified_z_score_outlier_detection(df, column, threshold=3.5):
    median = df[column].median()
    mad = np.median(np.abs(df[column] - median))
    modified_z = 0.6745 * (df[column] - median) / mad
    df['z_score'] = modified_z
    df['is_outlier'] = np.abs(modified_z) > threshold
    return df[df['is_outlier']]
```
