"""
Sayanox Sentinel OS - Anomaly Detection Service
ML-powered anomaly detection using Isolation Forest for system metrics.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import deque
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

logger = logging.getLogger(__name__)


class AnomalyDetectionService:
    """
    ML-powered anomaly detection service using Isolation Forest.
    Learns normal system behavior and flags deviations in real-time.
    """
    
    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.metrics_buffer: deque = deque(maxlen=1000)  # Store last 1000 samples
        self.is_trained: bool = False
        self.min_samples_for_training: int = 100
        self.contamination_rate: float = 0.1
        self.anomaly_threshold: float = -0.5  # Lower = more anomalous
        
        # Feature names for logging
        self.feature_names = [
            'cpu_percent',
            'memory_percent', 
            'disk_io_read',
            'disk_io_write',
            'net_bytes_sent',
            'net_bytes_recv',
            'process_count'
        ]
        
        # Anomaly history
        self.anomaly_history: deque = deque(maxlen=500)
        self.baseline_stats: Dict[str, float] = {}
        
        # Model persistence path
        self.model_path = "/app/data/anomaly_model.pkl"
        self.stats_path = "/app/data/baseline_stats.npy"
        
        # Load existing model if available
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained model if available."""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.stats_path):
                self.model = joblib.load(self.model_path)
                self.baseline_stats = np.load(self.stats_path, allow_pickle=True).item()
                self.is_trained = True
                logger.info("Loaded pre-trained anomaly detection model")
        except Exception as e:
            logger.warning(f"Could not load existing model: {e}")
    
    def _save_model(self):
        """Save trained model to disk."""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            if self.model:
                joblib.dump(self.model, self.model_path)
            if self.baseline_stats:
                np.save(self.stats_path, self.baseline_stats)
            logger.info("Saved anomaly detection model")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def add_sample(self, metrics: Dict[str, float]) -> None:
        """Add a new metrics sample to the buffer."""
        sample = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': metrics.get('cpu_percent', 0),
            'memory_percent': metrics.get('memory_percent', 0),
            'disk_io_read': metrics.get('disk_io_read', 0),
            'disk_io_write': metrics.get('disk_io_write', 0),
            'net_bytes_sent': metrics.get('net_bytes_sent', 0),
            'net_bytes_recv': metrics.get('net_bytes_recv', 0),
            'process_count': metrics.get('process_count', 0)
        }
        self.metrics_buffer.append(sample)
        
        # Update baseline stats periodically
        if len(self.metrics_buffer) % 50 == 0:
            self._update_baseline_stats()
    
    def _update_baseline_stats(self):
        """Update baseline statistics from current buffer."""
        if len(self.metrics_buffer) < 10:
            return
            
        data = list(self.metrics_buffer)
        for feature in self.feature_names:
            values = [d[feature] for d in data if feature in d]
            if values:
                self.baseline_stats[f'{feature}_mean'] = float(np.mean(values))
                self.baseline_stats[f'{feature}_std'] = float(np.std(values))
                self.baseline_stats[f'{feature}_min'] = float(np.min(values))
                self.baseline_stats[f'{feature}_max'] = float(np.max(values))
    
    def _prepare_features(self, sample: Dict) -> np.ndarray:
        """Convert sample dict to feature array."""
        return np.array([
            sample.get('cpu_percent', 0),
            sample.get('memory_percent', 0),
            sample.get('disk_io_read', 0),
            sample.get('disk_io_write', 0),
            sample.get('net_bytes_sent', 0),
            sample.get('net_bytes_recv', 0),
            sample.get('process_count', 0)
        ]).reshape(1, -1)
    
    def train_model(self) -> bool:
        """Train the Isolation Forest model on collected samples."""
        if len(self.metrics_buffer) < self.min_samples_for_training:
            logger.info(f"Need {self.min_samples_for_training - len(self.metrics_buffer)} more samples for training")
            return False
        
        try:
            # Prepare training data
            data = list(self.metrics_buffer)
            X = np.array([self._prepare_features(d).flatten() for d in data])
            
            # Fit scaler
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination_rate,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_scaled)
            
            self.is_trained = True
            self._save_model()
            
            logger.info(f"Trained anomaly detection model on {len(X)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Failed to train model: {e}")
            return False
    
    def detect_anomaly(self, metrics: Dict[str, float]) -> Tuple[bool, float, Dict]:
        """
        Detect if current metrics represent an anomaly.
        
        Returns:
            Tuple of (is_anomaly, anomaly_score, details)
        """
        if not self.is_trained:
            # If not trained, use simple threshold-based detection
            return self._simple_threshold_detection(metrics)
        
        try:
            # Prepare features
            X = self._prepare_features(metrics)
            X_scaled = self.scaler.transform(X)
            
            # Get anomaly score (-1 for anomaly, 1 for normal)
            prediction = self.model.predict(X_scaled)[0]
            
            # Get anomaly score (more negative = more anomalous)
            anomaly_score = self.model.score_samples(X_scaled)[0]
            
            is_anomaly = prediction == -1 or anomaly_score < self.anomaly_threshold
            
            # Generate details
            details = {
                'anomaly_score': float(anomaly_score),
                'threshold': self.anomaly_threshold,
                'is_trained': True,
                'deviations': self._calculate_deviations(metrics)
            }
            
            if is_anomaly:
                self._log_anomaly(metrics, anomaly_score, details)
            
            return is_anomaly, float(anomaly_score), details
            
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return False, 0.0, {'error': str(e)}
    
    def _simple_threshold_detection(self, metrics: Dict[str, float]) -> Tuple[bool, float, Dict]:
        """Fallback threshold-based detection when model is not trained."""
        anomalies = []
        max_deviation = 0
        
        thresholds = {
            'cpu_percent': 90,
            'memory_percent': 90,
            'disk_io_read': 100_000_000,  # 100 MB/s
            'disk_io_write': 100_000_000,
            'net_bytes_sent': 50_000_000,  # 50 MB/s
            'net_bytes_recv': 50_000_000
        }
        
        for feature, threshold in thresholds.items():
            value = metrics.get(feature, 0)
            if value > threshold:
                anomalies.append(feature)
                deviation = (value - threshold) / threshold
                max_deviation = max(max_deviation, deviation)
        
        is_anomaly = len(anomalies) > 0
        details = {
            'anomaly_score': -max_deviation if is_anomaly else 0,
            'threshold': 'static',
            'is_trained': False,
            'anomalies': anomalies,
            'deviations': self._calculate_deviations(metrics)
        }
        
        return is_anomaly, -max_deviation if is_anomaly else 0.0, details
    
    def _calculate_deviations(self, metrics: Dict[str, float]) -> Dict[str, float]:
        """Calculate how much each metric deviates from baseline."""
        deviations = {}
        for feature in self.feature_names:
            value = metrics.get(feature, 0)
            mean_key = f'{feature}_mean'
            std_key = f'{feature}_std'
            
            if mean_key in self.baseline_stats and std_key in self.baseline_stats:
                mean = self.baseline_stats[mean_key]
                std = self.baseline_stats[std_key]
                if std > 0:
                    z_score = (value - mean) / std
                    deviations[f'{feature}_zscore'] = float(z_score)
        
        return deviations
    
    def _log_anomaly(self, metrics: Dict[str, float], score: float, details: Dict):
        """Log detected anomaly to history."""
        anomaly_record = {
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics,
            'score': float(score),
            'details': details
        }
        self.anomaly_history.append(anomaly_record)
        logger.warning(f"Anomaly detected: score={score:.4f}, deviations={details.get('deviations', {})}")
    
    def get_anomaly_history(self, limit: int = 50) -> List[Dict]:
        """Get recent anomaly history."""
        return list(self.anomaly_history)[-limit:]
    
    def get_baseline_stats(self) -> Dict[str, float]:
        """Get current baseline statistics."""
        return self.baseline_stats.copy()
    
    def get_training_status(self) -> Dict:
        """Get model training status."""
        return {
            'is_trained': self.is_trained,
            'samples_collected': len(self.metrics_buffer),
            'min_samples_required': self.min_samples_for_training,
            'training_progress': min(100, len(self.metrics_buffer) / self.min_samples_for_training * 100),
            'anomalies_detected': len(self.anomaly_history),
            'baseline_stats': self.baseline_stats
        }
    
    def reset_model(self) -> bool:
        """Reset the model and retrain from scratch."""
        try:
            self.model = None
            self.scaler = None
            self.is_trained = False
            self.anomaly_history.clear()
            
            # Remove saved model files
            if os.path.exists(self.model_path):
                os.remove(self.model_path)
            if os.path.exists(self.stats_path):
                os.remove(self.stats_path)
            
            logger.info("Model reset successfully")
            
            # Attempt to retrain if we have enough samples
            return self.train_model()
            
        except Exception as e:
            logger.error(f"Failed to reset model: {e}")
            return False


# Global instance
anomaly_detector = AnomalyDetectionService()


async def background_training_loop(interval: int = 300):
    """Background task to periodically retrain the model."""
    while True:
        await asyncio.sleep(interval)
        if len(anomaly_detector.metrics_buffer) >= anomaly_detector.min_samples_for_training:
            logger.info("Running periodic model retraining...")
            anomaly_detector.train_model()


async def background_metrics_feeder(metrics_collector):
    """Feed metrics from collector to anomaly detector."""
    while True:
        try:
            # Get latest metrics
            metrics = await metrics_collector.get_latest_metrics()
            if metrics:
                anomaly_detector.add_sample(metrics)
                
                # Try to train if we have enough samples and model not trained
                if not anomaly_detector.is_trained:
                    anomaly_detector.train_model()
        except Exception as e:
            logger.error(f"Error feeding metrics to anomaly detector: {e}")
        
        await asyncio.sleep(5)  # Feed every 5 seconds
