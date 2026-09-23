"""
ML-Powered Anomaly Detection Module for Sayanox Sentinel OS
Phase 4 Enterprise Upgrade: Uses Isolation Forest to detect behavioral anomalies in system metrics
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Machine Learning-based anomaly detector using Isolation Forest.
    Learns normal system behavior and flags deviations in real-time.
    """
    
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100):
        """
        Initialize the anomaly detector.
        
        Args:
            contamination: Expected proportion of anomalies in the dataset (0-0.5)
            n_estimators: Number of isolation trees in the forest
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model: Optional[IsolationForest] = None
        self.training_data: List[Dict[str, float]] = []
        self.feature_keys = [
            'cpu_percent',
            'memory_percent', 
            'disk_usage_percent',
            'process_count'
        ]
        self.is_trained = False
        self.anomaly_threshold = -0.5  # Score below this is considered anomalous
        
    def _extract_features(self, metrics: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from metrics dictionary."""
        return np.array([
            metrics.get('cpu_percent', 0),
            metrics.get('memory_percent', 0),
            metrics.get('disk_usage_percent', 0),
            metrics.get('process_count', 0)
        ])
    
    def add_sample(self, metrics: Dict[str, Any]):
        """
        Add a sample to the training data buffer.
        
        Args:
            metrics: System metrics dictionary
        """
        self.training_data.append(metrics)
        
        # Keep only last 1000 samples for training efficiency
        if len(self.training_data) > 1000:
            self.training_data = self.training_data[-1000:]
    
    def train(self, min_samples: int = 50) -> bool:
        """
        Train the Isolation Forest model on collected samples.
        
        Args:
            min_samples: Minimum number of samples required for training
            
        Returns:
            bool: True if training was successful
        """
        if len(self.training_data) < min_samples:
            logger.warning(f"Not enough samples for training: {len(self.training_data)} < {min_samples}")
            return False
        
        try:
            # Extract feature matrix
            X = np.array([self._extract_features(m) for m in self.training_data])
            
            # Handle any NaN values
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Train Isolation Forest
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X)
            self.is_trained = True
            
            logger.info(f"Anomaly detection model trained on {len(self.training_data)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Error training anomaly detection model: {e}")
            return False
    
    def detect_anomaly(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect if the current metrics represent an anomaly.
        
        Args:
            metrics: Current system metrics
            
        Returns:
            Dictionary with anomaly detection results
        """
        result = {
            'is_anomaly': False,
            'anomaly_score': 0.0,
            'severity': 'normal',
            'timestamp': datetime.utcnow().isoformat(),
            'details': {}
        }
        
        if not self.is_trained:
            # Attempt auto-training if we have enough data
            if len(self.training_data) >= 50:
                self.train()
            else:
                result['details']['status'] = 'model_not_trained'
                return result
        
        try:
            # Extract features
            X = self._extract_features(metrics).reshape(1, -1)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Get anomaly score (-1 for anomaly, 1 for normal)
            prediction = self.model.predict(X)[0]
            
            # Get decision function score (more negative = more anomalous)
            score = self.model.decision_function(X)[0]
            
            result['anomaly_score'] = float(score)
            result['is_anomaly'] = prediction == -1
            
            # Determine severity based on score
            if score < -0.7:
                result['severity'] = 'critical'
            elif score < -0.5:
                result['severity'] = 'high'
            elif score < -0.3:
                result['severity'] = 'medium'
            elif score < 0:
                result['severity'] = 'low'
            else:
                result['severity'] = 'normal'
            
            # Add detailed analysis
            result['details'] = {
                'cpu_percent': metrics.get('cpu_percent', 0),
                'memory_percent': metrics.get('memory_percent', 0),
                'disk_usage_percent': metrics.get('disk_usage_percent', 0),
                'process_count': metrics.get('process_count', 0),
                'model_confidence': abs(score)
            }
            
            if result['is_anomaly']:
                logger.warning(
                    f"ANOMALY DETECTED! Score: {score:.4f}, Severity: {result['severity']}"
                )
            
        except Exception as e:
            logger.error(f"Error detecting anomaly: {e}")
            result['details']['error'] = str(e)
        
        return result
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get current status of the anomaly detection model."""
        return {
            'is_trained': self.is_trained,
            'training_samples': len(self.training_data),
            'contamination': self.contamination,
            'n_estimators': self.n_estimators,
            'feature_keys': self.feature_keys,
            'anomaly_threshold': self.anomaly_threshold
        }
    
    def reset(self):
        """Reset the model and training data."""
        self.model = None
        self.training_data = []
        self.is_trained = False
        logger.info("Anomaly detection model reset")


# Singleton instance
anomaly_detector = AnomalyDetector()
