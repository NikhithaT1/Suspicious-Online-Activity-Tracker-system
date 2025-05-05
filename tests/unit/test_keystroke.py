from unittest.mock import patch
import numpy as np
import unittest
from main import analyze_keystroke_pattern, train_keystroke_model

class TestKeystrokeAuth(unittest.TestCase):
    """Keystroke timing anomaly detection."""

    def setUp(self):
        # Simulate a user's normal timings (300ms ± 50ms)
        self.normal_timings = np.random.normal(0.3, 0.05, 100).tolist()

    

    def test_keystroke_normal(self):
        """TC-08: Accept normal typing speed (320ms)."""
        # Train the model with normal timings
        model, _, model_data = train_keystroke_model(self.normal_timings)
        
        # Mock the profile retrieval
        with patch("main.get_user_keystroke_profile") as mock_profile:
            mock_profile.return_value = (self.normal_timings, model_data)
            # 320ms is within normal range
            self.assertTrue(analyze_keystroke_pattern(1, 0.32))