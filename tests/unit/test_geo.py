from main import check_geolocation_velocity
import unittest

class TestGeoVelocity(unittest.TestCase):
    """Geolocation velocity anomaly detection."""

    def test_impossible_travel(self):
        """TC-05: Detect unrealistic travel (NYC to Paris in 1h)."""
        prev = {"latitude": 40.7128, "longitude": -74.0060}  # NYC
        curr = {"latitude": 48.8566, "longitude": 2.3522}    # Paris
        self.assertTrue(
            check_geolocation_velocity(prev, curr, 1)  # 1h difference
        )

    def test_normal_travel(self):
        """TC-06: Allow plausible travel (NYC to Boston in 3h)."""
        prev = {"latitude": 40.7128, "longitude": -74.0060}  # NYC
        curr = {"latitude": 42.3601, "longitude": -71.0589}  # Boston
        self.assertFalse(
            check_geolocation_velocity(prev, curr, 3)  # 3h difference
        )