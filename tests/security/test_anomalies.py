from main import get_process_list, monitor_clipboard
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

class TestAnomalyDetection(unittest.TestCase):
    """Suspicious activity detection."""

    @patch("psutil.process_iter")
    def test_suspicious_process_detection(self, mock_procs):
        """TC-11: Flag known malicious processes."""
        mock_procs.return_value = [
            MagicMock(info={"name": "wireshark.exe"}),
            MagicMock(info={"name": "chrome.exe"})
        ]
        suspicious = get_process_list()
        self.assertEqual(len(suspicious), 1)  # Only Wireshark flagged

    @patch("pyperclip.paste")
    def test_clipboard_monitoring(self, mock_paste):
        """TC-12: Log clipboard content."""
        mock_paste.return_value = "SensitiveData123"
        with patch("main.sqlite3.connect") as mock_db:
            monitor_clipboard(1)  # User ID
            mock_db.return_value.cursor.return_value.execute.assert_called_with(
                "INSERT INTO clipboard_logs (user_id, content) VALUES (?, ?)",
                (1, "SensitiveData123")
            )