import unittest
from unittest.mock import patch
from main import (
    hash_password, check_password,
    validate_credentials, create_session
)
import sqlite3
import bcrypt

class TestAuthSecurity(unittest.TestCase):
    """Authentication and session tests."""

    # --- Password Hashing ---
    def test_password_hashing(self):
        """TC-01: Verify hashing/verification works."""
        pwd = "SecurePass123!"
        hashed = hash_password(pwd)
        self.assertTrue(check_password(hashed, pwd))
        self.assertFalse(check_password(hashed, "WrongPass"))

    # --- Credential Validation ---
    def test_valid_admin_login(self):
        """TC-02: Validate default admin credentials."""
        result = validate_credentials("mainadmin", "mainadmin123")
        self.assertEqual(result["role"], "Main Admin")

    def test_invalid_login(self):
        """TC-03: Reject wrong credentials."""
        self.assertIsNone(validate_credentials("fakeuser", "wrongpass"))

    # --- Session Management ---
    @patch("main.sqlite3.connect")
    def test_session_creation(self, mock_db):
        """TC-04: Session token generation and DB insert."""
        mock_db.return_value.cursor.return_value.lastrowid = 1
        token = create_session(1, "testuser", "Admin")
        self.assertEqual(len(token), 36)  # UUID length
        self.assertGreaterEqual(mock_db.return_value.commit.call_count, 1)

if __name__ == "__main__":
    unittest.main()