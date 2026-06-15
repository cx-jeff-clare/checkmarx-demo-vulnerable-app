"""
Comprehensive tests for SQL injection vulnerability fix in app.py
Tests the get_user function to ensure it properly handles user input
and prevents SQL injection attacks.
"""

import unittest
import sqlite3
import os
from app import app, init_db


class TestSQLInjectionFix(unittest.TestCase):
    """Test suite for SQL injection vulnerability fix in get_user endpoint"""

    def setUp(self):
        """Set up test client and test database"""
        self.app = app
        self.client = app.test_client()
        self.app.config['TESTING'] = True

        # Remove existing test database if present
        if os.path.exists('demo.db'):
            os.remove('demo.db')

        # Initialize fresh database
        init_db()

        # Insert test data
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
            (1, 'testuser', 'hashedpassword123')
        )
        cursor.execute(
            "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
            (2, 'admin', 'adminpass456')
        )
        cursor.execute(
            "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
            (999, 'special_user', 'specialpass789')
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        """Clean up test database"""
        if os.path.exists('demo.db'):
            os.remove('demo.db')

    # ========================================================================
    # POSITIVE TEST CASES - Verify functionality works correctly
    # ========================================================================

    def test_get_user_valid_id(self):
        """Test that valid user ID returns correct user data"""
        response = self.client.get('/user/1')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNotNone(data['user'])
        # Verify correct user data is returned
        self.assertEqual(data['user'][0], 1)  # id
        self.assertEqual(data['user'][1], 'testuser')  # username

    def test_get_user_another_valid_id(self):
        """Test that another valid user ID returns correct data"""
        response = self.client.get('/user/2')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNotNone(data['user'])
        self.assertEqual(data['user'][0], 2)  # id
        self.assertEqual(data['user'][1], 'admin')  # username

    def test_get_user_large_id(self):
        """Test that large valid user ID works correctly"""
        response = self.client.get('/user/999')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNotNone(data['user'])
        self.assertEqual(data['user'][0], 999)  # id
        self.assertEqual(data['user'][1], 'special_user')  # username

    def test_get_user_nonexistent_id(self):
        """Test that non-existent user ID returns None gracefully"""
        response = self.client.get('/user/9999')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNone(data['user'])

    # ========================================================================
    # NEGATIVE TEST CASES - Verify SQL injection attacks are blocked
    # ========================================================================

    def test_sql_injection_basic_attack(self):
        """Test that basic SQL injection attempt is blocked: 1 OR 1=1"""
        # This attack would return all users in vulnerable code
        response = self.client.get('/user/1 OR 1=1')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        # Should return None because '1 OR 1=1' is treated as a single value
        # and won't match any user ID
        self.assertIsNone(data['user'])

    def test_sql_injection_union_attack(self):
        """Test that UNION-based SQL injection is blocked"""
        # Attempt to extract data using UNION
        payload = "1 UNION SELECT 1,2,3"
        response = self.client.get(f'/user/{payload}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        # Should return None - the payload is treated as string, not executed
        self.assertIsNone(data['user'])

    def test_sql_injection_comment_attack(self):
        """Test that SQL comment injection is blocked"""
        # Attempt to use SQL comments to bypass query logic
        payload = "1--"
        response = self.client.get(f'/user/{payload}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        # Should return None - comment syntax is not executed
        self.assertIsNone(data['user'])

    def test_sql_injection_drop_table_attack(self):
        """Test that DROP TABLE injection attempt is blocked"""
        # Attempt to drop the users table
        payload = "1; DROP TABLE users--"
        response = self.client.get(f'/user/{payload}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        # Should return None - the entire payload is treated as a value
        self.assertIsNone(data['user'])

        # Verify table still exists by making another valid query
        response = self.client.get('/user/1')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNotNone(data['user'])

    def test_sql_injection_boolean_based_attack(self):
        """Test that boolean-based blind SQL injection is blocked"""
        # Attempt boolean-based injection
        payload = "1 AND 1=1"
        response = self.client.get(f'/user/{payload}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        # Should return None - boolean logic is not executed as SQL
        self.assertIsNone(data['user'])

    def test_sql_injection_time_based_attack(self):
        """Test that time-based blind SQL injection is blocked"""
        # Attempt time-based injection with sleep/delay
        payload = "1 AND SLEEP(5)"
        response = self.client.get(f'/user/{payload}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        # Should return None quickly - no SQL execution
        self.assertIsNone(data['user'])

    def test_sql_injection_stacked_queries_attack(self):
        """Test that stacked queries injection is blocked"""
        # Attempt to execute multiple statements
        payload = "1; INSERT INTO users VALUES(100,'hacker','pwned')"
        response = self.client.get(f'/user/{payload}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        # Should return None - stacked query not executed
        self.assertIsNone(data['user'])

        # Verify the injection didn't work
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (100,))
        result = cursor.fetchone()
        conn.close()
        self.assertIsNone(result)  # User 100 should not exist

    # ========================================================================
    # EDGE CASES
    # ========================================================================

    def test_get_user_special_characters(self):
        """Test that special characters in user_id don't cause errors"""
        special_chars = ["'", '"', ";", "--", "/*", "*/", "\\", "%", "_"]
        for char in special_chars:
            response = self.client.get(f'/user/{char}')
            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            # Should handle gracefully without errors
            self.assertIsNone(data['user'])

    def test_get_user_empty_string(self):
        """Test that empty string is handled properly"""
        response = self.client.get('/user/')
        # Flask routing may return 404 for empty parameter
        self.assertIn(response.status_code, [200, 404])

    def test_get_user_very_long_input(self):
        """Test that very long input doesn't cause issues"""
        long_input = "A" * 10000
        response = self.client.get(f'/user/{long_input}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNone(data['user'])

    def test_get_user_unicode_characters(self):
        """Test that unicode characters are handled safely"""
        unicode_inputs = ["你好", "🔥", "café", "Ω"]
        for unicode_input in unicode_inputs:
            response = self.client.get(f'/user/{unicode_input}')
            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertIsNone(data['user'])

    # ========================================================================
    # REGRESSION TESTS - Ensure fix doesn't break functionality
    # ========================================================================

    def test_no_sql_execution_errors(self):
        """Test that parameterized queries don't cause SQL syntax errors"""
        # Various inputs that should be safe with parameterized queries
        safe_inputs = ["1", "2", "999", "0", "-1"]
        for input_val in safe_inputs:
            response = self.client.get(f'/user/{input_val}')
            self.assertEqual(response.status_code, 200)
            # Should not raise any SQL errors

    def test_database_integrity_after_attacks(self):
        """Test that database remains intact after injection attempts"""
        # Try multiple injection attacks
        attacks = [
            "1 OR 1=1",
            "1; DROP TABLE users",
            "1 UNION SELECT 1,2,3",
            "1' OR '1'='1"
        ]

        for attack in attacks:
            self.client.get(f'/user/{attack}')

        # Verify database is still functional
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()

        # Should still have our 3 test users
        self.assertEqual(count, 3)


if __name__ == '__main__':
    unittest.main()
