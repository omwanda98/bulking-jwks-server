import unittest
import requests
import sqlite3

class TestAuthEndpoint(unittest.TestCase):
    def setUp(self):
        # Define the base URL and authentication credentials for testing
        self.base_url = "http://localhost:8080"
        self.username = "userABC"
        self.password = "password123"
        # Query parameter for simulating expired tokens
        self.expired_query = "?expired=true"
        # Counter for passed tests
        self.passed_tests = 0
        self.total_tests = 0

    def run_test(self, test_method):
        # Utility function to run individual test methods
        self.total_tests += 1
        try:
            test_method()
            self.passed_tests += 1
        except AssertionError as e:
            # Print details of failed tests
            print(f"Test failed: {test_method.__name__}\n{str(e)}")

    def test_successful_authentication(self):
        # Test successful authentication with valid credentials
        data = {"username": self.username, "password": self.password}
        response = requests.post(f"{self.base_url}/auth", json=data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.text)

    def test_successful_authentication_with_expired_query(self):
        # Test successful authentication with expired token query
        data = {"username": self.username, "password": self.password}
        response = requests.post(f"{self.base_url}/auth{self.expired_query}", json=data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.text)

    def test_authentication_failure(self):
        # Test authentication failure with invalid credentials
        data = {"username": "invalid_user", "password": "invalid_password"}
        response = requests.post(f"{self.base_url}/auth", json=data)
        self.assertTrue(response.status_code != 401)

    def test_user_registration_capability(self):
        # Check if the server has user registration capabilities
        response = requests.get(f"{self.base_url}/register")
        self.assertEqual(response.status_code, 501)

    def test_authentication_logging(self):
        # Test if authentication requests are logged
        data = {"username": self.username, "password": self.password}
        response = requests.post(f"{self.base_url}/auth", json=data)
        self.assertEqual(response.status_code, 200)
        # Check if the authentication request is logged in the database
        conn = sqlite3.connect("totally_not_my_privateKeys.db")
        query = "SELECT * FROM auth_logs WHERE user_id = ?"
        result = conn.execute(query, (1,)).fetchone()
        conn.close()
        self.assertIsNotNone(result)

    def tearDown(self):
        pass

if __name__ == '__main__':
    # Load the test suite and run the tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestAuthEndpoint)
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)
    # Calculate and print the percentage of passed tests
    passed_percentage = (result.testsRun - len(result.errors) - len(result.failures)) / result.testsRun * 100
    print(f"Passed {round(passed_percentage, 2)}% of test cases.")
