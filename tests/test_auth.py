import unittest

from demix.auth import encode, decode

class TestAuth(unittest.TestCase):
    def test_auth(self):
        token = encode('wow@test.com') 
        auth_data = decode(token)
        self.assertEqual(auth_data['user'], 'wow@test.com')

if __name__ == '__main__':
    unittest.main()