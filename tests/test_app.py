import unittest

from demix.app import get_file_count_for_user

class TestAuth(unittest.TestCase):
    def test_count(self):
        print(get_file_count_for_user('art@network.ru'))

if __name__ == '__main__':
    unittest.main()