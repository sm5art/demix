import os
import unittest
 
from demix.app import app
 
class Base(unittest.TestCase):
    ############################
    #### setup and teardown ####
    ############################
 
    # executed prior to each test
    def setUp(self):
        self.app = app.test_client()
 
    # executed after each test
    def tearDown(self):
        pass
 
 
 
if __name__ == "__main__":
    unittest.main()