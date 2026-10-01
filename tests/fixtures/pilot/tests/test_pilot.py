import unittest

from pilot import new_client


class ClientTests(unittest.TestCase):
    def test_client_creation(self):
        self.assertIsNotNone(new_client())
