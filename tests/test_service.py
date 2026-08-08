import unittest

from service import add, health


class ServiceTests(unittest.TestCase):
    def test_add_general(self):
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(-2, 3), 1)

    def test_add_zero(self):
        self.assertEqual(add(0, 7), 7)

    def test_health(self):
        self.assertEqual(health(), {"ok": True})
