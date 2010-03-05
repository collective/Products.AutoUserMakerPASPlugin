import unittest

from Products.AutoUserMakerPASPlugin.auth import safe_int

class UtilsTests(unittest.TestCase):
    """ Test utilities """

    def test_safeint(self):
        """ Test safe_int-method """
        self.assertEqual(safe_int('0815'), 815)
        self.assertEqual(safe_int(42), 42)
        self.assertEqual(safe_int('bogus'), 0)
        self.assertEqual(safe_int('bogus2', None), None)

def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
