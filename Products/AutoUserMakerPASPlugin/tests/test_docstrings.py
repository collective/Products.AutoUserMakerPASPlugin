"""Run bin/zopectl test -s Products.AutoUserMakerPASPlugin.

add " -m '.*docstring.*'" to run just this test set.
"""

__revision__ = '0.1'

import unittest
from zope.testing import doctest
from Testing import ZopeTestCase as ztc
from Products.PloneTestCase import PloneTestCase as ptc

ptc.setupPloneSite()
ptc.installProduct('AutoUserMakerPASPlugin')

def test_suite():
    tests = (ztc.ZopeDocTestSuite('Products.AutoUserMakerPASPlugin.auth',
                                  test_class=ptc.PloneTestCase,
                                  optionflags=doctest.REPORT_ONLY_FIRST_FAILURE),)
    return unittest.TestSuite(tests)

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
