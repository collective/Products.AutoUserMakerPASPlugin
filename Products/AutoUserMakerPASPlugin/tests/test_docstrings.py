"""Run bin/zopectl test -s Products.AutoUserMakerPASPlugin.

add " -m '.*docstring.*'" to run just this test set.
"""

__revision__ = '0.1'

import unittest
from zope.testing import doctest
from Testing import ZopeTestCase as ztc

from Products.AutoUserMakerPASPlugin.tests.base import PluginTestCase

def test_suite():
    tests = (ztc.ZopeDocTestSuite('Products.AutoUserMakerPASPlugin.auth',
                                  test_class=PluginTestCase,
                                  optionflags=doctest.REPORT_ONLY_FIRST_FAILURE),)
    return unittest.TestSuite(tests)
