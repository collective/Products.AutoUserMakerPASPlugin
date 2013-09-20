"""Run bin/zopectl test -s Products.AutoUserMakerPASPlugin.

add " -m '.*txtfiles.*'" to run just this test set."""

__revision__ = '0.1'

import glob
import os
import unittest
from zope.testing import doctest
from Testing import ZopeTestCase as ztc

from Products.AutoUserMakerPASPlugin.tests.base import PluginFunctionalTestCase

def listDoctests():
    home = os.path.dirname(__file__)
    return [ii for ii in glob.glob(os.path.sep.join([home, '*.txt']))]

def test_suite():
    files = listDoctests()
    tests = [ztc.FunctionalDocFileSuite('tests/' + os.path.basename(filename),
                                        test_class=PluginFunctionalTestCase,
                                        package='Products.AutoUserMakerPASPlugin',
                                        optionflags=doctest.REPORT_ONLY_FIRST_FAILURE|doctest.ELLIPSIS)
             for filename in files]
    return unittest.TestSuite(tests)

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
