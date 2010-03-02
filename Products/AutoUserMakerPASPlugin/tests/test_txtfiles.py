"""Run bin/zopectl test -s Products.AutoUserMakerPASPlugin.

add " -m '.*txtfiles.*'" to run just this test set."""

__revision__ = '0.1'

import glob
import os
import unittest
from zope.testing import doctest
from Testing import ZopeTestCase as ztc
from Products.PloneTestCase import PloneTestCase as ptc
from Globals import package_home
try:
    from AutoUserMakerPASPlugin import aum_globals
    package = 'AutoUserMakerPASPlugin'
except ImportError:
    from Products.AutoUserMakerPASPlugin import aum_globals
    package = 'Products.AutoUserMakerPASPlugin'

ptc.setupPloneSite()
ptc.installProduct('AutoUserMakerPASPlugin')

def listDoctests():
    home = package_home(aum_globals)
    return [ii for ii in glob.glob(os.path.sep.join([home + '/tests', '*.txt']))]

def test_suite():
    files = listDoctests()
    tests = [ztc.FunctionalDocFileSuite('tests/' + os.path.basename(filename),
                                        test_class=ptc.PloneTestCase,
                                        package=package,
                                        optionflags=doctest.REPORT_ONLY_FIRST_FAILURE)
             for filename in files]
    return unittest.TestSuite(tests)

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')