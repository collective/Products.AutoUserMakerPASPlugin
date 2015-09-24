""" Test docstrings
"""

__revision__ = '0.1'

from plone.testing import layered
from Products.AutoUserMakerPASPlugin.tests.base import AUTOUSERMAKERPASPLUGIN_FUNCTIONAL_TESTING

import doctest
import glob
import os
import unittest


def listDoctests():
    home = os.path.dirname(__file__)
    return [ii for ii in glob.glob(os.path.sep.join([home, '*.txt']))]


OPTIONFLAGS = doctest.REPORT_ONLY_FIRST_FAILURE|doctest.ELLIPSIS


def test_suite():
    tests = [layered(doctest.DocTestSuite('Products.AutoUserMakerPASPlugin.auth',
                                  optionflags=OPTIONFLAGS),
                     layer=AUTOUSERMAKERPASPLUGIN_FUNCTIONAL_TESTING),]
    tests.extend([layered(doctest.DocFileSuite(os.path.basename(filename),
                                        optionflags=OPTIONFLAGS),
                          layer=AUTOUSERMAKERPASPLUGIN_FUNCTIONAL_TESTING)
             for filename in listDoctests()])
    return unittest.TestSuite(tests)
