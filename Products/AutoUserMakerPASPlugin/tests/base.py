# -*- coding: utf-8 -*-

from plone import api
from plone.app.testing import FunctionalTesting
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import PloneSandboxLayer
from plone.app.testing.bbb import PloneTestCase
from plone.testing import z2


class ProductsAutousermakerpaspluginLayer(PloneSandboxLayer):

    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        import Products.AutoUserMakerPASPlugin
        self.loadZCML(package=Products.AutoUserMakerPASPlugin)
        z2.installProduct(app, 'Products.AutoUserMakerPASPlugin')

    def setUpPloneSite(self, portal):
        quickinstaller = api.portal.get_tool(name='portal_quickinstaller')
        quickinstaller.installProduct('Products.AutoUserMakePASPlugin')


AUTOUSERMAKERPASPLUGIN_FIXTURE = ProductsAutousermakerpaspluginLayer()


AUTOUSERMAKERPASPLUGIN_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(AUTOUSERMAKERPASPLUGIN_FIXTURE,),
    name='ProductsAutousermakerpaspluginLayer:FunctionalTesting'
)


class PluginTestCase(PloneTestCase):
    """ Base class for AutoUserMakerPASPlugin tests """

    layer = AUTOUSERMAKERPASPLUGIN_FUNCTIONAL_TESTING

PluginFunctionalTestCase = PluginTestCase

# EOF
