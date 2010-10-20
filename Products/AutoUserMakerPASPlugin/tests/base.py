from Products.PloneTestCase import PloneTestCase as ptc

ptc.setupPloneSite()
ptc.installProduct('AutoUserMakerPASPlugin')

class PluginTestCase(ptc.PloneTestCase):
    """ Base class for AutoUserMakerPASPlugin tests """


class PluginFunctionalTestCase(ptc.FunctionalTestCase):
    """ Base class for AutoUserMakerPASPlugin integration tests """

# EOF
