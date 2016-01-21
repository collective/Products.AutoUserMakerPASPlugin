from plone import api
from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
from Products.AutoUserMakerPASPlugin.auth import httpEmailKey
from Products.AutoUserMakerPASPlugin.Extensions.Install import PLUGIN_ID as pluginId
from Products.AutoUserMakerPASPlugin.tests.base import PluginTestCase


class AutoUserMakerPASPluginTests(PluginTestCase):

    def afterSetUp(self):
        acl_users = api.portal.get_tool(name='acl_users')
        acl_users._setObject(pluginId, ApacheAuthPluginHandler(pluginId))
        self.plugin = acl_users[pluginId]

    def test_authentication(self):
        auth = self.plugin.authenticateCredentials
        self.assertFalse(auth({}))
        self.assertEqual(auth({'user_id': 'foobar'}), ('foobar', 'foobar'))

    def test_authentication_session(self):
        """ Test that authenticating will create a session, if configured."""
        if 'session' in self.portal.acl_users:
            self.plugin.authenticateCredentials({'user_id': 'foobar'})
            self.assertTrue('__ac' in self.plugin.REQUEST.RESPONSE.cookies)

    def test_challenge(self):
        class DummyReq(object):
            authenticated = False

            def __init__(self, url):
                self.ACTUAL_URL = url

            def getHeader(self, header, default):
                if self.authenticated:
                    return "SOME VALUE"
                else:
                    return default
 
        class DummyResp(object):
            url = ''

            def redirect(self, url, lock=True):
                self.url = url

        request = DummyReq('http://www.example.org/')
        response = DummyResp()
        self.assertFalse(response.url)


        # Authenticated already
        request.authenticated = True
        self.plugin.challenge(request, response)
        self.assertFalse(response.url)

        # Not yet atuthenticated
        request.authenticated = False
        self.plugin.challenge(request, response)
        self.assertEqual(response.url, 'https://www.example.org/')

    def test_loginurl(self):
        self.assertEqual(
            self.plugin.loginUrl('http://www.example.org/path?q=hello+world'),
            'https://www.example.org/path?q=hello+world')
        self.assertEqual(
            self.plugin.loginUrl('https://www.example.org/https/stays'), '')
        self.assertEqual(
            self.plugin.loginUrl('ftp://ftp.example.org/path'), '')

    def test_prop_upgrade(self):
        setattr(self.plugin, httpEmailKey, 'as attr')
        self.assertEqual(self.plugin.getConfig()[httpEmailKey], ('as attr',))

# EOF
