from Products.AutoUserMakerPASPlugin.tests.base import PluginTestCase
from Products.AutoUserMakerPASPlugin.Extensions.Install import \
    addautousermakerplugin


class AutoUserMakerPASPluginTests(PluginTestCase):

    def afterSetUp(self):
        self.plugin = addautousermakerplugin(self.portal.acl_users)

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

            def __init__(self, url):
                self.ACTUAL_URL = url

        class DummyResp(object):
            url = ''

            def redirect(self, url, lock=True):
                self.url = url

        request = DummyReq('http://www.example.org/')
        response = DummyResp()
        self.assertFalse(response.url)
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


def test_suite():
    """ This is the unittest suite """
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(AutoUserMakerPASPluginTests))
    return suite

# EOF
