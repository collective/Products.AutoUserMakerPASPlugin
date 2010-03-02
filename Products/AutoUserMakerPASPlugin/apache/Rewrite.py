#!/usr/bin/env python
""" Use this instead of the mod_rewrite directives in the ssl configuration:

    PythonFixupHandler /path/to/Rewrite.py

Remove or comment out these:

    #RewriteEngine On
    #RewriteCond %{LA-U:REMOTE_USER} (.+)
    #RewriteRule .* - [E=RW_RU:%1]
    #RequestHeader set X_REMOTE_USER %{RW_RU}e
    #RewriteCond %{REQUEST_URI} !^/(shibboleth-(sp|idp)|Shibboleth.sso|SAML|WAYF|server-(status|info)|index.php|php)
    #RewriteRule ^/(.*) http://127.0.0.1:8301/VirtualHostBase/https/alan.ithaka.org:443/test/VirtualHostRoot/$1 [L,P]

This change allows one apache instance to act as an SSL proxy and Shibboleth
Service Provider for multiple Plone sites. These sites can be on one or more
Zope instances, but must have unique DNS names.
"""
__revision__ = "0.2"

from mod_python import apache
import re
import urllib

# Customize these
# This allows the matched patterns to pass through (not be sent to zope).
_rSkip = re.compile(r'^/(shibboleth-(sp|idp)|Shibboleth.sso|SAML|WAYF|server-(status|info)|index.php|php)')
# This maps the host name provided by the browser to the back end zope listener.
_dHosts = {'alan.ithaka.org': '127.0.0.1:8301', 'test.ithaka.org': '127.0.0.1:8253'}
# This maps the host name provided by the browser to the path to plone in zope.
_dPaths = {'alan.ithaka.org': 'test', 'test.ithaka.org': 'test'}

def fixuphandler(req):
    # This implements a negative RewriteCond to not redirect certain paths.
    if req.proxyreq or _rSkip.search(req.uri):
        return apache.DECLINED
    # Make the REMOTE_USER value from Shibboleth available to zope.
    req.add_common_vars()
    if req.subprocess_env.has_key('REMOTE_USER'):
        req.headers_in['X_REMOTE_USER'] = req.subprocess_env['REMOTE_USER']
    # Build the reverse proxy request URL, and tell apache to use it.
    sHost = req.headers_in['Host']
    req.uri = "http://%s/VirtualHostBase/https/%s:443/%s/VirtualHostRoot%s" % \
        (_dHosts[sHost], sHost, _dPaths[sHost], urllib.quote(req.uri))
    req.proxyreq = apache.PROXYREQ_REVERSE
    req.filename = "proxy:" + req.uri
    req.handler = 'proxy-server'
    return apache.OK
