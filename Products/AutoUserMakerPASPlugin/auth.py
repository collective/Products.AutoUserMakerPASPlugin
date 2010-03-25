"""Classes to connect apache authentication into Zope/Plone."""
__revision__ = "0.4"

from random import choice
import re
import string

from persistent.list import PersistentList
from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from OFS.PropertyManager import PropertyManager
from ZODB.POSException import ConflictError

from Products.CMFCore.utils import getToolByName
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import (
    IAuthenticationPlugin, IExtractionPlugin, IRoleAssignerPlugin,
    IRolesPlugin, IUserAdderPlugin)
from Products.PluggableAuthService.permissions import ManageUsers
from Products.PluggableAuthService.PluggableAuthService import logger
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements

from Products.PluggableAuthService.PluggableAuthService import \
    _SWALLOWABLE_PLUGIN_EXCEPTIONS

stripDomainNamesKey = 'strip_domain_names'
stripDomainNamesListKey = 'strip_domain_name_list'
httpRemoteUserKey = 'http_remote_user'
httpCommonnameKey = 'http_commonname'
httpDescriptionKey = 'http_description'
httpEmailKey = 'http_email'
httpLocalityKey = 'http_locality'
httpStateKey = 'http_state'
httpCountryKey = 'http_country'
httpAuthzTokensKey = 'http_authz_tokens'
httpSharingTokensKey = 'http_sharing_tokens'
httpSharingLabelsKey = 'http_sharing_labels'
usernameKey = 'user_id'

PWCHARS = string.letters + string.digits + string.punctuation

def safe_int(s, default=0):
    try:
        return int(s)
    except (ValueError, TypeError):
        return default


class AutoUserMakerPASPlugin(BasePlugin):
    """ An authentication plugin that creates member objects

       AutoUserMakerPASPlugin expects a mapping like ExtractionPlugin
       returns, makes the user specified therein, gives him the Member role so
       Plone treats recognizes him, assigns local permissions if
       ShibbolethPermissions is installed and passes control to the next
       authentication plugin.

       This unittest doesn't show much since this really needs integration
       testing:
       >>> from Products.AutoUserMakerPASPlugin.auth import \
               AutoUserMakerPASPlugin
       >>> AutoUserMakerPASPlugin('test').authenticateCredentials({})
       >>> AutoUserMakerPASPlugin('test').authenticateCredentials(
       ...        {'user_id': 'foobar'})
       ('foobar', 'foobar')
    """
    security = ClassSecurityInfo()

    def __init__(self, pluginId, title=None):
        self.id = pluginId
        self.title = title

    security.declarePrivate('authenticateCredentials')
    def authenticateCredentials(self, credentials):
        """See class's docstring and IAuthenticationPlugin."""

        mappings = credentials.pop('_getMappings', [])
        userId = credentials.get(usernameKey, None)

        if userId is not None and self._getPAS() is not None and \
            self._getPAS().getUserById(userId) is None:
            # Make a user with id `userId`, and assign him at least the Member
            # role, since user doesn't exist.

            def generatePassword():
                """ Return a obfuscated password never used for login """
                return ''.join([choice(PWCHARS) for ii in range(10)])

            # Make sure we actually have user adders and role assigners. It
            # would be ugly to succeed at making the user but be unable to
            # assign him the role.
            userAdders = self.plugins.listPlugins(IUserAdderPlugin)
            if not userAdders:
                raise NotImplementedError("I wanted to make a new user, but"
                                          " there are no PAS plugins active"
                                          " that can make users.")
            roleAssigners = self.plugins.listPlugins(IRoleAssignerPlugin)
            if not roleAssigners:
                raise NotImplementedError("I wanted to make a new user and give"
                                          " him the Member role, but there are"
                                          " no PAS plugins active that assign"
                                          " roles to users.")

            # Add the user to the first IUserAdderPlugin that works:
            user = None
            for _, curAdder in userAdders:
                if curAdder.doAddUser(userId, generatePassword()):
                    # Assign a dummy password. It'll never be used;.
                    user = self._getPAS().getUser(userId)
                    try:
                        membershipTool = getToolByName(self,
                                                       'portal_membership')
                        if not membershipTool.getHomeFolder(userId):
                            membershipTool.createMemberArea(userId)
                    except (ConflictError, KeyboardInterrupt):
                        raise
                    except Exception, e:
                        pass
                    userProps = user.getPropertysheet('mutable_properties')
                    for ii in ('fullname', 'description', 'email', 'location'):
                        if credentials.has_key(ii):
                            userProps.setProperty(user, ii, credentials[ii])
                    break

            # Build a list of roles to assign to the user, always with Member
            roles = {'Member': True}
            groups = []
            if credentials.has_key('filters'):
                for role in mappings:
                    # for each source given in authz_mappings
                    for ii in role['values'].iterkeys():
                        assignRole = False
                        # if the authz_mappings pattern is not set, assume ok
                        if not role['values'][ii]:
                            assignRole = True
                        # if the source exists in the environment
                        elif credentials['filters'].has_key(ii):
                            try:
                                # compile the pattern from authz_mappings
                                oRe = re.compile(role['values'][ii])
                                # and compare the pattern to the environment
                                # value
                                match = oRe.search(credentials['filters'][ii])
                            except (ConflictError, KeyboardInterrupt):
                                raise
                            except Exception, e:
                                match = False
                            if match:
                                assignRole = True
                        if not assignRole:
                            break
                    # either there was no pattern or the pattern matched
                    # for every mapping, so add specified roles or groups.
                    if assignRole:
                        for ii in role['roles'].iterkeys():
                            if role['roles'][ii] == 'on':
                                roles[ii] = True
                        for ii in role['groupid']:
                            groups.append(ii)

            # Map the given roles to the user using all available
            # IRoleAssignerPlugins (just like doAddUser does for some reason):
            for curAssignerId, curAssigner in roleAssigners:
                for role in roles.iterkeys():
                    try:
                        curAssigner.doAssignRoleToPrincipal(user.getId(), role)
                    except _SWALLOWABLE_PLUGIN_EXCEPTIONS:
                        logger.warning('RoleAssigner %s error' % curAssignerId,
                                       exc_info=True)

            source_groups = getToolByName(self, 'source_groups')
            for ii in groups:
                source_groups.addPrincipalToGroup(user.getId(), ii)

            shibPerms = getToolByName(self, 'ShibbolethPermissions', None)
            uservals = credentials.get('localperms', None)
            if shibPerms is not None and uservals:
                # Ignore any error here, since it just means the user didn't
                #  get permissions on something. Not ignoring means the user
                #  will see a plone page that doesn't look like the user has
                #  logged in.
                try:
                    for path, regexs in shibPerms.getLocalRoles().iteritems():
                        for ii in regexs:
                            found = True
                            # Make sure the incoming user has all of the
                            # needed attributes
                            for name in ii.iterkeys():
                                if name == '_roles':
                                    continue
                                if not uservals.has_key(name):
                                    found = False
                                if not found:
                                    break
                            if found:
                                for name, pattern in ii.iteritems():
                                    if name == '_roles' or \
                                       uservals[name] is None:
                                        continue
                                    try:
                                        regex = re.compile(pattern)
                                        if not regex.search(uservals[name]):
                                            found = False
                                    except (ConflictError, KeyboardInterrupt):
                                        raise
                                    except Exception, e:
                                        pass
                                    if not found:
                                        break
                            if found:
                                # All of the attributes match
                                try:
                                    obj = self.unrestrictedTraverse(path)
                                except (AttributeError, KeyError):
                                    continue
                                logger.debug("Setting permissions on %r to %s",
                                             (repr(obj),
                                              ', '.join(ii['_roles'])))
                                obj.manage_setLocalRoles(userId, ii['_roles'])
                                obj.reindexObjectSecurity()
                except (ConflictError, KeyboardInterrupt):
                    raise
                except Exception, e:
                    logger.warning("error processing local roles: %s" % str(e))
        if userId is None:
            return None  # Pass control to the next IAuthenticationPlugin.
        return userId, userId

classImplements(AutoUserMakerPASPlugin, IAuthenticationPlugin)

class MockUser:
    """Used in ExtractionPlugin.extractCredentials for testing.

    Unittest it here (not that it does much ;-):
    >>> from Products.AutoUserMakerPASPlugin.auth import MockUser
    >>> user = MockUser('test')
    >>> user.getId()
    'test'
    >>> user.getGroups()
    ()
    """
    def __init__(self, sUserId):
        self.sUserId = sUserId

    def getId(self):
        """Return the id stored by __init__."""
        return self.sUserId

    def getGroups(self):
        """Return an empty tuple."""
        return ()


class ExtractionPlugin(BasePlugin, PropertyManager):
    """ A simple extraction plugin that retrieves its credentials
    information from a successful apache authentication.

    Usage info:
    >>> class MockRequest:
    ...     def __init__(self, environ={}):
    ...         self.environ = environ
    >>> request = MockRequest({'HTTP_X_REMOTE_USER': 'foobar'})

    ExtractionPlugin is an abstract class, but ApacheAuthPluginHandler fills
    it out.
    >>> from Products.AutoUserMakerPASPlugin.auth import ExtractionPlugin
    >>> handler = ExtractionPlugin()
    >>> handler.extractCredentials(request)
    {'user_id': 'foobar', 'description': None, 'localperms': {}, 'location': '', 'filters': {}, 'fullname': None, '_getMappings': [], 'email': None}

    """
    security = ClassSecurityInfo()

    def __init__(self):
        config = (
            (stripDomainNamesKey, 'int', 'w', 1),
            (stripDomainNamesListKey, 'lines', 'w', []),
            (httpRemoteUserKey, 'lines', 'w', ['HTTP_X_REMOTE_USER',]),
            (httpCommonnameKey, 'lines', 'w', ['HTTP_SHIB_PERSON_COMMONNAME',]),
            (httpDescriptionKey, 'lines', 'w', ['HTTP_SHIB_ORGPERSON_TITLE',]),
            (httpEmailKey, 'lines', 'w', ['HTTP_SHIB_INETORGPERSON_MAIL',]),
            (httpLocalityKey, 'lines', 'w', ['HTTP_SHIB_ORGPERSON_LOCALITY',]),
            (httpStateKey, 'lines', 'w', ['HTTP_SHIB_ORGPERSON_STATE',]),
            (httpCountryKey, 'lines', 'w', ['HTTP_SHIB_ORGPERSON_C',]),
            (httpAuthzTokensKey, 'lines', 'w', []),
            (httpSharingTokensKey, 'lines', 'w', []),
            (httpSharingLabelsKey, 'lines', 'w', []),
            ('required_roles', 'lines', 'wd', []),
            ('login_users', 'lines', 'wd', []))
        # Create any missing properties
        ids = {}
        for prop in (config):
            # keep track of property names for quick lookup
            ids[prop[0]] = True
            if prop[0] not in self.propertyIds():
                self.manage_addProperty(id=prop[0],
                                        type=prop[1],
                                        value=prop[3])
                self._properties[-1]['mode'] = prop[2]
        # Delete any existing properties that aren't in config
        for prop in self._properties:
            if not ids.has_key(prop['id']) and prop['id'] != 'prefix':
                self.manage_delProperties(prop['id'])
        # Get a list for storing mappings
        self.authzMappings = PersistentList()

    security.declareProtected(ManageUsers, 'getConfig')
    def getConfig(self):
        """ Return a mapping of my configuration values, for use in a
            page template.

        Verify it returns an empty configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import ExtractionPlugin
        >>> handler = ExtractionPlugin()
        >>> import pprint
        >>> pprint.pprint(handler.getConfig())
        {'http_authz_tokens': (),
         'http_commonname': ('HTTP_SHIB_PERSON_COMMONNAME',),
         'http_country': ('HTTP_SHIB_ORGPERSON_C',),
         'http_description': ('HTTP_SHIB_ORGPERSON_TITLE',),
         'http_email': ('HTTP_SHIB_INETORGPERSON_MAIL',),
         'http_locality': ('HTTP_SHIB_ORGPERSON_LOCALITY',),
         'http_remote_user': ('HTTP_X_REMOTE_USER',),
         'http_sharing_labels': (),
         'http_sharing_tokens': (),
         'http_state': ('HTTP_SHIB_ORGPERSON_STATE',),
         'strip_domain_name_list': (),
         'strip_domain_names': 1}
        """
        return {
            stripDomainNamesKey: self.getProperty(stripDomainNamesKey),
            stripDomainNamesListKey: self.getProperty(stripDomainNamesListKey),
            httpRemoteUserKey: self.getProperty(httpRemoteUserKey),
            httpCommonnameKey: self.getProperty(httpCommonnameKey),
            httpDescriptionKey: self.getProperty(httpDescriptionKey),
            httpEmailKey: self.getProperty(httpEmailKey),
            httpLocalityKey: self.getProperty(httpLocalityKey),
            httpStateKey: self.getProperty(httpStateKey),
            httpCountryKey: self.getProperty(httpCountryKey),
            httpAuthzTokensKey: self.getProperty(httpAuthzTokensKey),
            httpSharingTokensKey: self.getProperty(httpSharingTokensKey),
            httpSharingLabelsKey: self.getProperty(httpSharingLabelsKey)}

    security.declarePublic('getSharingConfig')
    def getSharingConfig(self):
        """Return the items end users can use to share with.

        Verify it returns an empty configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import ExtractionPlugin
        >>> handler = ExtractionPlugin()
        >>> handler.getSharingConfig()
        {'http_sharing_tokens': (), 'http_sharing_labels': ()}
        """
        return {httpSharingTokensKey: self.getProperty(httpSharingTokensKey),
                httpSharingLabelsKey: self.getProperty(httpSharingLabelsKey)}

    security.declareProtected(ManageUsers, 'getTokens')
    def getTokens(self):
        """Return http_authz_tokens as a tupple (how getProperty returns it).

        Verify it returns an empty configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import ExtractionPlugin
        >>> handler = ExtractionPlugin()
        >>> handler.getTokens()
        ()
        """
        return self.getProperty(httpAuthzTokensKey)

    security.declareProtected(ManageUsers, 'getMapping')
    def getMapping(self):
        """ Get a default empty mapping

        >>> from Products.AutoUserMakerPASPlugin.auth import ExtractionPlugin
        >>> handler = ExtractionPlugin()
        >>> sorted(handler.getMapping().items())
        [('groupid', []), ('roles', {}), ('userid', ''), ('values', {}), ('version', 1)]
        """
        return {'version': 1,
                 'values': {},
                 'roles': {},
                 'userid': '',
                 'groupid': []}

    security.declareProtected(ManageUsers, 'getMappings')
    def getMappings(self):
        """Return authzMappings as a persistent list of dictionaries.

        Verify it returns an empty configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import ExtractionPlugin
        >>> handler = ExtractionPlugin()
        >>> handler.getMappings()
        []
        """
        return self.authzMappings

    security.declareProtected(ManageUsers, 'listMappings')
    def listMappings(self):
        """Return authzMappings as a list of dictionaries.

        Verify it returns an empty configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import ExtractionPlugin
        >>> handler = ExtractionPlugin()
        >>> handler.getMappings()
        []
        """
        return list(self.authzMappings)

    security.declareProtected(ManageUsers, 'putMappings')
    def putMappings(self, authz):
        """Save the input as authzMappings."""
        self.authzMappings = PersistentList(authz)
        self._p_changed = 1

    security.declareProtected(ManageUsers, 'addMappings')
    def addMappings(self, authz):
        """Append the input to authzMappings."""
        self.authzMappings.append(authz)
        self._p_changed = 1

    security.declarePrivate('requiredRoles')
    def requiredRoles(self):
        """Extract the required roles from the property.

        Verify it returns an empty configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import ExtractionPlugin
        >>> handler = ExtractionPlugin()
        >>> handler.requiredRoles()
        ()
        """
        return self.getProperty('required_roles', [])

    security.declarePrivate('loginUsers')
    def loginUsers(self):
        """Extract the login users from the property.

        Verify it returns an empty configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import ExtractionPlugin
        >>> handler = ExtractionPlugin()
        >>> handler.loginUsers()
        ()
        """
        return self.getProperty('login_users', [])

    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        """Search a Zope request for Shibboleth tokens. See IExtractionPlugin.

        The request environment is searched for HTTP_X_REMOTE_USER, which should
        be commonly available, and is required. Additional user properties can
        be set by specification of HTTP_SHIB_PERSON_COMMONNAME (full name),
        HTTP_SHIB_ORGPERSON_TITLE (biography), HTTP_SHIB_INETORGPERSON_MAIL
        (email), and HTTP_SHIB_ORGPERSON_LOCALITY, HTTP_SHIB_ORGPERSON_STATE and
        HTTP_SHIB_ORGPERSON_C (location), or as those HTTP_* values get defined
        in the properites.

        The class unittest tests this."""
        config = self.getConfig()
        user = {'location': '', 'filters': {}, 'localperms': {}}
        for label, key in ((usernameKey, httpRemoteUserKey),
                           ('fullname', httpCommonnameKey),
                           ('description', httpDescriptionKey),
                           ('email', httpEmailKey)):
            for jj in config[key]:
                user[label] = request.environ.get(jj, None)
                if user[label]:
                    break
        if not user[usernameKey] or user[usernameKey] == '(null)':
            return None

        # clean up the user id, if told to do so
        if config[stripDomainNamesKey] and user[usernameKey].find('@') > 0:
            # With some Apache setups, the username is returned as
            # 'user123@some.domain.name'.
            nameDomain = user[usernameKey].split('@', 1)
            if len(nameDomain) == 1 or \
               config[stripDomainNamesKey] == 1 or \
               (config[stripDomainNamesKey] == 2 and \
                nameDomain[1] in config[stripDomainNamesListKey]):
                user[usernameKey] = nameDomain[0]

        # build a location value
        for ii in (config[httpLocalityKey], config[httpStateKey],
                   config[httpCountryKey]):
            if not ii:
                continue
            for jj in ii:
                val = request.environ.get(jj, None)
                if val:
                    if user['location']:
                        user['location'] += ', ' + val
                    else:
                        user['location'] = val

        # save the values of any authz filter
        for ii in self.getTokens():
            user['filters'][ii] = request.environ.get(ii, None)

        # save the values of any local authz filter
        sharing = self.getSharingConfig()
        for ii in sharing[httpSharingTokensKey]:
            user['localperms'][ii] = request.environ.get(ii, None)

        # See if this Shib user should map to a specific existing plone user
        sourceUsers = getToolByName(self, 'source_users', None)
        for role in self.authzMappings:
            # if this role mapping doesn't list a userid, skip it.
            if not role['userid']:
                continue
            if sourceUsers is None:
                continue
            # verify this userid actually exists in plone
            try:
                ploneUser = sourceUsers.getUserInfo(role['userid'])
            except KeyError:
                continue
            # for each source given in authz_mappings
            for ii in role['values'].iterkeys():
                assignRole = False
                # if the authz_mappings pattern is not set, assume ok
                if not role['values'][ii]:
                    assignRole = True
                # if the source exists in the environment
                elif user['filters'].has_key(ii):
                    # compile the pattern from authz_mappings
                    oRe = re.compile(role['values'][ii])
                    # and compare the pattern to the environment value
                    match = oRe.search(user['filters'][ii])
                    if match:
                        assignRole = True
                if not assignRole:
                    break
            # either there was no pattern or the pattern matched
            # for every mapping, so this shib user becomes the given plone user
            if assignRole:
                return ploneUser

        user['_getMappings'] = self.getMappings()

        loginUsers = self.loginUsers()
        requiredRoles = self.requiredRoles()
        if loginUsers:
            # Hard-coded list of users
            if user[usernameKey] in loginUsers:
                return user
            elif not requiredRoles:
                return None
            # Second chance: required role.
        if requiredRoles:
            rolemakers = self.plugins.listPlugins(IRolesPlugin)
            confirmedRoles = set()
            user = MockUser(user[usernameKey])
            for rolemaker_id, rolemaker in rolemakers:
                roles = rolemaker.getRolesForPrincipal(user, None)
                # Wichert Akkerman hints this may be evil. It might be running
                # the role provider plugins twice (PAS itself having done it the
                # first time) or something.
                if roles:
                    confirmedRoles.update(roles)
            for ii in requiredRoles:
                if ii not in confirmedRoles:
                    return None

        return user

classImplements(ExtractionPlugin, IExtractionPlugin)

class ApacheAuthPluginHandler(AutoUserMakerPASPlugin, ExtractionPlugin):
    """An aggregation of all the available apache PAS plugins."""

    meta_type = 'Apache Authentication'
    security = ClassSecurityInfo()

    def __init__(self, pluginId, title=None):
        ExtractionPlugin.__init__(self)
        AutoUserMakerPASPlugin.__init__(self, pluginId, title)

        self.rKey = re.compile(r'(.+)-(\d+)$')

    # A method to return the configuration page:
    security.declareProtected(ManageUsers, 'manage_config')
    manage_config = PageTemplateFile('config', globals())

    # A method to return the authorization mapping page:
    security.declareProtected(ManageUsers, 'manage_authz')
    manage_authz = PageTemplateFile('rolemap', globals())

    # Add a tab that calls that method:
    manage_options = ({'label': 'Options', 'action': 'manage_config'},
                      {'label': 'AuthZ', 'action': 'manage_authz'}) \
                     + BasePlugin.manage_options

    security.declareProtected(ManageUsers, 'getRoles')
    def getRoles(self):
        """Return a list of roles.

        Verify it returns an empty configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import \
                ApacheAuthPluginHandler
        >>> handler = ApacheAuthPluginHandler('someId')
        >>> handler = handler.__of__(self.portal.acl_users)
        >>> from pprint import pprint
        >>> sorted([role['id'] for role in handler.getRoles()])
        ['Contributor', 'Editor', 'Manager', 'Owner', 'Reader', 'Reviewer']
        """
        portalRoleManager = getToolByName(self, 'portal_role_manager')
        return [role for role in portalRoleManager.enumerateRoles()
                if role['id'] != 'Member']

    security.declareProtected(ManageUsers, 'getUsers')
    def getUsers(self):
        """Return the list of current users.

        Verify it returns a test default configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import \
                ApacheAuthPluginHandler
        >>> handler = ApacheAuthPluginHandler('someId')
        >>> handler = handler.__of__(self.portal.acl_users)
        >>> handler.getUsers()
        ['', 'test_user_1_']
        """
        sourceUsers = getToolByName(self, 'source_users')
        users = list(sourceUsers.getUserIds())
        users.insert(0, '')
        return users

    security.declareProtected(ManageUsers, 'getGroups')
    def getGroups(self):
        """Return the list of current groups.

        Verify it returns a test default configuration.
        >>> from Products.AutoUserMakerPASPlugin.auth import \
                ApacheAuthPluginHandler
        >>> handler = ApacheAuthPluginHandler('someId')
        >>> handler = handler.__of__(self.portal.acl_users)
        >>> handler.getGroups()
        ['Administrators', 'Reviewers']
        """
        sourceGroups = getToolByName(self, 'source_groups')
        return list(sourceGroups.getGroupIds())

    security.declareProtected(ManageUsers, 'getValue')
    def getValue(self, authz, kind, col):
        """Return the given configuration item as a string.

        This exists to handle the case of Shib tokens or roles getting removed
        or added while there are entries in authz_mappings."""
        try:
            return authz[kind][col]
        except (KeyError, IndexError):
            return ''

    security.declareProtected(ManageUsers, 'manage_changeConfig')
    def manage_changeConfig(self, REQUEST=None):
        """Update my configuration based on form data.

        Verify it returns nothing. More testing is done in the integration file.
        >>> from Products.AutoUserMakerPASPlugin.auth import \
                ApacheAuthPluginHandler
        >>> handler = ApacheAuthPluginHandler('someId')
        >>> handler.manage_changeConfig()

        """
        if not REQUEST:
            return None
        reqget = REQUEST.form.get
        strip = safe_int(reqget(stripDomainNamesKey, 1), default=1)
        if strip < 0: strip = 0
        if strip > 2: strip = 2
        # If Shib fields change, then update the authz_mappings property.
        tokens = self.getTokens()
        formTokens = tuple(reqget(httpAuthzTokensKey, '').splitlines())
        if tokens != formTokens:
            for ii in self.getMappings():
                saveVals = {}
                for jj in formTokens:
                    if ii['values'].has_key(jj):
                        saveVals[jj] = ii['values'][jj]
                    else:
                        saveVals[jj] = ''
                ii['values'] = saveVals
        # Save the form values
        self.manage_changeProperties({stripDomainNamesKey: strip,
            stripDomainNamesListKey: reqget(stripDomainNamesListKey, ''),
            httpRemoteUserKey: reqget(httpRemoteUserKey, ''),
            httpCommonnameKey: reqget(httpCommonnameKey, ''),
            httpDescriptionKey: reqget(httpDescriptionKey, ''),
            httpEmailKey: reqget(httpEmailKey, ''),
            httpLocalityKey: reqget(httpLocalityKey, ''),
            httpStateKey: reqget(httpStateKey, ''),
            httpCountryKey: reqget(httpCountryKey, ''),
            httpAuthzTokensKey: reqget(httpAuthzTokensKey, ''),
            httpSharingTokensKey: reqget(httpSharingTokensKey, ''),
            httpSharingLabelsKey: reqget(httpSharingLabelsKey, '')})
        return REQUEST.RESPONSE.redirect('%s/manage_config' %
                                         self.absolute_url())

    security.declareProtected(ManageUsers, 'manage_changeMapping')
    def manage_changeMapping(self, REQUEST=None):
        """Update mappings based on form data.

        Verify it returns nothing. More testing is done in the integration file.
        >>> from Products.AutoUserMakerPASPlugin.auth import \
                ApacheAuthPluginHandler
        >>> handler = ApacheAuthPluginHandler('someId')
        >>> handler.manage_changeMapping()
        """
        if not REQUEST:
            return None
        sources = self.getTokens()
        roles = self.getRoles()
        users = self.getUsers()
        groups = self.getGroups()
        authz = self.getMappings()
        # Pull the contents of the form in to a list formatted like authz to
        # allow us to check that the number of entries in the ZODB is the same
        # as the amount of input. This sort of handles somebody adding or
        # deleting a mapping from underneath somebody else.
        sets = []
        for ii in REQUEST.form.iterkeys():
            match = self.rKey.match(ii)
            if not match:
                continue
            index =  int(match.group(2))
            if len(sets) < index + 1:
                for jj in range(len(sets), index + 1):
                    sets.append(self.getMapping())
                    # set up all values, from property as check on incoming form
                    for kk in self.getProperty(httpAuthzTokensKey):
                        sets[jj]['values'][kk] = ''
                    # set up all roles, so ones not in REQUEST.form have
                    # an entry
                    for kk in roles:
                        sets[jj]['roles'][kk['id']] = ''
            if match.group(1) == 'auth':
                for jj in range(len(REQUEST.form[ii])):
                    sets[index]['values'][sources[jj]] = REQUEST.form[ii][jj]
            elif match.group(1) == 'userid':
                ii = REQUEST.form[ii]
                if ii in users:
                    sets[index]['userid'] = ii
            elif match.group(1) == 'groupid':
                sets[index]['groupid'] = []
                for ii in REQUEST.form[ii]:
                    if ii in groups:
                        sets[index]['groupid'].append(ii)
            elif sets[index]['roles'].has_key(match.group(1)):
                sets[index]['roles'][match.group(1)] = REQUEST.form[ii]
        if len(sets) != len(authz):
            return REQUEST.RESPONSE.redirect('%s/manage_authz' %
                                             self.absolute_url())
        # now process delete checkboxes
        deleteIds = REQUEST.form.get('delete_ids', [])
        # make sure deleteIds is a list on integers, in descending order
        deleteIds = [safe_int(did)
                     for did in deleteIds if safe_int(did, None) != None]
        deleteIds.sort(reverse=True)
        # now shorten without shifting indexes of items still to be removed
        for ii in deleteIds:
            try:
                sets.pop(ii)
            except IndexError:
                pass
        self.putMappings(sets)
        return REQUEST.RESPONSE.redirect('%s/manage_authz' %
                                         self.absolute_url())

    security.declareProtected(ManageUsers, 'manage_addMapping')
    def manage_addMapping(self, REQUEST=None):
        """Add a mapping based on form data.

        Verify it returns nothing. More testing is done in the integration file.
        >>> from Products.AutoUserMakerPASPlugin.auth import \
                ApacheAuthPluginHandler
        >>> handler = ApacheAuthPluginHandler('someId')
        >>> handler.manage_addMapping()
        """
        if not REQUEST:
            return None
        saveVals = self.getMapping()
        reqget = REQUEST.form.get
        auth = reqget('auth')
        if not auth or len(auth) != len(self.getTokens()):
            return REQUEST.RESPONSE.redirect('%s/manage_authz' %
                                             self.absolute_url())
        saveVals['values'] = dict(
		[(key, value) for key, value in zip(self.getTokens(), auth)])
        # loop through getRoles ensures no input other than currently
        # valid roles
        for role in self.getRoles():
            saveVals['roles'][role['id']] = reqget(role['id'], '')
        users = self.getUsers()
        userid = reqget('userid', '')
        if userid in self.getUsers():
            saveVals['userid'] = userid
        groups = self.getGroups()
        saveVals['groupid'] = [group for group in reqget('groupid', [])
				     if group in groups]
        self.addMappings(saveVals)
        return REQUEST.RESPONSE.redirect('%s/manage_authz' %
                                         self.absolute_url())

InitializeClass(ApacheAuthPluginHandler)
