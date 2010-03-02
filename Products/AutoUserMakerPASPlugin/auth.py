#!/usr/bin/env python
"""Classes to connect apache authentication into Zope/Plone."""
__revision__ = "0.4"

from random import choice
import pickle
import re

from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem
from Products.CMFCore.utils import getToolByName
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins \
	import IAuthenticationPlugin, IExtractionPlugin, IRoleAssignerPlugin, \
		   IRolesPlugin, IUserAdderPlugin
from Products.PluggableAuthService.permissions import ManageUsers
from Products.PluggableAuthService.PluggableAuthService import logger
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from persistent.list import PersistentList

try:
	from Products.PluggableAuthService import _SWALLOWABLE_PLUGIN_EXCEPTIONS
except ImportError:  # in case that private const goes away someday
	_SWALLOWABLE_PLUGIN_EXCEPTIONS = (NameError, AttributeError, KeyError, TypeError, ValueError)

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

class AutoUserMakerPASPlugin(BasePlugin):
	"""An authentication plugin that expects a mapping like ExtractionPlugin
	returns, makes the user specified therein, gives him the Member role so
	Plone treats recognizes him, assigns local permissions if ShibbolethPermissions
	is installed and passes control to the next authentication plugin.

	This unittest doesn't show much since this really needs integration testing:
	>>> from Products.AutoUserMakerPASPlugin.auth import AutoUserMakerPASPlugin
	>>> AutoUserMakerPASPlugin('test').authenticateCredentials({})

	>>> AutoUserMakerPASPlugin('test').authenticateCredentials({'user_id': 'foobar'})
	('foobar', 'foobar')
	"""
	security = ClassSecurityInfo()

	def __init__(self, pluginId, title=None):
		BasePlugin.__init__(self, pluginId, title)
		self.id = pluginId
		self.title = title

	security.declarePrivate('authenticateCredentials')
	def authenticateCredentials(self, credentials):
		"""See class's docstring and IAuthenticationPlugin."""
		#logger.info("authenticateCredentials(%r)" % repr(credentials))
		mappings = credentials.pop('_getMappings', [])

		userId = credentials.get(usernameKey, None)
		#logger.info("user_id = %s" % str(userId))
		if userId is not None and self._getPAS() is not None and \
			self._getPAS().getUserById(userId) is None:
			# Make a user with id `userId`, and assign him at least the Member
			# role, since user doesn't exist.

			def generatePassword():
				"""Return a random password, not necessarily easy to type or remember."""
				# I repeat RegistrationTool.generatePassword() here because
				# I don't want this product dependent on Plone. It could
				# conceivably be useful with just Zope. We might as well use the
				# same typo avoidance, though, in case somebody decides to stop
				# delegating auth once they've already started.
				chars = 'ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
				return ''.join([choice(chars) for ii in range(6)])

			# I could just call self._getPAS()._doAddUser(...), but that's
			# private and not part of the IPluggableAuthService interface. It
			# might break someday. So the following is based on
			# PluggableAuthService._doAddUser():

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
						membershipTool = getToolByName(self, 'portal_membership')
						if not membershipTool.getHomeFolder(userId):
							membershipTool.createMemberArea(userId)
					except Exception, e:
						logger.warning("error creating for home folder: %r = %s" % (e, e))
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
								# and compare the pattern to the environment value
								match = oRe.search(credentials['filters'][ii])
							except Exception, e:
								logger.warning("error in regular expression %s for %s: %s" % \
									(str(role['values'][ii]), str(credentials['filters'][ii]), str(e)))
								match = False
							if match:
								assignRole = True
						if not assignRole:
							break
					# either there was no pattern or the pattern matched
					# for every mapping, so add specified roles or groups.
					if assignRole:
						for ii in role['roles'].iterkeys():
							#logger.info("role['roles'][%s] = %s" % (ii, str(role['roles'][ii])))
							if role['roles'][ii] == 'on':
								#logger.info("found checked role %s" % ii)
								roles[ii] = True
						for ii in role['groupid']:
							groups.append(ii)

			# Map the given roles to the user using all available
			# IRoleAssignerPlugins (just like doAddUser does for some reason):
			for curAssignerId, curAssigner in roleAssigners:
				for role in roles.iterkeys():
					#logger.info("assigning role %s" % str(role))
					try:
						curAssigner.doAssignRoleToPrincipal(user.getId(), role)
					except _SWALLOWABLE_PLUGIN_EXCEPTIONS:
						logger.warning('RoleAssigner %s error' % curAssignerId, exc_info=True)

			source_groups = getToolByName(self, 'source_groups')
			for ii in groups:
				#logger.info("assigning %s group membership" % ii)
				source_groups.addPrincipalToGroup(user.getId(), ii)

			#logger.info("looking for ShibbolethPermissions")
			shibPerms = getToolByName(self, 'ShibbolethPermissions', None)
			#logger.info("got %s" % str(shibPerms))
			try: # Ignore any error here, since it just means the user didn't
				#  get permissions on something. Not ignoring means the user
				#  will see a plone page that doesn't look like the user has
				#  logged in.
				if shibPerms:
					uservals = credentials.get('localperms', None)
					#logger.info("uservals = %r" % repr(uservals))
					if uservals:
						for path, regexs in shibPerms.getLocalRoles().iteritems():
							#logger.info("checking path %s" % path)
							for ii in regexs:
								#logger.info("for data %r" % repr(ii))
								found = True
								# Make sure the incoming user has all of the needed attributes
								for name in ii.iterkeys():
									if name == '_roles':
										continue
									if not uservals.has_key(name):
										#logger.info("%s does not have a %s key" % (str(uservals), name))
										found = False
									if not found:
										break
								if found:
									#logger.info("User has all of the attributes; making sure they match.")
									for name, pattern in ii.iteritems():
										#logger.info(" name = %s, pattern = %s" % (name, pattern))
										if name == '_roles' or uservals[name] is None:
											continue
										try:
											regex = re.compile(pattern)
											if not regex.search(uservals[name]):
												logger.info("pattern %s for %s does not match %s" % (name, pattern, uservals[name]))
												found = False
										except Exception, e:
											logger.warning("error in regular expression %s for name %s: %s" % \
												(pattern, name, str(e)))
										if not found:
											break
								if found:
									#logger.info("all attributes match, setting permissions")
									# All of the attributes match
									obj = self.unrestrictedTraverse(path)
									#logger.info("Setting permissions on %r" % repr(obj))
									for role in ii['_roles']:
										#logger.info("setting %s on %s" % (roles, path))
										obj.manage_setLocalRoles(userId, role)
									obj.reindexObjectSecurity()
			except Exception, e:
				logger.warning("error processing local roles: %s" % str(e))
		#logger.info("authenticateCredentials returning: %s" % str(userId))
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
	"""A simple extraction plugin that retrieves its credentials
	information from a successful apache authentication.

	Usage info:
	>>> class MockRequest:
	...     def __init__(self, environ={}):
	...         self.environ = environ
	>>> request = MockRequest({'HTTP_X_REMOTE_USER': 'foobar'})

	ExtractionPlugin is an abstract class, but ApacheAuthPluginHandler fills it out.
	>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
	>>> handler = ApacheAuthPluginHandler('someId')
	>>> handler.extractCredentials(request)
	{'user_id': 'foobar', 'description': None, 'localperms': {}, 'location': '', 'filters': {}, 'fullname': None, '_getMappings': [], 'email': None}

	"""
	security = ClassSecurityInfo()

	def __init__(self):
		config = ((stripDomainNamesKey, 'int', 'w', 1),
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
			ids[prop[0]] = True   # keep track of property names for quick lookup
			if prop[0] not in self.propertyIds():
				self.manage_addProperty(id=prop[0],
										type=prop[1],
										value=prop[3])
				self._properties[-1]['mode'] = prop[2]
		# Delete any existing properties that aren't in config
		for prop in self._properties:
			if not ids.has_key(prop['id']) and prop['id'] != 'prefix':
				#logger.info("deleting %s" % (repr(prop)))
				self.manage_delProperties(prop['id'])
		# Get a list for storing mappings
		try:
			self.authzMappings = PersistentList()
		except Exception, err:
			logger.warning("error creating authzMappings: %s" % str(err), exc_info=True)

	security.declareProtected(ManageUsers, 'getConfig')
	def getConfig(self):
		"""Return a mapping of my configuration values, for use in a page template.

		Verify it returns an empty configuration.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.getConfig()
		{'http_state': ('HTTP_SHIB_ORGPERSON_STATE',), 'strip_domain_name_list': (), 'http_remote_user': ('HTTP_X_REMOTE_USER',), 'http_authz_tokens': (), 'strip_domain_names': 1, 'http_email': ('HTTP_SHIB_INETORGPERSON_MAIL',), 'http_commonname': ('HTTP_SHIB_PERSON_COMMONNAME',), 'http_sharing_tokens': (), 'http_locality': ('HTTP_SHIB_ORGPERSON_LOCALITY',), 'http_sharing_labels': (), 'http_description': ('HTTP_SHIB_ORGPERSON_TITLE',), 'http_country': ('HTTP_SHIB_ORGPERSON_C',)}
		"""
		return {stripDomainNamesKey: self.getProperty(stripDomainNamesKey),
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
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.getSharingConfig()
		{'http_sharing_tokens': (), 'http_sharing_labels': ()}
		"""
		return {httpSharingTokensKey: self.getProperty(httpSharingTokensKey),
				httpSharingLabelsKey: self.getProperty(httpSharingLabelsKey)}

	security.declareProtected(ManageUsers, 'getTokens')
	def getTokens(self):
		"""Return http_authz_tokens as a tupple (how getProperty returns it).

		Verify it returns an empty configuration.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.getTokens()
		()
		"""
		return self.getProperty(httpAuthzTokensKey)

	security.declareProtected(ManageUsers, 'getMapping')
	def getMapping(self):
		return {'version': 1, 'values': {}, 'roles': {}, 'userid': '', 'groupid': []}

	security.declareProtected(ManageUsers, 'getMappings')
	def getMappings(self):
		"""Return authzMappings as a list of dictionaries.

		Verify it returns an empty configuration.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.getMappings()
		[]
		"""
		try:
			rval = []
			for ii in self.authzMappings:
				rval.append(ii)
			return rval
		except Exception, err:
			#logger.info("error returning authzMappings: %s" % str(err), exc_info=True)
			return []

	security.declareProtected(ManageUsers, 'putMappings')
	def putMappings(self, authz):
		"""Save the input as authzMappings."""
		#logger.info("saving self.authzMappings as %r" % repr(authz))
		self.authzMappings = []
		for ii in authz:
			self.authzMappings.append(ii)

	security.declareProtected(ManageUsers, 'addMappings')
	def addMappings(self, authz):
		"""Append the input to authzMappings."""
		#logger.info("appending to self.authzMappings %r" % repr(authz))
		self.authzMappings.append(authz)

	security.declarePrivate('requiredRoles')
	def requiredRoles(self):
		"""Extract the required roles from the property.

		Verify it returns an empty configuration.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.requiredRoles()
		()
		"""
		return self.getProperty('required_roles', [])

	security.declarePrivate('loginUsers')
	def loginUsers(self):
		"""Extract the login users from the property.

		Verify it returns an empty configuration.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
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

		#logger.info("extractCredentials(%r)" % repr(request.environ))
		config = self.getConfig()
		#logger.info("config = %r" % repr(config))
		user = {'location': '', 'filters': {}, 'localperms': {}}
		for ii in ((usernameKey, httpRemoteUserKey),
				   ('fullname', httpCommonnameKey),
				   ('description', httpDescriptionKey),
				   ('email', httpEmailKey)):
			try:
				for jj in config[ii[1]]:
					user[ii[0]] = request.environ.get(jj, None)
					if user[ii[0]]:
						break
			except (IndexError, TypeError), err:
				logger.warning("user attribute configuration error: %s" % str(err), exc_info=True)
		#logger.info("user = %r" % repr(user))
		if not user[usernameKey] or user[usernameKey] == '(null)':
			return None

		# clean up the user id, if told to do so
		if config[stripDomainNamesKey] and user[usernameKey].find('@') > 0:
			# With some Apache setups, the username is returned as 'user123@some.domain.name'.
			nameDomain = user[usernameKey].split('@', 1)
			if len(nameDomain) == 1 or \
			   config[stripDomainNamesKey] == 1 or \
			   (config[stripDomainNamesKey] == 2 and \
				nameDomain[1] in config[stripDomainNamesListKey]):
				user[usernameKey] = nameDomain[0]
		#logger.info("user_id = %s" % user[usernameKey])

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
		#logger.info("user['location'] = %s" % user['location'])

		# save the values of any authz filter
		for ii in self.getTokens():
			user['filters'][ii] = request.environ.get(ii, None)
		#logger.info("user['filters'] = %r" % repr(user['filters']))

		# save the values of any local authz filter
		sharing = self.getSharingConfig()
		for ii in sharing[httpSharingTokensKey]:
			user['localperms'][ii] = request.environ.get(ii, None)
		#logger.info("user['localperms'] = %r" % repr(user['localperms']))

		# See if this Shib user should map to a specific existing plone user
		try:
			sourceUsers = getToolByName(self, 'source_users')
		except Exception, err:
			logger.warning("error getting source_users: %s" % str(err), exc_info=True)
		for role in self.authzMappings:
			#logger.info("role = %r" % repr(role))
			# if this role mapping doesn't list a userid, skip it.
			if not role['userid']:
				continue
			# verify this userid actually exists in plone
			try:
				ploneUser = sourceUsers.getUserInfo(role['userid'])
				#logger.info("mapped to %r" % repr(ploneUser))
			except KeyError:
				continue
			# for each source given in authz_mappings
			for ii in role['values'].iterkeys():
				#logger.info("checking role: %s" % ii)
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
				#logger.info("returning user %r" % repr(ploneUser))
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

		#logger.info("extractCredentials returning: %r" % repr(user))
		return user

classImplements(ExtractionPlugin, IExtractionPlugin)

class ApacheAuthPluginHandler(AutoUserMakerPASPlugin, ExtractionPlugin):
	"""An aggregation of all the available apache PAS plugins."""

	meta_type = 'Apache Authentication'
	security = ClassSecurityInfo()

	def __init__(self, pluginId, title=None):
		ExtractionPlugin.__init__(self)
		AutoUserMakerPASPlugin.__init__(self, pluginId, title)

		self._id = self.id = pluginId  # What's _id for?
		self.title = title
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
	def getRoles(self, context):
		"""Return a list of roles.

		Verify it returns an empty configuration.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.getRoles(self.portal.acl_users)
		[{'members_url': 'portal_role_manager/manage_roles?role_id=Manager&assign=1', 'description': '', 'title': '', 'properties_url': 'portal_role_manager/manage_roles?role_id=Manager', 'pluginid': 'portal_role_manager', 'id': 'Manager'}, {'members_url': 'portal_role_manager/manage_roles?role_id=Owner&assign=1', 'description': '', 'title': '', 'properties_url': 'portal_role_manager/manage_roles?role_id=Owner', 'pluginid': 'portal_role_manager', 'id': 'Owner'}, {'members_url': 'portal_role_manager/manage_roles?role_id=Reviewer&assign=1', 'description': '', 'title': '', 'properties_url': 'portal_role_manager/manage_roles?role_id=Reviewer', 'pluginid': 'portal_role_manager', 'id': 'Reviewer'}]
		"""
		portalRoleManager = getToolByName(context, 'portal_role_manager')
		roles = list(portalRoleManager.enumerateRoles())
		for ii in range(len(roles)):
			if roles[ii]['id'] == 'Member':
				roles.pop(ii)
				break
		#logger.info("str(roles) = %s" % str(roles))
		return roles

	security.declareProtected(ManageUsers, 'getUsers')
	def getUsers(self, context):
		"""Return the list of current users.

		Verify it returns a test default configuration.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.getUsers(self.portal.acl_users)
		['', 'test_user_1_']
		"""
		users = ['', ]
		sourceUsers = getToolByName(context, 'source_users')
		for ii in sourceUsers.getUserIds():
			users.append(str(ii))
		return users

	security.declareProtected(ManageUsers, 'getGroups')
	def getGroups(self, context):
		"""Return the list of current groups.

		Verify it returns a test default configuration.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.getGroups(self.portal.acl_users)
		['Administrators', 'Reviewers']
		"""
		groups = []
		sourceGroups = getToolByName(context, 'source_groups')
		for ii in sourceGroups.getGroupIds():
			groups.append(str(ii))
		return groups

	security.declareProtected(ManageUsers, 'getValue')
	def getValue(self, authz, row, kind, col):
		"""Return the given configuration item as a string.

		This exists to handle the case of Shib tokens or roles getting removed
		or added while there are entries in authz_mappings."""
		try:
			return authz[row][kind][col]
		except (KeyError, IndexError):
			return ''

	security.declareProtected(ManageUsers, 'manage_changeConfig')
	def manage_changeConfig(self, REQUEST=None):
		"""Update my configuration based on form data.

		Verify it returns nothing. More testing is done in the integration file.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.manage_changeConfig()

		"""
		#logger.info("%r\n" % repr(REQUEST.form))
		if not REQUEST:
			return None
		try:
			strip = int(REQUEST.form.get(stripDomainNamesKey, 1))
		except ValueError:
			strip = 1
		if strip < 0: strip = 0
		if strip > 2: strip = 2
		# If Shib fields change, then update the authz_mappings property.
		tokens = self.getTokens()
		formTokens = tuple(REQUEST.form.get(httpAuthzTokensKey, '').splitlines())
		#logger.info("%r == %r -> %s" % (repr(tokens), repr(formTokens), str(tokens == formTokens)))
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
			stripDomainNamesListKey: REQUEST.form.get(stripDomainNamesListKey, ''),
			httpRemoteUserKey: REQUEST.form.get(httpRemoteUserKey, ''),
			httpCommonnameKey: REQUEST.form.get(httpCommonnameKey, ''),
			httpDescriptionKey: REQUEST.form.get(httpDescriptionKey, ''),
			httpEmailKey: REQUEST.form.get(httpEmailKey, ''),
			httpLocalityKey: REQUEST.form.get(httpLocalityKey, ''),
			httpStateKey: REQUEST.form.get(httpStateKey, ''),
			httpCountryKey: REQUEST.form.get(httpCountryKey, ''),
			httpAuthzTokensKey: REQUEST.form.get(httpAuthzTokensKey, ''),
			httpSharingTokensKey: REQUEST.form.get(httpSharingTokensKey, ''),
			httpSharingLabelsKey: REQUEST.form.get(httpSharingLabelsKey, '')})
		return REQUEST.RESPONSE.redirect('%s/manage_config' % self.absolute_url())

	security.declareProtected(ManageUsers, 'manage_changeMapping')
	def manage_changeMapping(self, REQUEST=None):
		"""Update mappings based on form data.

		Verify it returns nothing. More testing is done in the integration file.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.manage_changeMapping()
		"""
		#logger.info("%r\n" % repr(REQUEST.form))
		if not REQUEST:
			return None
		sources = self.getTokens()
		roles = self.getRoles(self)
		users = self.getUsers(self)
		groups = self.getGroups(self)
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
					# set up all roles, so ones not in REQUEST.form have an entry
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
			return REQUEST.RESPONSE.redirect('%s/manage_authz' % self.absolute_url())
		# now process delete checkboxes
		deleteIds = REQUEST.form.get('delete_ids', [])
		# make sure deleteIds is a list on integers, in descending order
		for ii in range(len(deleteIds)):
			try:
				deleteIds[ii] = int(deleteIds[ii])
			except ValueError:
				continue
		deleteIds.sort(reverse=True)
		#logger.info("delete ids: %r\n" % repr(deleteIds))
		# now shorten without shifting indexes of items still to be removed
		for ii in deleteIds:
			try:
				sets.pop(ii)
			except IndexError:
				pass
		self.putMappings(sets)
		return REQUEST.RESPONSE.redirect('%s/manage_authz' % self.absolute_url())

	security.declareProtected(ManageUsers, 'manage_addMapping')
	def manage_addMapping(self, REQUEST=None):
		"""Add a mapping based on form data.

		Verify it returns nothing. More testing is done in the integration file.
		>>> from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
		>>> handler = ApacheAuthPluginHandler('someId')
		>>> handler.manage_addMapping()
		"""
		#logger.info("REQUEST = %r\n" % repr(REQUEST.form))
		if not REQUEST:
			return None
		saveVals = self.getMapping()
		jj = 0
		auth = REQUEST.form.get('auth')
		if not auth or len(auth) != len(self.getTokens()):
			return REQUEST.RESPONSE.redirect('%s/manage_authz' % self.absolute_url())
		# loop through getTokens values, saving 'paired' setting
		# XXX: I'm not crazy about this, because a change in the tokens list
		# while another browser windows has the form open will result in the
		# wrong permissions getting assigned.
		for ii in self.getTokens():
			try:
				saveVals['values'][ii] = auth[jj]
			except Exception, err:
				logger.warning("saveVales['values'][%s] = %s yeilds %s" % (ii, auth[jj], str(err)), exc_info=True)
			jj += 1
		# loop through getRoles ensures no input other than currently valied roles
		for ii in self.getRoles(self):
			saveVals['roles'][ii['id']] = REQUEST.form.get(ii['id'], '')
		users = self.getUsers(self)
		ii = REQUEST.form.get('userid', '')
		if ii in users:
			saveVals['userid'] = ii
		groups = self.getGroups(self)
		for ii in REQUEST.form.get('groupid', []):
			if ii in groups:
				saveVals['groupid'].append(ii)
		#logger.info("saveVals = %r\n" % repr(saveVals))
		self.addMappings(saveVals)
		return REQUEST.RESPONSE.redirect('%s/manage_authz' % self.absolute_url())

InitializeClass(ApacheAuthPluginHandler)
