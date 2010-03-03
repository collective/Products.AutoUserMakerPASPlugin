# This lets you install AutoUserMaker through Plone, if you're into that. If you
# aren't using Plone, it doesn't hurt anything.

from Products.CMFCore.utils import getToolByName
from Products.PluggableAuthService.interfaces.plugins import (
    IAuthenticationPlugin, IExtractionPlugin)
from Products.PluggableAuthService.PluggableAuthService import logger
from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler

def _firstIdOfClass(container, class_):
    """ Return the id of the first object of class `class_` within `container`.
    If there is none, return None.
    """
    for id in container.objectIds():
        if isinstance(container[id], class_):
            return id

def install(portal, reinstall=False):
    acl_users = getToolByName(portal, 'acl_users')

    # Put an apachepas multiplugin in the acl_users folder, if there isn't one:
    pluginId = _firstIdOfClass(acl_users, ApacheAuthPluginHandler)
    if not pluginId:
        pluginId = 'AutoUserMakerPASPlugin'
        # http://wiki.zope.org/zope2/ObjectManager
        constructors = acl_users.manage_addProduct[pluginId]
        constructors.manage_addAutoUserMaker(pluginId,
                                             title='AutoUserMakerPAS Plugin')

    # Activate it:
    plugins = acl_users.plugins
    for interface in [IAuthenticationPlugin, IExtractionPlugin]:
        try:
            plugins.activatePlugin(interface, pluginId)  # plugins is a PluginRegistry
        except KeyError:
            continue

    if reinstall:
        import pickle
        plugin = getattr(plugins, pluginId)
        #logger.info("plugin = %s" % repr(plugin))
        # Get the configuration out of the property, and delete the property.
        try:
            prop = "\n".join(acl_users.getProperty('aum_config'))
            #logger.info("aum_config = %s" % repr(prop))
            config = pickle.loads(prop)
        except Exception, err:
            logger.info("error getting config: %s of %r" % (str(err), repr(err)))
        try:
            prop = "\n".join(acl_users.getProperty('aum_mappings'))
            #logger.info("aum_mappings = %s" % repr(prop))
            mappings = pickle.loads(prop)
        except Exception, err:
            logger.info("error getting mappings: %s of %r" % (str(err), repr(err)))
        # Now restore the configuration
        #logger.info("config = %s" % repr(config))
        for prop in plugin.propertyMap():
            if config.has_key(prop['id']):
                try:
                    val = config[prop['id']]['value']
                    if prop['type'] == 'lines':
                        val = "\n".join(val)
                    #logger.info("setting %s to %s" % (prop['id'], repr(val)))
                    if config[prop['id']]['type'] == prop['type']:
                        plugin.manage_changeProperties({prop['id']: val})
                    elif prop['type'] == 'int':
                        try:
                            plugin.manage_changeProperties({prop['id']: int(val)})
                        except TypeError:
                            pass
                    else:
                        plugin.manage_changeProperties({prop['id']: str(val)})
                except Exception, err:
                    logger.info("error in install: %s" % str(err))
        # Now restore the mappings.
        #logger.info("settings mappings to %s" % str(mappings))
        plugin.putMappings(mappings)
    for ii in ('aum_config', 'aum_mappings'):
        try:
            acl_users.manage_delProperties([ii])
        except:
            pass

def uninstall(portal, reinstall=False):
    acl_users = getToolByName(portal, 'acl_users')
    pluginId = _firstIdOfClass(acl_users, ApacheAuthPluginHandler)
    if pluginId:                 # only if the plugin is installed
        if reinstall:           # only if install() above is going to run next
            import pickle
            plugin = getattr(acl_users.plugins, pluginId)
            # Get the current configuration
            config = {}
            for prop in plugin.propertyMap():
                #logger.info("property = %s" % str(prop))
                config[prop['id']] = prop
                config[prop['id']]['value'] = plugin.getProperty(prop['id'])
                #logger.info("value = %s" % (str(config[prop['id']]['value'])))
            # and stick it in a property for temporary storage.
            # There's got to be a better way to do this.
            conf = pickle.dumps(config)
            #logger.info("config = %s" % repr(conf))
            acl_users.manage_addProperty(id='aum_config', type='lines', value=conf)
            # Do the same for the mappings
            mappings = pickle.dumps(plugin.getMappings())
            #logger.info("mappings = %s" % repr(mappings))
            acl_users.manage_addProperty(id='aum_mappings', type='lines', value=mappings)
        acl_users.manage_delObjects(ids=[pluginId])  # implicitly deactivates
