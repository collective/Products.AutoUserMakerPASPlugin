from Products.PluggableAuthService.interfaces.authservice import IPluggableAuthService
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, IExtractionPlugin
from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler

def _firstIdOfClass(container, class_):
    """Return the id of the first object of class `class_` within `container`.
    If there is none, return None."""
    for id in container.objectIds():
        if isinstance(container[id], class_):
            return id
    return None

def addAutoUserMakerPASPlugin(context):
    """Find the nearest acl_users and adds and activates an Auto User Maker.

    Return a 1-tuple with the new Auto User Maker as its only element."""

    acl_users = getattr(context, 'acl_users', None)
    if acl_users is None:
        raise LookupError("No acl_users can be acquired or otherwise found.")

    pas = IPluggableAuthService(acl_users, None)
    if pas is None:
        raise ValueError("The nearest acl_users object is not a PluggableAuthService.")

    pluginId = _firstIdOfClass(acl_users, ApacheAuthPluginHandler)
    if not pluginId:
        pluginId = 'AutoUserMakerPASPlugin'
        setup = acl_users.manage_addProduct[pluginId]
        setup.manage_addAutoUserMaker(pluginId, 'AutoUserMakerPAS Plugin')

    plugins = acl_users.plugins
    for interface in [IAuthenticationPlugin, IExtractionPlugin]:
        plugins.activatePlugin(interface, pluginId)

    return pas[pluginId]
