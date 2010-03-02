#
from AccessControl.Permissions import add_user_folders
from Products.PluggableAuthService import registerMultiPlugin
from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
from Products.AutoUserMakerPASPlugin import zmi

registerMultiPlugin(ApacheAuthPluginHandler.meta_type)

def initialize(context):
    """Intializer called when used as a Zope 2 product."""
    context.registerClass(ApacheAuthPluginHandler,
                          permission=add_user_folders,
                          constructors=(zmi.manage_addAutoUserMakerForm,
                                        zmi.manage_addAutoUserMaker),
                          visibility=None,
                          icon='autousermaker.gif')
