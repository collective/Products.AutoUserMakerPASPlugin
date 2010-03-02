#
from AccessControl.Permissions import add_user_folders
from Products.PluggableAuthService import registerMultiPlugin
try:
    from AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
except ImportError:
    from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler
try:
    from AutoUserMakerPASPlugin import zmi
except ImportError:
    from Products.AutoUserMakerPASPlugin import zmi

try:
    registerMultiPlugin(ApacheAuthPluginHandler.meta_type)
except RuntimeError:
    # make refresh users happy
    pass


aum_globals = globals()

def initialize(context):
    """Intializer called when used as a Zope 2 product."""
    context.registerClass(ApacheAuthPluginHandler,
                          permission=add_user_folders,
                          constructors=(zmi.manage_addAutoUserMakerForm,
                                        zmi.manage_addAutoUserMaker),
                          visibility=None,
                          icon='autousermaker.gif')
