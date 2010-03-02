"""Used in installing AutoUserMakerPASPlugin."""

__revision__ = '1.2'

from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.AutoUserMakerPASPlugin.auth import ApacheAuthPluginHandler

manage_addAutoUserMakerForm = PageTemplateFile('add-AutoUserMakerPASPlugin.zpt', globals())

def manage_addAutoUserMaker(self, pluginId, title='', REQUEST=None):
    """Add an Auto User Maker to a Pluggable Auth Service."""

    handler = ApacheAuthPluginHandler(pluginId, title)
    self._setObject(handler.getId(), handler)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect('%s/manage_workspace'
                                     '?manage_tabs_message='
                                     'AutoUserMakerPASPlugin+added.'
                                     % self.absolute_url())
