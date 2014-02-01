Overview
========

Accept Apache based authentication in Zope and create Plone users.

*AutoUserMakerPasPlugin* is a PAS plugin developed from apachepas, which allows
Zope to delegate authentication concerns to Apache, and that automatically
creates users as Apache lets them through. Using *AutoUserMakerPasPlugin*, you
can configure your Plone site so any user known to your LDAP, Kerberos,
Shibboleth, or Cosign (a.k.a. WebAccess) system--or indeed any other system
which has an Apache authentication module--can transparently log in using his
enterprise-wide credentials.

If you want only a few select users to be able to log into your site, don't
use Auto User Maker; stick to just apachepas, and create your few users
manually. If, however, you want anyone with enterprise credentials to be
able to authenticate, read on.


Requirements
============

* Zope and Plone. Tested with Zope 2.9.7 and Plone 2.5.3, and Zope 2.10.5 and
  Plone 3.0.6.

* PluggableAuthService (included with Plone 2.5.x and maybe earlier).

* I test this with Shibboleth, currently 2.0 service provider.

Installation
============

1. Unzip the AutoUserMakerPASPlugin.zip file in $INSTANCE_HOME/Products.

2. Restart Zope.

3. Install the plugin:

    If you're using Plone...

        1. Go to your-plone-site -> site setup -> Add/Remove Products,
           and install AutoUserMakerPASPlugin.

    If you're not using Plone...

        1. In the Zope Management Interface, navigate to your-plone-site ->
           acl_users.

        2. Add an Auto User Maker to the folder.

        3. Navigate to your-plone-site -> acl_users -> plugins ->
           Authentication Plugins.

        2. Go to the Activate tab of your newly created Auth User Make instance,
           and turn on Authentication and Extraction.

4. Set up the required Apache directives. For example:

::

        # Some Linux distributions (e.g., Debian Etch and Red Hat Enterprise
        # Linux AS Release 4) have default settings which prevent the header
        # rewrites below from working. Fix that:
        <Proxy *>
            Order deny,allow
            Allow from all
        </Proxy>

        RewriteEngine On

        # Grab the remote user as environment variable.
        # (This RewriteRule doesn't actually rewrite anything URL-wise.)
        RewriteCond %{LA-U:REMOTE_USER} (.+)
        RewriteRule .* - [E=RU:%1]

        # Put the username into a request header:
        RequestHeader set X_REMOTE_USER %{RU}e

        # For Shibboleth SP 2.0, you must also set HTTP headers, if you want
        # account data populated.
		#RequestHeader set SHIB_PERSON_COMMONNAME %{displayName}e
        #RequestHeader set SHIB_INETORGPERSON_MAIL %{mail}e
        #RequestHeader set SHIB_ORGPERSON_LOCALITY %{l}e
        #RequestHeader set SHIB_ORGPERSON_STATE %{st}e
        #RequestHeader set SHIB_ORGPERSON_C %{c}e

		# Don't send shib stuff to plone
		RewriteCond %{REQUEST_URI} !^/(shibboleth-(sp|idp)|Shibboleth.sso|SAML)
        # Do the typical VirtualHostMonster rewrite:
        RewriteRule ^/port_8080(.*) http://localhost:8080/VirtualHostBase/http//localhost:80/VirtualHostRoot/_vh_port_8080/$1 [L,P]

I (Alan Brenner) used the following on a virtual interface on my Apache 2.2 and
Shibboleth 1.3 development system:

::

        Listen 192.168.191.1:80
        <VirtualHost 192.168.191.1:80>
            ServerName alan.ithaka.org
            DocumentRoot /usr/local/apache-httpd-2.2.4/htdocs
            ProxyRequests Off
            ProxyPass /server-status !
            ProxyPass /server-info !
            ProxyPass /index.php !
            ProxyPass /Shibboleth.sso !
            ProxyPass /shibboleth-sp !
            ProxyPass /shibboleth-idp !
            ProxyPass /php !
            ProxyPass / http://127.0.0.1:8253/VirtualHostBase/http/alan.ithaka.org:80/test/VirtualHostRoot/

            LoadModule mod_shib /usr/local/shibboleth-sp-1.3/libexec/mod_shib_22.so
            ShibSchemaDir /usr/local/shibboleth-sp-1.3/share/xml/shibboleth
            ShibConfig /usr/local/shibboleth-sp-1.3/etc/shibboleth/shibboleth.xml
            ShibURLScheme http
            <Location /php>
                AuthType shibboleth
                ShibRedirectToSSL 443
                # An index.php like:
                #<html><head><title>shib test</title></head><body><?php phpinfo(); ?></body></html>
                # is helpful to validate security, and see what values shib is setting.
            </Location>
        </VirtualHost>

        <Location /shibboleth-idp/SSO>
            AuthType Basic
            AuthName Test
            AuthUserFile /usr/local/apache-httpd-2.2.4/conf/users
            require valid-user
        </Location>

        <IfModule !mod_jk.c>
            LoadModule jk_module modules/mod_jk.so
            JkShmFile /usr/local/apache-httpd-2.2.4/logs/jk-runtime-status
            JkWorkersFile /usr/local/apache-tomcat-5.5.23/conf/jk/workers.properties
            JkLogFile /var/log/httpd/mod_jk.log
        </IfModule>
        JkLogLevel emerg
        JkMount /shibboleth-idp/* ajp13
        JkMount /jsp-examples ajp13
        JkMount /jsp-examples/* ajp13
        JkMount /tomcat-docs ajp13
        JkMount /tomcat-docs/* ajp13
        JkMount /admin ajp13
        JkMount /admin/* ajp13

        Listen 443
        <VirtualHost 192.168.191.1:443>
            DocumentRoot "/usr/local/apache-httpd-2.2.4/htdocs"
            ServerName alan.ithaka.org
            ServerAdmin alan.brenner@ithaka.org
            ErrorLog /usr/local/apache-httpd-2.2.4/logs/error_log.443
            TransferLog /usr/local/apache-httpd-2.2.4/logs/access_log.443
            SSLEngine on
            SSLCipherSuite ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL
            SSLCertificateFile /usr/local/shibboleth-sp-1.3/etc/shibboleth/idp.crt
            SSLCertificateKeyFile /usr/local/shibboleth-sp-1.3/etc/shibboleth/idp.key
            <FilesMatch "\.(cgi|shtml|phtml|php)$">
                SSLOptions +StdEnvVars
            </FilesMatch>
            <Proxy *>
                Order deny,allow
                Allow from all
            </Proxy>
            RewriteEngine On
            RewriteCond %{LA-U:REMOTE_USER} (.+)
            RewriteRule .* - [E=RW_RU:%1]
            RequestHeader set X_REMOTE_USER %{RW_RU}e
            RewriteCond %{REQUEST_URI} !^/(shibboleth-(sp|idp)|Shibboleth.sso|SAML|WAYF|server-(status|info)|index.php|php)
            RewriteRule ^/(.*) http://127.0.0.1:8253/VirtualHostBase/https/alan.ithaka.org:443/test/VirtualHostRoot/$1 [L,P]
            <Location />
                AuthType shibboleth
                ShibRequireSession Off
                require shibboleth
            </Location>
        </VirtualHost>

        Listen 8443
        <VirtualHost 192.168.191.1:8443>
            ErrorLog /usr/local/apache-httpd-2.2.4/logs/error_log.8443
            TransferLog /usr/local/apache-httpd-2.2.4/logs/access_log.8443
            SSLEngine on
            SSLCipherSuite ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP
            SSLVerifyClient optional_no_ca
            SSLVerifyDepth 10
            SSLOptions +StdEnvVars +ExportCertData
            SSLCertificateFile /usr/local/shibboleth-sp-1.3/etc/shibboleth/idp.crt
            SSLCertificateKeyFile /usr/local/shibboleth-sp-1.3/etc/shibboleth/idp.key
            ProxyRequests Off
        </VirtualHost>

I use this for Apache 2.2 and Shibboleth 2.0 (and please see the page at
https://spaces.internet2.edu/display/SHIB2/IdPSPLocalTestInstall for a more
complete set of instructions on the Shibboleth side):

::

        Include /etc/shibboleth/apache22.config

        <VirtualHost *:80>
            ServerName alan.ithaka.org
            ServerAdmin alan.brenner@ithaka.org
            DocumentRoot /Library/WebServer/Documents
            ProxyRequests Off
            ProxyPass /server-status !
            ProxyPass /server-info !
            ProxyPass /index.php !
            ProxyPass / http://127.0.0.1:8253/VirtualHostBase/http/alan.ithaka.org:80/test/VirtualHostRoot/
        </VirtualHost>

        Listen 443
        <VirtualHost 172.16.209.1:443>
            DocumentRoot "/Library/WebServer/Documents"
            ServerName alan.ithaka.org:443
            ServerAdmin alan.brenner@ithaka.org
            ErrorLog "/var/log/apache2/error_log"
            TransferLog "/var/log/apache2/access_log"
            SSLEngine on
            SSLCipherSuite ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL
            SSLCertificateFile "/etc/apache2/server.crt"
            SSLCertificateKeyFile "/etc/apache2/server.key"
            <FilesMatch "\.(cgi|shtml|phtml|php)$">
                SSLOptions +StdEnvVars
            </FilesMatch>
            <Directory "/Library/WebServer/CGI-Executables">
                SSLOptions +StdEnvVars
            </Directory>
            BrowserMatch ".*MSIE.*" \
                     nokeepalive ssl-unclean-shutdown \
                     downgrade-1.0 force-response-1.0
            CustomLog "/var/log/apache2/ssl_request_log" \
                      "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"
            <Proxy *>
                Order deny,allow
                Allow from all
            </Proxy>
            RewriteEngine On
            RewriteCond %{LA-U:REMOTE_USER} (.+)
            RewriteRule .* - [E=RW_RU:%1]
            RequestHeader set X_REMOTE_USER %{RW_RU}e
            RequestHeader set SHIB_PERSON_COMMONNAME %{displayName}e
            RequestHeader set SHIB_INETORGPERSON_MAIL %{mail}e
            RequestHeader set SHIB_ORGPERSON_LOCALITY %{l}e
            RequestHeader set SHIB_ORGPERSON_STATE %{st}e
            RequestHeader set SHIB_ORGPERSON_C %{c}e
            RewriteCond %{REQUEST_URI} !^/(shibboleth-sp|server-(status|info)|index.php|secure)
            RewriteRule ^/(.*) http://127.0.0.1:8253/VirtualHostBase/https/alan.ithaka.org:443/test/VirtualHostRoot/$1 [L,P]
            <Location />
                AuthType shibboleth
                ShibRequireSession On
                require shibboleth
            </Location>
        </VirtualHost>
        
        <VirtualHost 172.16.60.1:443>
            DocumentRoot "/Library/WebServer/Documents"
            ServerName alanidp.ithaka.org:443
            ServerAdmin alan.brenner@ithaka.org
            ErrorLog "/var/log/apache2/error_idp_log"
            TransferLog "/var/log/apache2/access_idp_log"
            SSLEngine on
            SSLCipherSuite ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL
            SSLCertificateFile "/etc/apache2/server_idp.crt"
            SSLCertificateKeyFile "/etc/apache2/server_idp.key"
            <FilesMatch "\.(cgi|shtml|phtml|php)$">
                SSLOptions +StdEnvVars
            </FilesMatch>
            <Directory "/Library/WebServer/CGI-Executables">
                SSLOptions +StdEnvVars
            </Directory>
            BrowserMatch ".*MSIE.*" \
                     nokeepalive ssl-unclean-shutdown \
                     downgrade-1.0 force-response-1.0
            <FilesMatch "\.(cgi|shtml|phtml|php)$">
                SSLOptions +StdEnvVars
            </FilesMatch>
            <Proxy *>
                Order deny,allow
                Allow from all
            </Proxy>
            ProxyPass /idp/ ajp://127.0.0.1:8009/idp/
            <Location /idp/Authn/RemoteUser>
                AuthType Basic
                AuthName "IdPTest"
                AuthUserfile /etc/apache2/pass
                require valid-user
            </Location>
        </VirtualHost>

Notice for Shibboleth 2, I've had to use a different host for the Identity
Provider.

Shibboleth Changes
------------------

For Shibboleth 1.3, change the MemorySessionCache in the Service Provider's
shibboleth.xml file to increase values to avoid sessions expiring in 30 minutes:

 ::

  <MemorySessionCache cleanupInterval="28800" cacheTimeout="60"
     AATimeout="30" AAConnectTimeout="15" defaultLifetime="28800"
     retryInterval="300" strictValidity="false" propagateErrors="false"/>

Here, you increase the cleanupInterval and defaultLifetime values in seconds.

For Shibboleth 2.0, change the LoginHandler entry in the Identity Provider's
handler.xml to increase values to avoid sessions expiring in 30 minutes:

 ::

  <LoginHandler xsi:type="RemoteUser" authenticationDuration="480">

Here, you add the authenticationDuration value in minutes.

Configuration
=============

Usernames with domain names
---------------------------

If your Apache setup includes a domain in the username, AutoUserMakerPASPlugin
will, by default, strip it off. For example, if Apache sets X_REMOTE_USER to
"fred@example.com", AutoUserMakerPASPlugin will shorten it to "fred". If you
don't want AutoUserMakerPASPlugin to do this (for example, if you are using a
cross-domain authorization system like Shibboleth where this could cause name
collisions)...

1. In the ZMI, click your *AutoUserMakerPASPlugin* instance in acl_users.

2. Click the "Do not strip domain names from usernames".

3. Click Save.

This can also be set up to strip names from specific DNS domains, by selecting
the 'Strip domain names from all usernames in the domain(s) below' button, and
entering domains in the input box below that button, then click Save.

Header Mapping
--------------

If you are using Shibboleth (http://shibboleth.internet2.edu/), additional data
can be sent from Apache to Zope. Configure the values that the Shibboleth
service provider is making available in the field for each input type, then
click Save. This will allow AutoUserMakerPASPlugin to populate the basic Plone
user attributes (full name, email, etc). Multiple environment variables can be
searched for each attribute by listing them on individual lines. The first value
found will be used.

Assigning Plone Roles, Groups or an Existing User
-------------------------------------------------

AutoUserMakerPASPlugin can map incoming attributes, to Plone roles, groups and
already existing users.

1. Add environment variables to check in the entry box near the bottom of the
   Options tab, and click save.

2. Click the AuthZ tab, and in the Add Role Mapping section, enter regular
   expressions that should select incoming users. You don't need to fill in all
   of the Source fields, but at least one should be. Blank fields match, so
   if no pattern is given, then all new users will be assigned as specified in
   the roles, user and group(s) columns.

3. Either select roles, an existing user, or one or more groups to assign to
   users that match the given pattern(s).

4. Click Save.

Once a mapping exists, there will be an area to edit the existing mapping,
including deleting it.

Allowing Users to Share Content
-------------------------------

If *ShibbolethPermissions* is installed, adding items in the last 2 input fields
in the configuration tab sets up the values users can use to share content with.
Enter environment variable names of the same sort used for assigning roles or
setting user properties in the left input box. Enter labels in the right box
that users will see for the variable on the same line in the left box, and click
save.

Admitting only certain users
----------------------------

If you want to admit only a subset of the users that Apache recognizes...

1. In the ZMI, click your *ApacheAuthPluginHandler* instance.

2. Click the Properties tab.

3. Put "Member" in the required_roles field.

4. Click Save Changes.

5. Use the *Users and Groups Administration* page in Plone to create
   the users you want to admit.

Users you have not added will still be able to satisfy Apache's login
prompt but will not be recognized by Plone.


Design Rationale (technical and only for the curious)
=====================================================

User Creation
-------------

We chose to actually create and store users in the PAS rather than just
pretending they exist. If we had only pretended, then the users wouldn't
show up when you go to 'your-plone-site/prefs_users_overview' and click
"Show all". (Writing a 'IUserEnumerationPlugin' is impossible in our
case, as the enterprise user store is none of Zope's concern; Apache is
the only thing that talks to the user store.)

Role Assignment
---------------

There were two ways we could have gone about giving users the Member
role (which is what Plone requires in order to treat them as first-class
citizens): (1) an 'IRolesPlugin' which would simply pretend everyone has
the Member role or (2) actually assigning each user the Member role and
storing the assignment in the ZODB (or, more correctly, wherever an
active 'IRoleAssignerPlugin' chooses to store it). We chose (2) so you
can uninstall Auto Member Maker later and have your users keep working.
If we had done (1), you would need to manually assign the Member role to
each of your users if you ever stopped using Auto Member Maker.


Testing
=======

To run the *AutoUserMakerPASPlugin* tests, use the standard Zope testrunner:

    $INSTANCE_HOME/bin/zopectl test -s Products.AutoUserMakerPASPlugin


Credits
=======

apachepas
---------
Originally developed by Rocky Burt (rocky AT serverzen.com) on behalf of
"Zest Software":http://zestsoftware.nl.

Version 1.1 by Erik Rose of "WebLion", http://weblion.psu.edu/.

AutoMemberMakerPASPlugin
------------------------

This product was developed by Erik Rose, of the WebLion group at Penn State
University.

AutoUserMakerPASPlugin
----------------------

Alan Brenner, of Ithaka Harbors, Inc., under the direction of the Research in
Information Technology program of the Andrew W. Mellon Foundaton, combined
apachepas and AutoMemberMaker, and added user, group and role mappings, and
support for user level sharing. I've added tests as well. I'd like to thank Paul
Yuergens of psych.ucla.edu, Li Cheng of pku.edu.cn and Yuri <yurj> of alfa.it
for testing, and Alex Man of seas.ucla.edu for tracking down the Shibboleth 1.3
session expiration cause.

