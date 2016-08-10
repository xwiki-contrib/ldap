/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xpn.xwiki.plugin.ldap;

import java.security.Provider;
import java.text.MessageFormat;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.xpn.xwiki.XWikiContext;

/**
 * Access to LDAP configurations.
 * 
 * @version $Id$
 * @deprecated since 8.3, use {@link org.xwiki.contrib.ldap.XWikiLDAPConfig} instead
 */
@Deprecated
public final class XWikiLDAPConfig
{
    /**
     * Mapping fields separator.
     */
    public static final String DEFAULT_SEPARATOR = org.xwiki.contrib.ldap.XWikiLDAPConfig.DEFAULT_SEPARATOR;

    /**
     * LDAP properties names suffix in xwiki.cfg.
     */
    public static final String CFG_LDAP_SUFFIX = org.xwiki.contrib.ldap.XWikiLDAPConfig.CFG_LDAP_SUFFIX;

    /**
     * LDAP port property name in xwiki.cfg.
     */
    public static final String CFG_LDAP_PORT = org.xwiki.contrib.ldap.XWikiLDAPConfig.CFG_LDAP_PORT;

    /**
     * LDAP properties names suffix in XWikiPreferences.
     */
    public static final String PREF_LDAP_SUFFIX = org.xwiki.contrib.ldap.XWikiLDAPConfig.PREF_LDAP_SUFFIX;

    /**
     * LDAP port property name in XWikiPreferences.
     */
    public static final String PREF_LDAP_PORT = org.xwiki.contrib.ldap.XWikiLDAPConfig.PREF_LDAP_PORT;

    /**
     * LDAP port property name in XWikiPreferences.
     */
    public static final String PREF_LDAP_UID = org.xwiki.contrib.ldap.XWikiLDAPConfig.PREF_LDAP_UID;

    /**
     * Enable photo update property name in XWikiPreferences.
     * 
     * @since 8.1M2
     */
    public static final String PREF_LDAP_UPDATE_PHOTO = org.xwiki.contrib.ldap.XWikiLDAPConfig.PREF_LDAP_UPDATE_PHOTO;

    /**
     * Profile photo attachment name property name in XWikiPreferences.
     * 
     * @since 8.1M2
     */
    public static final String PREF_LDAP_PHOTO_ATTACHMENT_NAME =
        org.xwiki.contrib.ldap.XWikiLDAPConfig.PREF_LDAP_PHOTO_ATTACHMENT_NAME;

    /**
     * LDAP photo property name in XWikiPreferences.
     * 
     * @since 8.1M2
     */
    public static final String PREF_LDAP_PHOTO_ATTRIBUTE =
        org.xwiki.contrib.ldap.XWikiLDAPConfig.PREF_LDAP_PHOTO_ATTRIBUTE;

    /**
     * Mapping fields separator.
     */
    public static final String USERMAPPING_SEP = org.xwiki.contrib.ldap.XWikiLDAPConfig.USERMAPPING_SEP;

    /**
     * Character user to link XWiki field name and LDAP field name in user mappings property.
     */
    public static final String USERMAPPING_XWIKI_LDAP_LINK =
        org.xwiki.contrib.ldap.XWikiLDAPConfig.USERMAPPING_XWIKI_LDAP_LINK;

    /**
     * Different LDAP implementations groups classes name.
     * 
     * @since 1.5M1
     */
    public static final Set<String> DEFAULT_GROUP_CLASSES =
        org.xwiki.contrib.ldap.XWikiLDAPConfig.DEFAULT_GROUP_CLASSES;

    /**
     * Different LDAP implementations groups member property name.
     * 
     * @since 1.5M1
     */
    public static final Set<String> DEFAULT_GROUP_MEMBERFIELDS =
        org.xwiki.contrib.ldap.XWikiLDAPConfig.DEFAULT_GROUP_MEMBERFIELDS;

    /**
     * Default LDAP attribute name containing binary photo.
     * 
     * @since 8.1M2
     */
    public static final String DEFAULT_PHOTO_ATTRIBUTE = org.xwiki.contrib.ldap.XWikiLDAPConfig.DEFAULT_PHOTO_ATTRIBUTE;

    /**
     * Unique instance of {@link XWikiLDAPConfig}.
     */
    private static XWikiLDAPConfig deprecatedInstance;

    private org.xwiki.contrib.ldap.XWikiLDAPConfig config = org.xwiki.contrib.ldap.XWikiLDAPConfig.getInstance();

    /**
     * Protected constructor. Use {@link #getInstance()}.
     */
    private XWikiLDAPConfig()
    {

    }

    /**
     * @return unique instance of {@link XWikiLDAPConfig}.
     */
    public static XWikiLDAPConfig getInstance()
    {
        if (deprecatedInstance == null) {
            deprecatedInstance = new XWikiLDAPConfig();
        }

        return deprecatedInstance;
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     * 
     * @param prefName the name of the property in XWikiPreferences.
     * @param cfgName the name of the property in xwiki.cfg.
     * @param def default value.
     * @param context the XWiki context.
     * @return the value of the property.
     */
    public String getLDAPParam(String prefName, String cfgName, String def, XWikiContext context)
    {
        return this.config.getLDAPParam(prefName, cfgName, def, context);
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     * 
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @param context the XWiki context.
     * @return the value of the property.
     */
    public String getLDAPParam(String name, String def, XWikiContext context)
    {
        return this.config.getLDAPParam(name, def, context);
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     * 
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @param context the XWiki context.
     * @return the value of the property.
     */
    public long getLDAPParamAsLong(String name, long def, XWikiContext context)
    {
        return this.config.getLDAPParamAsLong(name, def, context);
    }

    /**
     * @param context the XWiki context.
     * @return the of the LDAP groups classes.
     * @since 1.5M1
     */
    public Collection<String> getGroupClasses(XWikiContext context)
    {
        return this.config.getGroupClasses(context);
    }

    /**
     * @param context the XWiki context.
     * @return the names of the fields for members of groups.
     * @since 1.5M1
     */
    public Collection<String> getGroupMemberFields(XWikiContext context)
    {
        return this.config.getGroupMemberFields(context);
    }

    /**
     * @param context the XWiki context.
     * @return the secure provider to use for SSL.
     * @throws XWikiLDAPException error when trying to instantiate secure provider.
     * @since 1.5M1
     */
    public Provider getSecureProvider(XWikiContext context) throws XWikiLDAPException
    {
        try {
            return this.config.getSecureProvider(context);
        } catch (org.xwiki.contrib.ldap.XWikiLDAPException e) {
            throw new XWikiLDAPException(e.getMessage(), e);
        }
    }

    /**
     * @param context the XWiki context.
     * @return true if LDAP is enabled.
     */
    public boolean isLDAPEnabled(XWikiContext context)
    {
        return this.config.isLDAPEnabled(context);
    }

    /**
     * Get LDAP port from configuration.
     * 
     * @param context the XWiki context.
     * @return the LDAP port.
     */
    public int getLDAPPort(XWikiContext context)
    {
        return this.config.getLDAPPort(context);
    }

    /**
     * Get mapping between XWiki groups names and LDAP groups names.
     * 
     * @param context the XWiki context.
     * @return the mapping between XWiki users and LDAP users. The key is the XWiki group, and the value is the list of
     *         mapped LDAP groups.
     */
    public Map<String, Set<String>> getGroupMappings(XWikiContext context)
    {
        return this.config.getGroupMappings(context);
    }

    /**
     * Get mapping between XWiki users attributes and LDAP users attributes. The key in the Map is lower cased to easily
     * support any case.
     * 
     * @param attrListToFill the list to fill with extracted LDAP fields to use in LDAP search.
     * @param context the XWiki context.
     * @return the mapping between XWiki groups and LDAP groups.
     */
    public Map<String, String> getUserMappings(List<String> attrListToFill, XWikiContext context)
    {
        return this.config.getUserMappings(attrListToFill, context);
    }

    /**
     * @param context the XWiki context.
     * @return the time in seconds until a entry in the cache is to expire.
     */
    public int getCacheExpiration(XWikiContext context)
    {
        return this.config.getCacheExpiration(context);
    }

    /**
     * @param context the XWiki context.
     * @return the pattern to resolve to find the password to use to connect to LDAP server. It is based on
     *         {@link MessageFormat}.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindDN(String, String, XWikiContext)
     */
    public String getLDAPBindDN(XWikiContext context)
    {
        return this.config.getLDAPBindDN(context);
    }

    /**
     * @param login the login provided by the user
     * @param password the password provided by the user
     * @param context the XWiki context.
     * @return the login to use to connect to LDAP server.
     */
    public String getLDAPBindDN(String login, String password, XWikiContext context)
    {
        return this.config.getLDAPBindDN(login, password, context);
    }

    /**
     * @param context the XWiki context.
     * @return the pattern to resolve to find the password to use to connect to LDAP server.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindPassword(String, String, XWikiContext)
     */
    public String getLDAPBindPassword(XWikiContext context)
    {
        return this.config.getLDAPBindPassword(context);
    }

    /**
     * @param login the login provided by the user
     * @param password the password provided by the user
     * @param context the XWiki context.
     * @return the password to use to connect to LDAP server.
     */
    public String getLDAPBindPassword(String login, String password, XWikiContext context)
    {
        return this.config.getLDAPBindPassword(login, password, context);
    }

    /**
     * @param context the XWiki context.
     * @return the maximum number of milliseconds the client waits for any operation under these constraints to
     *         complete.
     * @since 4.3M1
     */
    public int getLDAPTimeout(XWikiContext context)
    {
        return this.config.getLDAPTimeout(context);
    }

    /**
     * @param context the XWiki context.
     * @return the maximum number of search results to be returned from a search operation.
     * @since 6.3M1
     */
    public int getLDAPMaxResults(XWikiContext context)
    {
        return this.config.getLDAPMaxResults(context);
    }

    /**
     * @param context the XWiki context.
     * @return set of LDAP attributes that should be treated as binary data.
     * @since 8.1M2
     */
    public Set<String> getBinaryAttributes(XWikiContext context)
    {
        return this.config.getBinaryAttributes(context);
    }
}
