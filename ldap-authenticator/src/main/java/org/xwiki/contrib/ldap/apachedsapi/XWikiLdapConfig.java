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
package org.xwiki.contrib.ldap.apachedsapi;

import java.security.Provider;
import java.text.MessageFormat;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.apachedsapi.internal.DefaultXWikiLDAPConfigImpl;
import org.xwiki.stability.Unstable;

/**
 * The configuration used to authenticate users against an LDAP.
 * @version $Id: $
 * @since 10.0
 */
public interface XWikiLdapConfig
{

    /**
     * @return the custom in memory configuration. Can be used to override any property per login.
     */
    Map<String, String> getMemoryConfiguration();

    /**
     * Parse the given user name for user id and group. 
     * Given the regular expression from the "ldap_remoteUserParser" configuration variable
     * parse the input and stores the "uid" and group information extracted from that expression.
     * The group information is stored according  "ldap_remoteUserMapping.&lt;groupname>" mapping.
     * @param ssoRemoteUser the id of the remote user; should not be null
     */
    void parseRemoteUser(String ssoRemoteUser);

    /**
     * Try to find the configuration in the following order:
     * <ul>
     * <li>Local configuration stored in this {@link DefaultXWikiLDAPConfigImpl} instance (ldap_*name*)</li>
     * <li>XWiki Preferences page (ldap_*name*)</li>
     * <li>xwiki.cfg configuration file (ldap.*name*)</li>
     * <li>A final configuration that could be overriden by extended authenticators</li>
     * </ul>
     *
     * @param name the name of the property in XWikiPreferences.
     * @param cfgName the name of the property in xwiki.cfg.
     * @param def default value.
     * @return the value of the property.
     */
    String getLDAPParam(String name, String cfgName, String def);

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     *
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @return the value of the property.
     */
    String getLDAPParam(String name, String def);

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     *
     * @param name the name of the property in XWikiPreferences.
     * @param cfgName the name of the property in xwiki.cfg.
     * @param def default value.
     * @return the value of the property.
     */
    long getLDAPParamAsLong(String name, String cfgName, long def);

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     *
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @return the value of the property.
     */
    long getLDAPParamAsLong(String name, long def);

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param def the default value
     * @return the configuration value as {@link List}
     */
    List<String> getLDAPListParam(String name, List<String> def);

    /**
     * @return a Java regexp used to parse the remote user provided by JAAS.
     */
    Pattern getRemoteUserPattern();

    /**
     * @param groupId the identifier of the group matched by the REMOTE_USER regexp
     * @return the properties associated to the passed group
     */
    List<String> getRemoteUserMapping(int groupId);

    /**
     * @param propertyName the name of the property
     * @param forceLowerCaseKey if true the keys will be stored lowered cased in the {@link Map}
     * @return the mapping (the value for each domain) associated to the passed property
     */
    Map<String, String> getRemoteUserMapping(String propertyName, boolean forceLowerCaseKey);

    /**
     * @return try to find existing XWiki user with both complete user id and user login
     */
    Set<String> getTestLoginFor();

    /**
     * @return an HTTP header that could be used to retrieve the authenticated user.
     */
    String getHttpHeader();

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param separator the separator used to cut each element of the list
     * @param def the default value
     * @return the configuration value as {@link List}
     */
    List<String> getLDAPListParam(String name, char separator, List<String> def);

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param def the default value
     * @param forceLowerCaseKey
     * @return the configuration value as {@link Map}
     */
    Map<String, String> getLDAPMapParam(String name, Map<String, String> def, boolean forceLowerCaseKey);

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param separator the separator used to cut each element of the list
     * @param def the default value
     * @param forceLowerCaseKey
     * @return the configuration value as {@link Map}
     */
    Map<String, String> getLDAPMapParam(String name, char separator, Map<String, String> def,
        boolean forceLowerCaseKey);

    /**
     * Add a configuration value to the "in memory" config.
     * These values will be effective if there is no value in the other configuration sources,
     * and will be used by all threads until the server is restarted (or the authenticator extension reloaded)
     * @param key the name of the configuration variable
     * @param value the configuration value as a string
     */
    @Unstable
    void setFinalProperty(String key, String value);

    /**
     * @return the collection of the LDAP groups classes.
     */
    Collection<String> getGroupClasses();

    /**
     * @return the names of the fields for members of groups.
     */
    Collection<String> getGroupMemberFields();

    /**
     * @return the secure provider to use for SSL.
     * @throws XWikiLDAPException error when trying to instantiate secure provider.
     */
    Provider getSecureProvider() throws XWikiLDAPException;

    /**
     * @return true if LDAP is enabled.
     */
    boolean isLDAPEnabled();

    /**
     * Get LDAP port from configuration.
     * 
     * @return the LDAP port.
     */
    int getLDAPPort();

    /**
     * Get LDAP host from configuration.
     * 
     * @return the name of the LDAP host.
     */
    String getLDAPHost();
    
    /**
     * Get mapping between XWiki groups names and LDAP groups names.
     *
     * @return the mapping between XWiki users and LDAP users. The key is the XWiki group, and the value is the list of
     *         mapped LDAP groups.
     */
    Map<String, Set<String>> getGroupMappings();

    /**
     * Get mapping between XWiki users attributes and LDAP users attributes. The key in the Map is lower cased to easily
     * support any case.
     *
     * @param attrListToFill the list to fill with extracted LDAP fields to use in LDAP search.
     * @return the mapping between XWiki groups and LDAP groups.
     */
    Map<String, String> getUserMappings(List<String> attrListToFill);

    /**
     * @return the time in seconds until a entry in the cache is to expire.
     */
    int getCacheExpiration();

    /**
     * @return the pattern to resolve to find the password to use to connect to LDAP server. It is based on
     *         {@link MessageFormat}.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindDN(String, String)
     */
    String getLDAPBindDN();

    /**
     * @param input the login provided by the user
     * @param password the password provided by the user
     * @return the login to use to connect to LDAP server.
     */
    String getLDAPBindDN(String input, String password);

    /**
     * @return the pattern to resolve to find the password to use to connect to LDAP server.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindPassword(String, String)
     */
    String getLDAPBindPassword();

    /**
     * @param input the login provided by the user
     * @param password the password provided by the user
     * @return the password to use to connect to LDAP server.
     */
    String getLDAPBindPassword(String input, String password);

    /**
     * @return the maximum number of milliseconds the client waits for any operation under these constraints to
     *         complete.
     */
    int getLDAPTimeout();

    /**
     * @return the maximum number of search results to be returned from a search operation.
     */
    int getLDAPMaxResults();

    /**
     * @return the maximum number of elements to return in each search page
     */
    int getSearchPageSize();

    /**
     * @return set of LDAP attributes that should be treated as binary data.
     */
    Set<String> getBinaryAttributes();

}