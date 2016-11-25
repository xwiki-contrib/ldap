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
package org.xwiki.contrib.ldap;

import java.security.Provider;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.configuration.ConfigurationSource;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.web.Utils;

/**
 * Access to LDAP configurations.
 * 
 * @version $Id$
 * @since 8.3
 */
public class XWikiLDAPConfig
{
    /**
     * Mapping fields separator.
     */
    public static final String DEFAULT_SEPARATOR = ",";

    /**
     * LDAP properties names suffix in xwiki.cfg.
     */
    public static final String CFG_LDAP_SUFFIX = "xwiki.authentication.ldap.";

    /**
     * LDAP port property name in xwiki.cfg.
     */
    public static final String CFG_LDAP_PORT = CFG_LDAP_SUFFIX + "port";

    /**
     * LDAP properties names suffix in XWikiPreferences.
     */
    public static final String PREF_LDAP_SUFFIX = "ldap_";

    /**
     * LDAP port property name in XWikiPreferences.
     */
    public static final String PREF_LDAP_PORT = "ldap_port";

    /**
     * LDAP port property name in XWikiPreferences.
     */
    public static final String PREF_LDAP_UID = "ldap_UID_attr";

    /**
     * Enable photo update property name in XWikiPreferences.
     * 
     * @since 8.1M2
     */
    public static final String PREF_LDAP_UPDATE_PHOTO = "ldap_update_photo";

    /**
     * Profile photo attachment name property name in XWikiPreferences.
     * 
     * @since 8.1M2
     */
    public static final String PREF_LDAP_PHOTO_ATTACHMENT_NAME = "ldap_photo_attachment_name";

    /**
     * LDAP photo property name in XWikiPreferences.
     * 
     * @since 8.1M2
     */
    public static final String PREF_LDAP_PHOTO_ATTRIBUTE = "ldap_photo_attribute";

    /**
     * Mapping fields separator.
     */
    public static final String USERMAPPING_SEP = DEFAULT_SEPARATOR;

    /**
     * Character user to link XWiki field name and LDAP field name in user mappings property.
     */
    public static final String USERMAPPING_XWIKI_LDAP_LINK = "=";

    /**
     * Different LDAP implementations groups classes name.
     * 
     * @since 1.5M1
     */
    public static final Set<String> DEFAULT_GROUP_CLASSES = new HashSet<>();

    /**
     * Different LDAP implementations groups member property name.
     * 
     * @since 1.5M1
     */
    public static final Set<String> DEFAULT_GROUP_MEMBERFIELDS = new HashSet<>();

    /**
     * Default LDAP attribute name containing binary photo.
     * 
     * @since 8.1M2
     */
    public static final String DEFAULT_PHOTO_ATTRIBUTE = "thumbnailPhoto";

    /**
     * Logging tool.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiLDAPConfig.class);

    /**
     * The default secure provider to use for SSL.
     */
    private static final String DEFAULT_SECUREPROVIDER = "com.sun.net.ssl.internal.ssl.Provider";

    static {
        DEFAULT_GROUP_CLASSES.add("group".toLowerCase());
        DEFAULT_GROUP_CLASSES.add("groupOfNames".toLowerCase());
        DEFAULT_GROUP_CLASSES.add("groupOfUniqueNames".toLowerCase());
        DEFAULT_GROUP_CLASSES.add("dynamicGroup".toLowerCase());
        DEFAULT_GROUP_CLASSES.add("dynamicGroupAux".toLowerCase());
        DEFAULT_GROUP_CLASSES.add("groupWiseDistributionList".toLowerCase());
        DEFAULT_GROUP_CLASSES.add("posixGroup".toLowerCase());
        DEFAULT_GROUP_CLASSES.add("apple-group".toLowerCase());

        DEFAULT_GROUP_MEMBERFIELDS.add("member".toLowerCase());
        DEFAULT_GROUP_MEMBERFIELDS.add("uniqueMember".toLowerCase());
        DEFAULT_GROUP_MEMBERFIELDS.add("memberUid".toLowerCase());
    }

    /**
     * Unique instance of {@link XWikiLDAPConfig}.
     */
    private static XWikiLDAPConfig instance;

    private final Map<String, String> memoryConfiguration;

    private ConfigurationSource configurationSource;

    private ConfigurationSource cfgConfigurationSource;

    /**
     * @param userId the complete user id given
     * @param xcontext the XWiki context
     * @since 9.0
     * @deprecated since 9.1.1, use {@link #XWikiLDAPConfig(String)} instead
     */
    @Deprecated
    public XWikiLDAPConfig(String userId, XWikiContext xcontext)
    {
        this(userId);
    }

    /**
     * @param userId the complete user id given
     * @since 9.1.1
     */
    public XWikiLDAPConfig(String userId)
    {
        this(userId, Utils.getComponent(ConfigurationSource.class, "wiki"));
    }

    /**
     * @param userId the complete user id given
     * @param configurationSource the Configuration source to use to find LDAP parameters first (if not found in this
     *        source then the parameter will be searched for in xwiki.cfg).
     * @since 9.1.1
     */
    public XWikiLDAPConfig(String userId, ConfigurationSource configurationSource)
    {
        this.memoryConfiguration = new HashMap<>();

        // Look for LDAP parameters first in the XWikiPreferences document from the current wiki
        this.configurationSource = configurationSource;

        this.cfgConfigurationSource = Utils.getComponent(ConfigurationSource.class, "xwikicfg");

        if (userId != null) {
            parseRemoteUser(userId);
        }
    }

    /**
     * @return unique instance of {@link XWikiLDAPConfig}.
     * @deprecated since 8.5, use {@link XWikiLDAPConfig#XWikiLDAPConfig(String, XWikiContext)} instead
     */
    @Deprecated
    public static XWikiLDAPConfig getInstance()
    {
        if (instance == null) {
            instance = new XWikiLDAPConfig(null);
        }

        return instance;
    }

    /**
     * @return the custom configuration. Can be used to override any property.
     * @since 9.0
     */
    public Map<String, String> getMemoryConfiguration()
    {
        return this.memoryConfiguration;
    }

    private void parseRemoteUser(String ssoRemoteUser)
    {
        this.memoryConfiguration.put("auth.input", ssoRemoteUser);
        this.memoryConfiguration.put("uid", ssoRemoteUser);

        Pattern remoteUserParser = getRemoteUserPattern();

        LOGGER.debug("remoteUserParser: {}", remoteUserParser);

        if (remoteUserParser != null) {
            Matcher marcher = remoteUserParser.matcher(ssoRemoteUser);

            if (marcher.find()) {
                int groupCount = marcher.groupCount();
                if (groupCount == 0) {
                    this.memoryConfiguration.put("uid", marcher.group());
                } else {
                    for (int g = 1; g <= groupCount; ++g) {
                        String groupValue = marcher.group(g);

                        List<String> remoteUserMapping = getRemoteUserMapping(g);

                        for (String configName : remoteUserMapping) {
                            this.memoryConfiguration.put(configName,
                                convertRemoteUserMapping(configName, groupValue));
                        }
                    }
                }
            }
        }
    }

    private String convertRemoteUserMapping(String propertyName, String propertyValue)
    {
        Map<String, String> hostConvertor = getRemoteUserMapping(propertyName, true);

        LOGGER.debug("hostConvertor: {}", hostConvertor);

        String converted = hostConvertor.get(propertyValue.toLowerCase());

        return converted != null ? converted : propertyValue;
    }

    /**
     * Try to find the configuration in the following order:
     * <ul>
     * <li>Local configuration stored in this {@link XWikiLDAPConfig} instance (ldap_*name*)</li>
     * <li>XWiki Preferences page (ldap_*name*)</li>
     * <li>xwiki.cfg configuration file (ldap.*name*)</li>
     * </ul>
     * 
     * @param name the name of the property in XWikiPreferences.
     * @param cfgName the name of the property in xwiki.cfg.
     * @param def default value.
     * @param context the XWiki context (unused)
     * @return the value of the property.
     * @deprecated since 9.1.1, use {@link #getLDAPParam(String, String, String)} instead
     */
    @Deprecated
    public String getLDAPParam(String name, String cfgName, String def, XWikiContext context)
    {
        return getLDAPParam(name, cfgName, def);
    }

    /**
     * Try to find the configuration in the following order:
     * <ul>
     * <li>Local configuration stored in this {@link XWikiLDAPConfig} instance (ldap_*name*)</li>
     * <li>XWiki Preferences page (ldap_*name*)</li>
     * <li>xwiki.cfg configuration file (ldap.*name*)</li>
     * </ul>
     *
     * @param name the name of the property in XWikiPreferences.
     * @param cfgName the name of the property in xwiki.cfg.
     * @param def default value.
     * @return the value of the property.
     * @since 9.1.1
     */
    public String getLDAPParam(String name, String cfgName, String def)
    {
        if (this.memoryConfiguration.containsKey(name)) {
            return this.memoryConfiguration.get(name);
        }

        // First look for the parameter in the defined configuration source (by default in XWikiPreferences document
        // from the current wiki).
        String param = this.configurationSource.getProperty(name, String.class);

        // If not found, check in xwiki.cfg
        if (param == null || "".equals(param)) {
            param = this.cfgConfigurationSource.getProperty(cfgName);
        }

        if (param == null) {
            param = def;
        }

        return param;
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     * 
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @param context the XWiki context (unused)
     * @return the value of the property.
     * @deprecated since 9.1.1, use {@link #getLDAPParam(String, String)} instead
     */
    @Deprecated
    public String getLDAPParam(String name, String def, XWikiContext context)
    {
        return getLDAPParam(name, def);
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     *
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @return the value of the property.
     * @since 9.1.1
     */
    public String getLDAPParam(String name, String def)
    {
        return getLDAPParam(name, name.replace(PREF_LDAP_SUFFIX, CFG_LDAP_SUFFIX), def);
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     * 
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @param context the XWiki context.
     * @return the value of the property.
     * @deprecated since 9.1.1, use {@link #getLDAPParamAsLong(String, long)}
     */
    @Deprecated
    public long getLDAPParamAsLong(String name, long def, XWikiContext context)
    {
        return getLDAPParamAsLong(name, def);
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     *
     * @param name the name of the property in XWikiPreferences.
     * @param cfgName the name of the property in xwiki.cfg.
     * @param def default value.
     * @return the value of the property.
     * @since 9.1.1
     */
    public long getLDAPParamAsLong(String name, String cfgName, long def)
    {
        String paramStr = getLDAPParam(name, name.replace(PREF_LDAP_SUFFIX, CFG_LDAP_SUFFIX), String.valueOf(def));

        long value;

        try {
            value = Long.valueOf(paramStr);
        } catch (Exception e) {
            value = def;
        }

        return value;
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     *
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @return the value of the property.
     * @since 9.1.1
     */
    public long getLDAPParamAsLong(String name, long def)
    {
        return getLDAPParamAsLong(name, name.replace(PREF_LDAP_SUFFIX, CFG_LDAP_SUFFIX), def);
    }

    /**
     * @param context the XWiki context.
     * @return the of the LDAP groups classes.
     * @since 1.5M1
     * @deprecated since 9.1.1, use {@link #getGroupClasses()} instead
     */
    @Deprecated
    public Collection<String> getGroupClasses(XWikiContext context)
    {
        return getGroupClasses();
    }

    /**
     * @return the of the LDAP groups classes.
     * @since 9.1.1
     */
    public Collection<String> getGroupClasses()
    {
        String param = getLDAPParam("ldap_group_classes", null);

        Collection<String> set;

        if (param != null) {
            String[] table = param.split(DEFAULT_SEPARATOR);

            set = new HashSet<>();
            for (String name : table) {
                set.add(name.toLowerCase());
            }
        } else {
            set = DEFAULT_GROUP_CLASSES;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("ldap_group_classes: " + set);
        }

        return set;
    }

    /**
     * @param context the XWiki context.
     * @return the names of the fields for members of groups.
     * @since 1.5M1
     * @deprecated since 9.1.1, use {@link #getGroupMemberFields()} instead
     */
    @Deprecated
    public Collection<String> getGroupMemberFields(XWikiContext context)
    {
        return getGroupMemberFields();
    }

    /**
     * @return the names of the fields for members of groups.
     * @since 9.1.1
     */
    public Collection<String> getGroupMemberFields()
    {
        String param = getLDAPParam("ldap_group_memberfields", null);

        Collection<String> set;

        if (param != null) {
            String[] table = param.split(DEFAULT_SEPARATOR);

            set = new HashSet<String>();
            for (String name : table) {
                set.add(name.toLowerCase());
            }
        } else {
            set = DEFAULT_GROUP_MEMBERFIELDS;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("ldap_group_memberfields: " + set);
        }

        return set;
    }

    /**
     * @param context the XWiki context.
     * @return the secure provider to use for SSL.
     * @throws XWikiLDAPException error when trying to instantiate secure provider.
     * @since 1.5M1
     * @deprecated since 9.1.1, use {@link #getSecureProvider()} instead
     */
    @Deprecated
    public Provider getSecureProvider(XWikiContext context) throws XWikiLDAPException
    {
        return getSecureProvider();
    }

    /**
     * @return the secure provider to use for SSL.
     * @throws XWikiLDAPException error when trying to instantiate secure provider.
     * @since 9.1.1
     */
    public Provider getSecureProvider() throws XWikiLDAPException
    {
        Provider provider;

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        String className = getLDAPParam("ldap_ssl.secure_provider", DEFAULT_SECUREPROVIDER);

        try {
            provider = (java.security.Provider) cl.loadClass(className).newInstance();
        } catch (Exception e) {
            throw new XWikiLDAPException("Fail to load secure ssl provider.", e);
        }

        return provider;
    }

    /**
     * @param context the XWiki context.
     * @return true if LDAP is enabled.
     * @deprecated since 9.1.1, use {@link #isLDAPEnabled()} instead
     */
    @Deprecated
    public boolean isLDAPEnabled(XWikiContext context)
    {
        return isLDAPEnabled();
    }

    /**
     * @return true if LDAP is enabled.
     * @since 9.1.1
     */
    public boolean isLDAPEnabled()
    {
        String param = getLDAPParam("ldap", "xwiki.authentication.ldap", "0");

        return param != null && param.equals("1");
    }

    /**
     * Get LDAP port from configuration.
     * 
     * @return the LDAP port.
     * @since 9.1.1
     */
    public int getLDAPPort()
    {
        return (int) getLDAPParamAsLong(PREF_LDAP_PORT, CFG_LDAP_PORT, 0);
    }

    /**
     * Get LDAP port from configuration.
     *
     * @param context the XWiki context.
     * @return the LDAP port.
     * @deprecated since 9.1.1, use {@link #getLDAPPort()} instead
     */
    @Deprecated
    public int getLDAPPort(XWikiContext context)
    {
        return getLDAPPort();
    }

    /**
     * Get mapping between XWiki groups names and LDAP groups names.
     * 
     * @param context the XWiki context.
     * @return the mapping between XWiki users and LDAP users. The key is the XWiki group, and the value is the list of
     *         mapped LDAP groups.
     * @deprecated since 9.1.1, use {@link #getGroupMappings()} instead
     */
    @Deprecated
    public Map<String, Set<String>> getGroupMappings(XWikiContext context)
    {
        return getGroupMappings();
    }

    /**
     * Get mapping between XWiki groups names and LDAP groups names.
     *
     * @return the mapping between XWiki users and LDAP users. The key is the XWiki group, and the value is the list of
     *         mapped LDAP groups.
     *         @since 9.1.1
     */
    public Map<String, Set<String>> getGroupMappings()
    {
        String param = getLDAPParam("ldap_group_mapping", "");

        Map<String, Set<String>> groupMappings = new HashMap<String, Set<String>>();

        if (param.trim().length() > 0) {
            char[] buffer = param.trim().toCharArray();
            boolean escaped = false;
            StringBuilder mapping = new StringBuilder(param.length());
            for (int i = 0; i < buffer.length; ++i) {
                char c = buffer[i];

                if (escaped) {
                    mapping.append(c);
                    escaped = false;
                } else {
                    if (c == '\\') {
                        escaped = true;
                    } else if (c == '|') {
                        addGroupMapping(mapping.toString(), groupMappings);
                        mapping.setLength(0);
                    } else {
                        mapping.append(c);
                    }
                }
            }

            if (mapping.length() > 0) {
                addGroupMapping(mapping.toString(), groupMappings);
            }
        }

        return groupMappings;
    }

    /**
     * @param mapping the mapping to parse
     * @param groupMappings the map to add parsed group mapping to
     */
    private void addGroupMapping(String mapping, Map<String, Set<String>> groupMappings)
    {
        int splitIndex = mapping.indexOf('=');

        if (splitIndex < 1) {
            LOGGER.error("Error parsing ldap_group_mapping attribute [{}]", mapping);
        } else {
            String xwikigroup = mapping.substring(0, splitIndex);
            String ldapgroup = mapping.substring(splitIndex + 1);

            Set<String> ldapGroups = groupMappings.get(xwikigroup);

            if (ldapGroups == null) {
                ldapGroups = new HashSet<String>();
                groupMappings.put(xwikigroup, ldapGroups);
            }

            ldapGroups.add(ldapgroup);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Groupmapping found [{}] [{}]", xwikigroup, ldapGroups);
            }
        }
    }

    /**
     * Get mapping between XWiki users attributes and LDAP users attributes. The key in the Map is lower cased to easily
     * support any case.
     * 
     * @param attrListToFill the list to fill with extracted LDAP fields to use in LDAP search.
     * @param context the XWiki context.
     * @return the mapping between XWiki groups and LDAP groups.
     * @deprecated since 9.1.1, use {@link #getUserMappings(List)} instead
     */
    @Deprecated
    public Map<String, String> getUserMappings(List<String> attrListToFill, XWikiContext context)
    {
        return getUserMappings(attrListToFill);
    }

    /**
     * Get mapping between XWiki users attributes and LDAP users attributes. The key in the Map is lower cased to easily
     * support any case.
     *
     * @param attrListToFill the list to fill with extracted LDAP fields to use in LDAP search.
     * @return the mapping between XWiki groups and LDAP groups.
     * @since 9.1.1
     */
    public Map<String, String> getUserMappings(List<String> attrListToFill)
    {
        Map<String, String> userMappings = new HashMap<>();

        String ldapFieldMapping = getLDAPParam("ldap_fields_mapping", null);

        if (ldapFieldMapping != null && ldapFieldMapping.length() > 0) {
            String[] fields = ldapFieldMapping.split(USERMAPPING_SEP);

            for (int j = 0; j < fields.length; j++) {
                String[] field = fields[j].split(USERMAPPING_XWIKI_LDAP_LINK);
                if (2 == field.length) {
                    String xwikiattr = field[0].replace(" ", "");
                    String ldapattr = field[1].replace(" ", "");

                    userMappings.put(ldapattr.toLowerCase(), xwikiattr);

                    if (attrListToFill != null) {
                        attrListToFill.add(ldapattr);
                    }
                } else {
                    LOGGER.error("Error parsing LDAP fields mapping attribute from configuration, got [{}]",
                        fields[j]);
                }
            }
        }

        return userMappings;
    }

    /**
     * @param context the XWiki context.
     * @return the time in seconds until a entry in the cache is to expire.
     * @deprecated  since 9.1.1, use {@link #getCacheExpiration()} instead
     */
    @Deprecated
    public int getCacheExpiration(XWikiContext context)
    {
        return getCacheExpiration();
    }

    /**
     * @return the time in seconds until a entry in the cache is to expire.
     * @since 9.1.1
     */
    public int getCacheExpiration()
    {
        return (int) getLDAPParamAsLong("ldap_groupcache_expiration", 21600);
    }

    /**
     * @param context the XWiki context.
     * @return the pattern to resolve to find the password to use to connect to LDAP server. It is based on
     *         {@link MessageFormat}.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindDN(String, String)
     * @deprecated since 9.1.1, use {@link #getLDAPBindDN()}
     */
    @Deprecated
    public String getLDAPBindDN(XWikiContext context)
    {
        return getLDAPBindDN();
    }

    /**
     * @return the pattern to resolve to find the password to use to connect to LDAP server. It is based on
     *         {@link MessageFormat}.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindDN(String, String)
     * @since 9.1.1
     */
    public String getLDAPBindDN()
    {
        return getLDAPParam("ldap_bind_DN", "{0}");
    }

    /**
     * @param input the login provided by the user
     * @param password the password provided by the user
     * @param context the XWiki context.
     * @return the login to use to connect to LDAP server.
     * @deprecated since 9.1.1, use {@link #getLDAPBindDN(String, String)} instead
     */
    @Deprecated
    public String getLDAPBindDN(String input, String password, XWikiContext context)
    {
        return getLDAPBindDN(input, password);
    }

    /**
     * @param input the login provided by the user
     * @param password the password provided by the user
     * @return the login to use to connect to LDAP server.
     * @since 9.1.1
     */
    public String getLDAPBindDN(String input, String password)
    {
        return MessageFormat.format(getLDAPBindDN(), XWikiLDAPConnection.escapeLDAPDNValue(input),
            XWikiLDAPConnection.escapeLDAPDNValue(password));
    }

    /**
     * @param context the XWiki context.
     * @return the pattern to resolve to find the password to use to connect to LDAP server.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindPassword(String, String)
     * @deprecated since 9.1.1, use {@link #getLDAPBindPassword()} instead
     */
    @Deprecated
    public String getLDAPBindPassword(XWikiContext context)
    {
        return getLDAPBindPassword();
    }

    /**
     * @return the pattern to resolve to find the password to use to connect to LDAP server.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindPassword(String, String, XWikiContext)
     * @since 9.1.1
     */
    public String getLDAPBindPassword()
    {
        return getLDAPParam("ldap_bind_pass", "{1}");
    }

    /**
     * @param input the login provided by the user
     * @param password the password provided by the user
     * @param context the XWiki context.
     * @return the password to use to connect to LDAP server.
     * @since 9.1.1, use {@link #getLDAPBindPassword(String, String)} instead
     */
    @Deprecated
    public String getLDAPBindPassword(String input, String password, XWikiContext context)
    {
        return getLDAPBindPassword(input, password);
    }

    /**
     * @param input the login provided by the user
     * @param password the password provided by the user
     * @return the password to use to connect to LDAP server.
     * @since 9.1.1
     */
    public String getLDAPBindPassword(String input, String password)
    {
        return MessageFormat.format(getLDAPBindPassword(), input, password);
    }

    /**
     * @param context the XWiki context.
     * @return the maximum number of milliseconds the client waits for any operation under these constraints to
     *         complete.
     * @since 4.3M1
     * @deprecated since 9.1.1, use {@link #getLDAPTimeout()} instead
     */
    @Deprecated
    public int getLDAPTimeout(XWikiContext context)
    {
        return (int) getLDAPParamAsLong("ldap_timeout", 1000);
    }

    /**
     * @return the maximum number of milliseconds the client waits for any operation under these constraints to
     *         complete.
     * @since 9.1.1
     */
    public int getLDAPTimeout()
    {
        return (int) getLDAPParamAsLong("ldap_timeout", 1000);
    }

    /**
     * @param context the XWiki context.
     * @return the maximum number of search results to be returned from a search operation.
     * @since 6.3M1
     * @deprecated since 9.1.1, use {@link #getLDAPMaxResults()}
     */
    @Deprecated
    public int getLDAPMaxResults(XWikiContext context)
    {
        return getLDAPMaxResults();
    }

    /**
     * @return the maximum number of search results to be returned from a search operation.
     * @since 9.1.1
     */
    public int getLDAPMaxResults()
    {
        return (int) getLDAPParamAsLong("ldap_maxresults", 1000);
    }

    /**
     * @param context the XWiki context.
     * @return set of LDAP attributes that should be treated as binary data.
     * @since 8.1M2
     * @deprecated since 9.1.1, use {@link #getBinaryAttributes()} instead
     */
    @Deprecated
    public Set<String> getBinaryAttributes(XWikiContext context)
    {
        return getBinaryAttributes();
    }

    /**
     * @return set of LDAP attributes that should be treated as binary data.
     * @since 9.1.1
     */
    public Set<String> getBinaryAttributes()
    {
        Set<String> binaryAttributes = new HashSet<>();

        binaryAttributes.add(getLDAPParam(XWikiLDAPConfig.PREF_LDAP_PHOTO_ATTRIBUTE, DEFAULT_PHOTO_ATTRIBUTE));

        return binaryAttributes;
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param def the default value
     * @param context the XWiki context.
     * @return the configuration value as {@link List}
     * @since 9.0
     * @deprecated since 9.1.1, use {@link #getLDAPListParam(String, List)} instead
     */
    @Deprecated
    public List<String> getLDAPListParam(String name, List<String> def, XWikiContext context)
    {
        return getLDAPListParam(name, def);
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param def the default value
     * @return the configuration value as {@link List}
     * @since 9.1.1
     */
    public List<String> getLDAPListParam(String name, List<String> def)
    {
        return getLDAPListParam(name, ',', def);
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param separator the separator used to cut each element of the list
     * @param def the default value
     * @param context the XWiki context.
     * @return the configuration value as {@link List}
     * @since 9.0
     * @deprecated since 9.1.1, use {@link #getLDAPListParam(String, char, List)} instead
     */
    @Deprecated
    public List<String> getLDAPListParam(String name, char separator, List<String> def, XWikiContext context)
    {
        return getLDAPListParam(name, separator, def);
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param separator the separator used to cut each element of the list
     * @param def the default value
     * @return the configuration value as {@link List}
     * @since 9.1.1
     */
    public List<String> getLDAPListParam(String name, char separator, List<String> def)
    {
        List<String> list = def;

        String str = getLDAPParam(name, null);

        if (str != null) {
            if (!StringUtils.isEmpty(str)) {
                list = splitParam(str, separator);
            } else {
                list = Collections.emptyList();
            }
        }

        return list;
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param def the default value
     * @param forceLowerCaseKey
     * @param context the XWiki context.
     * @return the configuration value as {@link Map}
     * @since 9.0
     * @deprecated since 9.1.1, use {@link #getLDAPMapParam(String, Map, boolean)} instead
     */
    @Deprecated
    public Map<String, String> getLDAPMapParam(String name, Map<String, String> def, boolean forceLowerCaseKey,
        XWikiContext context)
    {
        return getLDAPMapParam(name, def, forceLowerCaseKey);
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param def the default value
     * @param forceLowerCaseKey
     * @return the configuration value as {@link Map}
     * @since 9.1.1
     */
    public Map<String, String> getLDAPMapParam(String name, Map<String, String> def, boolean forceLowerCaseKey)
    {
        return getLDAPMapParam(name, '|', def, forceLowerCaseKey);
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param separator the separator used to cut each element of the list
     * @param def the default value
     * @param forceLowerCaseKey
     * @param context the XWiki context.
     * @return the configuration value as {@link Map}
     * @since 9.0
     * @deprecated since 9.1.1, use {@link #getLDAPMapParam(String, char, Map, boolean)} instead
     */
    @Deprecated
    public Map<String, String> getLDAPMapParam(String name, char separator, Map<String, String> def,
        boolean forceLowerCaseKey, XWikiContext context)
    {
        return getLDAPMapParam(name, separator, def, forceLowerCaseKey);
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param separator the separator used to cut each element of the list
     * @param def the default value
     * @param forceLowerCaseKey
     * @return the configuration value as {@link Map}
     * @since 9.1.1
     */
    public Map<String, String> getLDAPMapParam(String name, char separator, Map<String, String> def,
        boolean forceLowerCaseKey)
    {
        Map<String, String> mappings = def;

        List<String> list = getLDAPListParam(name, separator, null);

        if (list != null) {
            if (list.isEmpty()) {
                mappings = Collections.emptyMap();
            } else {
                mappings = new LinkedHashMap<>();

                for (String fieldStr : list) {
                    int index = fieldStr.indexOf('=');
                    if (index != -1) {
                        String key = fieldStr.substring(0, index);
                        String value = index + 1 == fieldStr.length() ? "" : fieldStr.substring(index + 1);

                        mappings.put(forceLowerCaseKey ? key.toLowerCase() : key, value);
                    } else {
                        LOGGER.warn("Error parsing LDAP [{}] attribute from configuration, got [{}]", name, fieldStr);
                    }
                }
            }
        }

        return mappings;
    }

    private List<String> splitParam(String text, char delimiter)
    {
        List<String> tokens = new ArrayList<>();
        boolean escaped = false;
        StringBuilder sb = new StringBuilder();

        for (char ch : text.toCharArray()) {
            if (escaped) {
                sb.append(ch);
                escaped = false;
            } else if (ch == delimiter) {
                if (sb.length() > 0) {
                    tokens.add(sb.toString());
                    sb.delete(0, sb.length());
                }
            } else if (ch == '\\') {
                escaped = true;
            } else {
                sb.append(ch);
            }
        }

        if (sb.length() > 0) {
            tokens.add(sb.toString());
        }

        return tokens;
    }

    /**
     * @param context the XWiki context
     * @return a Java regexp used to parse the remote user provided by JAAS.
     * @since 9.0
     * @deprecated since 9.1.1, use {@link #getRemoteUserPattern()} instead
     */
    @Deprecated
    public Pattern getRemoteUserPattern(XWikiContext context)
    {
        return getRemoteUserPattern();
    }

    /**
     * @return a Java regexp used to parse the remote user provided by JAAS.
     * @since 9.1.1
     */
    public Pattern getRemoteUserPattern()
    {
        String param = getLDAPParam("ldap_remoteUserParser", null);

        return param != null ? Pattern.compile(param) : null;
    }

    /**
     * @param groupId the identifier of the group matched by the REMOTE_USER regexp
     * @param context the XWiki context
     * @return the properties associated to the passed group
     * @since 9.0
     * @deprecated since 9.1.1, use {@link #getRemoteUserMapping(int)} instead
     */
    @Deprecated
    public List<String> getRemoteUserMapping(int groupId, XWikiContext context)
    {
        return getRemoteUserMapping(groupId);
    }

    /**
     * @param groupId the identifier of the group matched by the REMOTE_USER regexp
     * @return the properties associated to the passed group
     * @since 9.1.1
     */
    public List<String> getRemoteUserMapping(int groupId)
    {
        return getLDAPListParam("ldap_remoteUserMapping." + groupId, ',', Collections.<String>emptyList());
    }

    /**
     * @param propertyName the name of the property
     * @param forceLowerCaseKey if true the keys will be stored lowered cased in the {@link Map}
     * @param context the XWiki context
     * @return the mapping (the value for each domain) associated to the passed property
     * @since 9.0
     * @deprecated since 9.1.1, use {@link #getRemoteUserMapping(String, boolean)} instead
     */
    @Deprecated
    public Map<String, String> getRemoteUserMapping(String propertyName, boolean forceLowerCaseKey,
        XWikiContext context)
    {
        return getRemoteUserMapping(propertyName, forceLowerCaseKey);
    }

    /**
     * @param propertyName the name of the property
     * @param forceLowerCaseKey if true the keys will be stored lowered cased in the {@link Map}
     * @return the mapping (the value for each domain) associated to the passed property
     * @since 9.1.1
     */
    public Map<String, String> getRemoteUserMapping(String propertyName, boolean forceLowerCaseKey)
    {
        return getLDAPMapParam("ldap_remoteUserMapping." + propertyName, '|', Collections.<String, String>emptyMap(),
            forceLowerCaseKey);
    }

    /**
     * @param context the XWiki context
     * @return try to find existing XWiki user with both complete user id and user login
     * @since 9.0
     * @deprecated since 9.1.1, use {@link #getTestLoginFor()} instead
     */
    @Deprecated
    public Set<String> getTestLoginFor(XWikiContext context)
    {
        return getTestLoginFor();
    }

    /**
     * @return try to find existing XWiki user with both complete user id and user login
     * @since 9.1.1
     */
    public Set<String> getTestLoginFor()
    {
        List<String> list = getLDAPListParam("ldap_testLoginFor", ',', Collections.<String>emptyList());

        Set<String> set = new HashSet<>(list.size());
        for (String uid : list) {
            set.add(StrSubstitutor.replace(uid, this.memoryConfiguration));
        }

        LOGGER.debug("TestLoginFor: {}", set);

        return set;
    }

    /**
     * @param context the XWiki context
     * @return an HTTP header that could be used to retrieve the authenticated user (only in xwiki.cfg).
     * @since 9.1
     * @deprecated since 9.1.1, use {@link #getHttpHeader()} instead
     */
    @Deprecated
    public String getHttpHeader(XWikiContext context)
    {
        return getHttpHeader();
    }

    /**
     * @return an HTTP header that could be used to retrieve the authenticated user (only in xwiki.cfg).
     * @since 9.1.1
     */
    public String getHttpHeader()
    {
        return this.cfgConfigurationSource.getProperty("xwiki.authentication.ldap.httpHeader");
    }
}
