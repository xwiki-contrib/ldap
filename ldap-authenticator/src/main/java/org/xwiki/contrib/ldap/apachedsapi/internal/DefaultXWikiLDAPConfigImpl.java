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
package org.xwiki.contrib.ldap.apachedsapi.internal;

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

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.component.annotation.Component;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.context.Execution;
import org.xwiki.context.ExecutionContext;
import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.apachedsapi.XWikiLDAPConnection;
import org.xwiki.contrib.ldap.apachedsapi.XWikiLdapConfig;
import org.xwiki.stability.Unstable;

/**
 * Component to access to LDAP configurations.
 * 
 * @version $Id$
 * @since 10.0
 */
@Component(roles = XWikiLdapConfig.class)
public class DefaultXWikiLDAPConfigImpl implements XWikiLdapConfig
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
     */
    public static final String PREF_LDAP_UPDATE_PHOTO = "ldap_update_photo";

    /**
     * Profile photo attachment name property name in XWikiPreferences.
     */
    public static final String PREF_LDAP_PHOTO_ATTACHMENT_NAME = "ldap_photo_attachment_name";

    /**
     * LDAP photo property name in XWikiPreferences.
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
     */
    public static final Set<String> DEFAULT_GROUP_CLASSES = new HashSet<>();

    /**
     * Different LDAP implementations groups member property name.
     */
    public static final Set<String> DEFAULT_GROUP_MEMBERFIELDS = new HashSet<>();

    /**
     * Default LDAP attribute name containing binary photo.
     */
    public static final String DEFAULT_PHOTO_ATTRIBUTE = "thumbnailPhoto";

    /**
     * Logging tool.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultXWikiLDAPConfigImpl.class);

    /**
     * The default secure provider to use for SSL.
     */
    private static final String DEFAULT_SECUREPROVIDER = "com.sun.net.ssl.internal.ssl.Provider";

    /**
     * the key to store the thread dependent "in memory" configuration in the execution context.
     */
    private static final String LDAP_IN_MEMORY_CONFIG_KEY = DefaultXWikiLDAPConfigImpl.class.getName() + "::memory";

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

    @Inject
    @Named("wiki")
    private ConfigurationSource configurationSource;

    @Inject
    @Named("xwikicfg")
    private ConfigurationSource cfgConfigurationSource;

    @Inject
    private Execution executionContextProvider;

    private final Map<String, String> finalMemoryConfiguration;

    /**
     * component constructor.
     */
    public DefaultXWikiLDAPConfigImpl()
    {
        this.finalMemoryConfiguration = new HashMap<>();
    }

    /**
     * @return the custom in memory configuration. Can be used to override any property per login action.
     */
    @Override
    public Map<String, String> getMemoryConfiguration()
    {
        ExecutionContext exec = executionContextProvider.getContext();
        @SuppressWarnings("unchecked")
        Map<String, String> memoryConfig = (Map<String, String>) exec.getProperty(LDAP_IN_MEMORY_CONFIG_KEY);
        if (memoryConfig == null) {
            memoryConfig = new HashMap<String, String>();
            // exec.setProperty(LDAP_IN_MEMORY_CONFIG_KEY, memoryConfig);
            exec.newProperty(LDAP_IN_MEMORY_CONFIG_KEY).initial(memoryConfig).nonNull().declare();
        }
        return memoryConfig;
    }

    /**
     * Parse the given user name for user id and group. 
     * Given the regular expression from the "ldap_remoteUserParser" configuration variable
     * parse the input and stores the "uid" and group information extracted from that expression.
     * The group information is stored according  "ldap_remoteUserMapping.&lt;groupname>" mapping.
     * @param ssoRemoteUser the id of the remote user; should not be null
     */
    @Override
    public void parseRemoteUser(String ssoRemoteUser)
    {
        this.getMemoryConfiguration().put("auth.input", ssoRemoteUser);
        this.getMemoryConfiguration().put("uid", ssoRemoteUser.trim());

        Pattern remoteUserParser = getRemoteUserPattern();

        LOGGER.debug("remoteUserParser: {}", remoteUserParser);

        if (remoteUserParser != null) {
            Matcher marcher = remoteUserParser.matcher(ssoRemoteUser);

            if (marcher.find()) {
                int groupCount = marcher.groupCount();
                if (groupCount == 0) {
                    this.getMemoryConfiguration().put("uid", marcher.group().trim());
                } else {
                    for (int g = 1; g <= groupCount; ++g) {
                        String groupValue = marcher.group(g);

                        List<String> remoteUserMapping = getRemoteUserMapping(g);

                        for (String configName : remoteUserMapping) {
                            this.getMemoryConfiguration().put(configName, convertRemoteUserMapping(configName, groupValue));
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
    @Override
    public String getLDAPParam(String name, String cfgName, String def)
    {
        if (this.getMemoryConfiguration().containsKey(name)) {
            return this.getMemoryConfiguration().get(name);
        }

        // First look for the parameter in the defined configuration source (by default in XWikiPreferences document
        // from the current wiki).
        String param = this.configurationSource.getProperty(name, String.class);

        // If not found, check in xwiki.cfg
        if (param == null || "".equals(param)) {
            param = this.cfgConfigurationSource.getProperty(cfgName);
        }

        if (param == null) {
            param = this.finalMemoryConfiguration.get(name);
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
     * @return the value of the property.
     */
    @Override
    public String getLDAPParam(String name, String def)
    {
        return getLDAPParam(name, name.replaceFirst(PREF_LDAP_SUFFIX, CFG_LDAP_SUFFIX), def);
    }


    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax ldap_*name* (for XWiki
     * Preferences) will be changed to ldap.*name* for xwiki.cfg.
     *
     * @param name the name of the property in XWikiPreferences.
     * @param cfgName the name of the property in xwiki.cfg.
     * @param def default value.
     * @return the value of the property.
     */
    @Override
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
     */
    @Override
    public long getLDAPParamAsLong(String name, long def)
    {
        return getLDAPParamAsLong(name, name.replace(PREF_LDAP_SUFFIX, CFG_LDAP_SUFFIX), def);
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param def the default value
     * @return the configuration value as {@link List}
     */
    @Override
    public List<String> getLDAPListParam(String name, List<String> def)
    {
        return getLDAPListParam(name, ',', def);
    }

    /**
     * @return a Java regexp used to parse the remote user provided by JAAS.
     */
    @Override
    public Pattern getRemoteUserPattern()
    {
        String param = getLDAPParam("ldap_remoteUserParser", null);

        return param != null ? Pattern.compile(param) : null;
    }

    /**
     * @param groupId the identifier of the group matched by the REMOTE_USER regexp
     * @return the properties associated to the passed group
     */
    @Override
    public List<String> getRemoteUserMapping(int groupId)
    {
        return getLDAPListParam("ldap_remoteUserMapping." + groupId, ',', Collections.<String>emptyList());
    }

    /**
     * @param propertyName the name of the property
     * @param forceLowerCaseKey if true the keys will be stored lowered cased in the {@link Map}
     * @return the mapping (the value for each domain) associated to the passed property
     */
    @Override
    public Map<String, String> getRemoteUserMapping(String propertyName, boolean forceLowerCaseKey)
    {
        return getLDAPMapParam("ldap_remoteUserMapping." + propertyName, '|', Collections.<String, String>emptyMap(),
            forceLowerCaseKey);
    }

    /**
     * @return try to find existing XWiki user with both complete user id and user login
     */
    @Override
    public Set<String> getTestLoginFor()
    {
        List<String> list = getLDAPListParam("ldap_testLoginFor", ',', Collections.<String>emptyList());

        Set<String> set = new HashSet<>(list.size());
        for (String uid : list) {
            set.add(StrSubstitutor.replace(uid, this.getMemoryConfiguration()));
        }

        LOGGER.debug("TestLoginFor: {}", set);

        return set;
    }

    /**
     * @return an HTTP header that could be used to retrieve the authenticated user (only in xwiki.cfg).
     */
    @Override
    public String getHttpHeader()
    {
        return this.cfgConfigurationSource.getProperty("xwiki.authentication.ldap.httpHeader");
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param separator the separator used to cut each element of the list
     * @param def the default value
     * @return the configuration value as {@link List}
     */
    @Override
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
     * @return the configuration value as {@link Map}
     */
    @Override
    public Map<String, String> getLDAPMapParam(String name, Map<String, String> def, boolean forceLowerCaseKey)
    {
        return getLDAPMapParam(name, '|', def, forceLowerCaseKey);
    }

    /**
     * @param name the name of the property in XWikiPreferences.
     * @param separator the separator used to cut each element of the list
     * @param def the default value
     * @param forceLowerCaseKey
     * @return the configuration value as {@link Map}
     * @since 9.1.1
     */
    @Override
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
     * Add a configuration value to the "in memory" config.
     * These values will be effective if there is no value in the other configuration sources,
     * and will be used by all threads until the server is restarted (or the authenticator extension reloaded)
     * @param key the name of the configuration variable
     * @param value the configuration value as a string
     */
    @Override
    @Unstable
    public void setFinalProperty(String key, String value)
    {
        this.finalMemoryConfiguration.put(key, value);
    }
    
    /**
     * @return the collection of the LDAP groups classes.
     */
    @Override
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
     * @return the names of the fields for members of groups.
     */
    @Override
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
     * @return the secure provider to use for SSL.
     * @throws XWikiLDAPException error when trying to instantiate secure provider.
     * @since 9.1.1
     */
    @Override
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
     * @return true if LDAP is enabled.
     */
    @Override
    public boolean isLDAPEnabled()
    {
        String param = getLDAPParam("ldap", "xwiki.authentication.ldap", "0");

        return param != null && param.equals("1");
    }

    /**
     * Get LDAP port from configuration.
     * 
     * @return the LDAP port.
     */
    @Override
    public int getLDAPPort()
    {
        return (int) getLDAPParamAsLong(PREF_LDAP_PORT, CFG_LDAP_PORT, 0);
    }

    /**
     * Get LDAP host from configuration.
     * 
     * @return the LDAP host name.
     */
    @Override
    public String getLDAPHost()
    {
        // FIXME: constants needed for this?
        return getLDAPParam("ldap_server", "localhost");
    }

    /**
     * Get mapping between XWiki groups names and LDAP groups names.
     *
     * @return the mapping between XWiki users and LDAP users. The key is the XWiki group, and the value is the list of
     *         mapped LDAP groups.
     * @since 9.1.1
     */
    @Override
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
     * @return the mapping between XWiki groups and LDAP groups.
     */
    @Override
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
                    LOGGER.error("Error parsing LDAP fields mapping attribute from configuration, got [{}]", fields[j]);
                }
            }
        }

        return userMappings;
    }

    /**
     * @return the time in seconds until a entry in the cache is to expire.
     */
    @Override
    public int getCacheExpiration()
    {
        return (int) getLDAPParamAsLong("ldap_groupcache_expiration", 21600);
    }

    /**
     * @return the pattern to resolve to find the password to use to connect to LDAP server. It is based on
     *         {@link MessageFormat}.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindDN(String, String)
     */
    @Override
    public String getLDAPBindDN()
    {
        return getLDAPParam("ldap_bind_DN", "{0}");
    }

    /**
     * @param input the login provided by the user
     * @param password the password provided by the user
     * @return the login to use to connect to LDAP server.
     */
    @Override
    public String getLDAPBindDN(String input, String password)
    {
        return MessageFormat.format(getLDAPBindDN(), XWikiLDAPConnection.escapeLDAPDNValue(input),
            XWikiLDAPConnection.escapeLDAPDNValue(password));
    }

    /**
     * @return the pattern to resolve to find the password to use to connect to LDAP server.
     * @see MessageFormat#format(String, Object...)
     * @see #getLDAPBindPassword(String, String)
     */
    @Override
    public String getLDAPBindPassword()
    {
        return getLDAPParam("ldap_bind_pass", "{1}");
    }

    /**
     * @param input the login provided by the user
     * @param password the password provided by the user
     * @return the password to use to connect to LDAP server.
     */
    @Override
    public String getLDAPBindPassword(String input, String password)
    {
        return MessageFormat.format(getLDAPBindPassword(), input, password);
    }

    /**
     * @return the maximum number of milliseconds the client waits for any operation under these constraints to
     *         complete.
     */
    @Override
    public int getLDAPTimeout()
    {
        return (int) getLDAPParamAsLong("ldap_timeout", 1000);
    }

    /**
     * @return the maximum number of search results to be returned from a search operation.
     */
    @Override
    public int getLDAPMaxResults()
    {
        return (int) getLDAPParamAsLong("ldap_maxresults", 1000);
    }

    /**
     * @return the maximum number of elements to return in each search page
     */
    @Override
    public int getSearchPageSize()
    {
        return (int) getLDAPParamAsLong("ldap_searchPageSize", 500);
    }

    /**
     * @return set of LDAP attributes that should be treated as binary data.
     */
    @Override
    public Set<String> getBinaryAttributes()
    {
        Set<String> binaryAttributes = new HashSet<>();

        binaryAttributes.add(getLDAPParam(DefaultXWikiLDAPConfigImpl.PREF_LDAP_PHOTO_ATTRIBUTE, DEFAULT_PHOTO_ATTRIBUTE));

        return binaryAttributes;
    }
}
