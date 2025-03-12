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

import java.io.UnsupportedEncodingException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPDN;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;
import com.xpn.xwiki.XWikiContext;

/**
 * LDAP communication tool.
 * 
 * @version $Id$
 * @since 8.3
 */
public class XWikiLDAPConnection
{
    /**
     * Logging tool.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiLDAPConnection.class);

    /**
     * The LDAP connection.
     */
    private LDAPConnection connection;

    /**
     * LDAP attributes that should be treated as binary data.
     */
    private Set<String> binaryAttributes = new HashSet<>();

    private final XWikiLDAPConfig configuration;

    /**
     * @deprecated since 8.5, use {@link #XWikiLDAPConnection(XWikiLDAPConfig)} instead
     */
    @Deprecated
    public XWikiLDAPConnection()
    {
        this(new XWikiLDAPConfig(null));
    }

    /**
     * @param configuration the configuration to use
     * @since 9.0
     */
    public XWikiLDAPConnection(XWikiLDAPConfig configuration)
    {
        this.configuration = configuration;
    }

    /**
     * @param connection the connection to copy
     */
    public XWikiLDAPConnection(org.xwiki.contrib.ldap.XWikiLDAPConnection connection)
    {
        this();

        this.connection = connection.connection;
        this.binaryAttributes = connection.binaryAttributes;
    }

    /**
     * @param context the XWiki context.
     * @return the maximum number of milliseconds the client waits for any operation under these constraints to
     *         complete.
     */
    private int getTimeout(XWikiContext context)
    {
        return this.configuration.getLDAPTimeout();
    }

    /**
     * @param context the XWiki context.
     * @return the maximum number of search results to be returned from a search operation.
     */
    private int getMaxResults(XWikiContext context)
    {
        return this.configuration.getLDAPMaxResults();
    }

    /**
     * @return the {@link LDAPConnection}.
     */
    public LDAPConnection getConnection()
    {
        return this.connection;
    }

    /**
     * Open a LDAP connection.
     * 
     * @param ldapUserName the user name to connect to LDAP server.
     * @param password the password to connect to LDAP server.
     * @param context the XWiki context.
     * @return true if connection succeed, false otherwise.
     * @throws XWikiLDAPException error when trying to open connection.
     */
    public boolean open(String ldapUserName, String password, XWikiContext context) throws XWikiLDAPException
    {
        // open LDAP
        int ldapPort = this.configuration.getLDAPPort();
        String ldapHost = this.configuration.getLDAPParam("ldap_server", "localhost");

        // allow to use the given user and password also as the LDAP bind user and password
        String bindDN = this.configuration.getLDAPBindDN(ldapUserName, password);
        String bindPassword = this.configuration.getLDAPBindPassword(ldapUserName, password);

        boolean bind;
        if ("1".equals(this.configuration.getLDAPParam("ldap_ssl", "0"))) {
            String keyStore = this.configuration.getLDAPParam("ldap_ssl.keystore", "");

            LOGGER.debug("Connecting to LDAP using SSL");

            bind = open(ldapHost, ldapPort, bindDN, bindPassword, keyStore, true, context);
        } else {
            bind = open(ldapHost, ldapPort, bindDN, bindPassword, null, false, context);
        }

        return bind;
    }

    /**
     * Open LDAP connection.
     * 
     * @param ldapHost the host of the server to connect to.
     * @param ldapPort the port of the server to connect to.
     * @param loginDN the user DN to connect to LDAP server.
     * @param password the password to connect to LDAP server.
     * @param pathToKeys the path to SSL keystore to use.
     * @param ssl if true connect using SSL.
     * @param context the XWiki context.
     * @return true if the connection succeed, false otherwise.
     * @throws XWikiLDAPException error when trying to open connection.
     */
    public boolean open(String ldapHost, int ldapPort, String loginDN, String password, String pathToKeys, boolean ssl,
        XWikiContext context) throws XWikiLDAPException
    {
        int port = ldapPort;

        if (port <= 0) {
            port = ssl ? LDAPConnection.DEFAULT_SSL_PORT : LDAPConnection.DEFAULT_PORT;
        }

        setBinaryAttributes(this.configuration.getBinaryAttributes());

        try {
            if (ssl) {
                // The security providers are preregistered and used depending on the context, so there is no need to
                // set one. Dynamically set it only if a specific provider is requested.
                Provider secureProvider = this.configuration.getSecureProvider();
                if (secureProvider != null) {
                    Security.addProvider(secureProvider);
                }

                if (pathToKeys != null && pathToKeys.length() > 0) {
                    // Dynamically set the property that JSSE uses to identify
                    // the keystore that holds trusted root certificates

                    System.setProperty("javax.net.ssl.trustStore", pathToKeys);
                    // obviously unnecessary: sun default pwd = "changeit"
                    // System.setProperty("javax.net.ssl.trustStorePassword", sslpwd);
                }

                LDAPSocketFactory ssf = new LDAPJSSESecureSocketFactory();

                // Set the socket factory as the default for all future connections
                // LDAPConnection.setSocketFactory(ssf);

                // Note: the socket factory can also be passed in as a parameter
                // to the constructor to set it for this connection only.
                this.connection = new LDAPConnection(ssf);
            } else {
                this.connection = new LDAPConnection();
            }

            // connect
            boolean doServiceDiscovery = "1".equals(this.configuration.getLDAPParam("ldap_service_discovery", "1"));
            connect(ldapHost, port, doServiceDiscovery, ssl);

            // set referral following
            LDAPSearchConstraints constraints = new LDAPSearchConstraints(this.connection.getConstraints());
            constraints.setTimeLimit(getTimeout(context));
            constraints.setMaxResults(getMaxResults(context));
            if (this.configuration.isFollowReferrals()) {
                constraints.setReferralFollowing(true);
                constraints.setReferralHandler(new LDAPPluginReferralHandler(loginDN, password, context));
            }
            this.connection.setConstraints(constraints);

            // bind
            bind(loginDN, password);
        } catch (UnsupportedEncodingException e) {
            throw new XWikiLDAPException("LDAP bind failed with UnsupportedEncodingException.", e);
        } catch (LDAPException e) {
            throw new XWikiLDAPException("LDAP bind failed with LDAPException.", e);
        }

        return true;
    }

    /**
     * Connect to server.
     * 
     * @param ldapHost the host of the server to connect to.
     * @param port the port of the server to connect to.
     * @param doServiceDiscovery if true, LDAP hosts are discovered via a SRV record lookup. If no SRV record is found,
     *            <code>ldapHost</code> is used as fallback.
     * @param ssl if true service discovery is performed for LDAPS.
     * @throws LDAPException error when trying to connect.
     */
    private void connect(String ldapHost, int port, boolean doServiceDiscovery, boolean ssl) throws LDAPException
    {
        if (doServiceDiscovery) {
            List<SRVRecord> ldapSRVRecords = discoverLDAPService(ldapHost, ssl);
            if (ldapSRVRecords != null && !ldapSRVRecords.isEmpty()) {
                LOGGER.debug("{} SRV record(s) discovered", ldapSRVRecords.size());
                StringBuilder ldapHostListBuilder = new StringBuilder();
                final String SEPARATOR = " ";
                for (SRVRecord ldapSRVRecord : ldapSRVRecords) {
                    ldapHostListBuilder.append(ldapSRVRecord.getTarget());
                    ldapHostListBuilder.append(":");
                    ldapHostListBuilder.append(ldapSRVRecord.getPort());
                    ldapHostListBuilder.append(SEPARATOR);
                }
                ldapHost = ldapHostListBuilder.toString();
            }
        }

        LOGGER.debug("Connection to LDAP server [{}:{}]", ldapHost, port);

        // connect to the server
        this.connection.connect(ldapHost, port);
    }

    /**
     * This class encapsulates an SRV record.
     * 
     * @see <a href="https://tools.ietf.org/html/rfc2782">RFC 2782: A DNS RR for specifying the location of services
     *      (DNS SRV)</a>
     */
    private static class SRVRecord
    {
        private int priority, weight, port;

        private String target;

        /**
         * Creates an SRV Record from the given data
         *
         * @param attributes A string array that contains priority, weight, port and name of the server (in that order)
         */
        public SRVRecord(String[] attributes)
        {
            if (attributes.length != 4)
                throw new IllegalArgumentException(
                    "attributes array needs exactly 4 entries: priority, weight, port and server name");
            // format for an JNDI SRV record lookup is "0 100 389 dc1.example.com."
            this.priority = Integer.parseInt(attributes[0]);
            this.weight = Integer.parseInt(attributes[1]);
            this.port = Integer.parseInt(attributes[2]);
            this.target = attributes[3];
        }

        /** Returns the priority */
        public int getPriority()
        {
            return priority;
        }

        /** Returns the weight */
        public int getWeight()
        {
            return weight;
        }

        /** Returns the port that the service runs on */
        public int getPort()
        {
            return port;
        }

        /** Returns the host running the service */
        public String getTarget()
        {
            return target;
        }

        /** Converts SRV record to a String */
        @Override
        public String toString()
        {
            StringBuilder sb = new StringBuilder();
            sb.append(priority).append(" ");
            sb.append(weight).append(" ");
            sb.append(port).append(" ");
            sb.append(target);
            return sb.toString();
        }

        /**
         * Performs a weighted shuffle on a list of SRV records using Efraimidis/Spirakis fast parallel weighted random
         * sampling algorithm A
         * 
         * @param records a list of SRV records
         * @return a list of SRV records, shuffled according to their weight
         */
        private static List<SRVRecord> efraimidisWeightedShuffle(List<SRVRecord> records)
        {
            List<Pair<SRVRecord, Double>> recordKeyList = new ArrayList<>(records.size());
            for (SRVRecord record : records) {
                // Math.radom() returns doubles < 1.0 so this is not entirely correct, but since key is always 0 for
                // u < 1.0 and weight=0 it saves us from handling 0-weighted records separately (permissible by RFC 2782
                // but weights need to be strictly positive reals for Efraimidis/Spirakis algorithm A to work)
                double key = Math.pow(Math.random(), (1.0 / record.getWeight()));
                recordKeyList.add(Pair.of(record, key));
            }
            recordKeyList.sort(
                (Pair<SRVRecord, Double> p1, Pair<SRVRecord, Double> p2) -> p2.getRight().compareTo(p1.getRight()));

            List<SRVRecord> resultList = new ArrayList<>(records.size());
            for (Pair<SRVRecord, Double> p : recordKeyList)
                resultList.add(p.getLeft());

            return resultList;
        }
    }

    /**
     * Performs an SRV record lookup on <code>_ldap._tcp.realm</code> or <code>_ldaps._tcp.realm</code> if ssl is
     * enabled.
     * 
     * @param realm the realm for which SRV records should be looked up.
     * @param ldaps if true, service discovery uses <code>_ldaps._tcp</code>, if false <code>_ldap._tcp</code> is used.
     * @return a list of SRV records sorted by priority/weight, null if SRV lookup failed or returned an empty result.
     */
    private List<SRVRecord> discoverLDAPService(String realm, boolean ldaps)
    {
        String service = ldaps ? "_ldaps" : "_ldap";
        String proto = "_tcp";
        String lookup = service + "." + proto + "." + realm;
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        Attributes attributes;
        try {
            DirContext ctx = new InitialDirContext(env);
            attributes = ctx.getAttributes(lookup, new String[] {"SRV"});
        } catch (NameNotFoundException e) {
            LOGGER.debug("No SRV record for {} found.", lookup);
            return null;
        } catch (NamingException e) {
            LOGGER.debug("DNS lookup failed.", e);
            return null;
        }

        Attribute attribute = attributes.get("SRV");
        if (attribute == null) {
            LOGGER.debug("No SRV record found in {}.", attribute);
            return null;
        }

        // organise entries by priority so a weighted shuffle can be performed for all entries with a given priority
        SortedMap<Integer, List<SRVRecord>> priorityMap = new TreeMap<>();
        for (int i = 0; i < attribute.size(); i++) {
            try {
                Object value = attribute.get(i);
                if (value != null) {
                    SRVRecord srvRecord = new SRVRecord(value.toString().split(" "));
                    LOGGER.trace("SRV record found: {}", srvRecord.toString());
                    priorityMap.putIfAbsent(srvRecord.getPriority(), new ArrayList<SRVRecord>());
                    priorityMap.get(srvRecord.getPriority()).add(srvRecord);
                }
            } catch (NamingException e) {
                LOGGER.debug("Unable to get {}-th value from attributes.", i, e);
            } catch (IllegalArgumentException e) {
                LOGGER.debug("Unable to create SRVRecord object.", e);
            }
        }
        List<SRVRecord> sortedWeightedRecordList = new ArrayList<>();
        for (int priority : priorityMap.keySet())
            sortedWeightedRecordList.addAll(SRVRecord.efraimidisWeightedShuffle(priorityMap.get(priority)));

        return sortedWeightedRecordList;
    }

    /**
     * Bind to LDAP server.
     * 
     * @param loginDN the user DN to connect to LDAP server.
     * @param password the password to connect to LDAP server.
     * @throws UnsupportedEncodingException error when converting provided password to UTF-8 table.
     * @throws LDAPException error when trying to bind.
     */
    public void bind(String loginDN, String password) throws UnsupportedEncodingException, LDAPException
    {
        LOGGER.debug("Binding to LDAP server with credentials login=[{}]", loginDN);

        // authenticate to the server
        this.connection.bind(LDAPConnection.LDAP_V3, loginDN, password.getBytes("UTF8"));
    }

    /**
     * Close LDAP connection.
     */
    public void close()
    {
        try {
            if (this.connection != null) {
                this.connection.disconnect();
            }
        } catch (LDAPException e) {
            LOGGER.debug("LDAP close failed.", e);
        }
    }

    /**
     * Check if provided password is correct provided users's password.
     * 
     * @param userDN the user.
     * @param password the password.
     * @return true if the password is valid, false otherwise.
     */
    public boolean checkPassword(String userDN, String password)
    {
        return checkPassword(userDN, password, "userPassword");
    }

    /**
     * Check if provided password is correct provided users's password.
     * 
     * @param userDN the user.
     * @param password the password.
     * @param passwordField the name of the LDAP field containing the password.
     * @return true if the password is valid, false otherwise.
     */
    public boolean checkPassword(String userDN, String password, String passwordField)
    {
        try {
            LDAPAttribute attribute = new LDAPAttribute(passwordField, password);
            return this.connection.compare(userDN, attribute);
        } catch (LDAPException e) {
            if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
                LOGGER.debug("Unable to locate user_dn [{}]", userDN, e);
            } else if (e.getResultCode() == LDAPException.NO_SUCH_ATTRIBUTE) {
                LOGGER.debug("Unable to verify password because userPassword attribute not found.", e);
            } else {
                LOGGER.debug("Unable to verify password", e);
            }
        }

        return false;
    }

    /**
     * Execute a LDAP search query and return the first entry.
     * 
     * @param baseDN the root DN from where to search.
     * @param filter the LDAP filter.
     * @param attr the attributes names of values to return.
     * @param ldapScope the scope of the entries to search. The following are the valid options:
     *            <ul>
     *            <li>SCOPE_BASE - searches only the base DN
     *            <li>SCOPE_ONE - searches only entries under the base DN
     *            <li>SCOPE_SUB - searches the base DN and all entries within its subtree
     *            </ul>
     * @return the found LDAP attributes.
     */
    public List<XWikiLDAPSearchAttribute> searchLDAP(String baseDN, String filter, String[] attr, int ldapScope)
    {
        List<XWikiLDAPSearchAttribute> searchAttributeList = null;

        // filter return all attributes return attrs and values time out value
        try (PagedLDAPSearchResults searchResults = searchPaginated(baseDN, ldapScope, filter, attr, false)) {
            if (!searchResults.hasMore()) {
                return Collections.emptyList();
            }

            LDAPEntry nextEntry = searchResults.next();
            String foundDN = nextEntry.getDN();

            searchAttributeList = new ArrayList<>();

            searchAttributeList.add(new XWikiLDAPSearchAttribute("dn", foundDN));

            LDAPAttributeSet attributeSet = nextEntry.getAttributeSet();

            ldapToXWikiAttribute(searchAttributeList, attributeSet);
        } catch (LDAPException e) {
            LOGGER.debug("LDAP Search failed", e);
        }

        LOGGER.debug("LDAP search found attributes [{}]", searchAttributeList);

        return searchAttributeList;
    }

    /**
     * @param baseDN the root DN from where to search.
     * @param filter filter the LDAP filter
     * @param attr the attributes names of values to return
     * @param ldapScope the scope of the entries to search. The following are the valid options:
     *            <ul>
     *            <li>SCOPE_BASE - searches only the base DN
     *            <li>SCOPE_ONE - searches only entries under the base DN
     *            <li>SCOPE_SUB - searches the base DN and all entries within its subtree
     *            </ul>
     * @return a result stream. LDAPConnection#abandon should be called when it's not needed anymore.
     * @throws LDAPException error when searching
     * @since 3.3M1
     */
    public LDAPSearchResults search(String baseDN, String filter, String[] attr, int ldapScope) throws LDAPException
    {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("LDAP search: baseDN=[{}] query=[{}] attr=[{}] ldapScope=[{}]", baseDN, filter,
                attr != null ? Arrays.asList(attr) : null, ldapScope);
        }

        return this.connection.search(baseDN, ldapScope, filter, attr, false);
    }

    /**
     * @param base the root DN from where to search.
     * @param scope the scope of the entries to search. The following are the valid options:
     *            <ul>
     *            <li>SCOPE_BASE - searches only the base DN
     *            <li>SCOPE_ONE - searches only entries under the base DN
     *            <li>SCOPE_SUB - searches the base DN and all entries within its subtree
     *            </ul>
     * @param filter filter the LDAP filter
     * @param attrs the attributes names of values to return
     * @param typesOnly if true, returns the names but not the values of the attributes found. If false, returns the
     *            names and values for attributes found.
     * @return a result stream. LDAPConnection#abandon should be called when it's not needed anymore.
     * @throws LDAPException error when searching
     * @since 9.3
     */
    public PagedLDAPSearchResults searchPaginated(String base, int scope, String filter, String[] attrs,
        boolean typesOnly) throws LDAPException
    {
        int pageSize = this.configuration.getSearchPageSize();

        return new PagedLDAPSearchResults(this, base, scope, filter, attrs, typesOnly, pageSize);
    }

    /**
     * Fill provided <code>searchAttributeList</code> with provided LDAP attributes.
     * 
     * @param searchAttributeList the XWiki attributes.
     * @param attributeSet the LDAP attributes.
     */
    public void ldapToXWikiAttribute(List<XWikiLDAPSearchAttribute> searchAttributeList, LDAPAttributeSet attributeSet)
    {
        for (LDAPAttribute attribute : (Set<LDAPAttribute>) attributeSet) {
            String attributeName = attribute.getName();

            if (!isBinaryAttribute(attributeName)) {
                LOGGER.debug("  - values for attribute [{}]", attributeName);

                Enumeration<String> allValues = attribute.getStringValues();

                if (allValues != null) {
                    while (allValues.hasMoreElements()) {
                        String value = allValues.nextElement();

                        LOGGER.debug("    |- [{}]", value);

                        searchAttributeList.add(new XWikiLDAPSearchAttribute(attributeName, value));
                    }
                }
            } else {
                LOGGER.debug("  - attribute [{}] is binary", attributeName);

                Enumeration<byte[]> allValues = attribute.getByteValues();

                if (allValues != null) {
                    while (allValues.hasMoreElements()) {
                        byte[] value = allValues.nextElement();

                        searchAttributeList.add(new XWikiLDAPSearchAttribute(attributeName, value));
                    }
                }
            }
        }
    }

    /**
     * Fully escape DN value (the part after the =).
     * <p>
     * For example, for the dn value "Acme, Inc", the escapeLDAPDNValue method returns "Acme\, Inc".
     * </p>
     * 
     * @param value the DN value to escape
     * @return the escaped version o the DN value
     */
    public static String escapeLDAPDNValue(String value)
    {
        return StringUtils.isBlank(value) ? value : LDAPDN.escapeRDN("key=" + value).substring(4);
    }

    /**
     * Escape part of a LDAP query filter.
     * 
     * @param value the value to escape
     * @return the escaped version
     */
    public static String escapeLDAPSearchFilter(String value)
    {
        if (value == null) {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char curChar = value.charAt(i);
            switch (curChar) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(curChar);
            }
        }
        return sb.toString();
    }

    /**
     * Update list of LDAP attributes that should be treated as binary data.
     * 
     * @param binaryAttributes set of binary attributes
     */
    private void setBinaryAttributes(Set<String> binaryAttributes)
    {
        this.binaryAttributes = binaryAttributes;
    }

    /**
     * Checks whether attribute should be treated as binary data.
     * 
     * @param attributeName name of attribute to check
     * @return true if attribute should be treated as binary data.
     */
    private boolean isBinaryAttribute(String attributeName)
    {
        return binaryAttributes.contains(attributeName);
    }
}
