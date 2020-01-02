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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.codec.api.BinaryAttributeDetector;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.EntryCursorImpl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute;

import com.novell.ldap.util.Base64;
import com.xpn.xwiki.XWikiContext;

/**
 * A small abstraction around the LDAP connection.
 * This variant uses the Apache DS API.
 * 
 * @version $Id$
 * @since 10.0
 */
public class XWikiLdapConnection
{
    /**
     * Logging tool.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiLdapConnection.class);

    /**
     * The LDAP connection.
     */
    private LdapConnection connection;

    /**
     * LDAP attributes that should be treated as binary data.
     */
    private Set<String> binaryAttributes = new HashSet<>();

    private final XWikiLdapConfig configuration;

    /**
     * @param configuration the configuration to use
     */
    public XWikiLdapConnection(XWikiLdapConfig configuration)
    {
        this.configuration = configuration;
    }

    /**
     * @param connection the connection to copy
     */
    public XWikiLdapConnection(XWikiLdapConnection connection)
    {
        this.connection = connection.connection;
        this.binaryAttributes = connection.binaryAttributes;
        this.configuration = connection.configuration;
    }

    /**
     * @return the maximum number of milliseconds the client waits for any operation under these constraints to
     *         complete.
     */
    private int getTimeout()
    {
        return this.configuration.getLDAPTimeout();
    }

    /**
     * @return the maximum number of search results to be returned from a search operation.
     */
    int getMaxResults()
    {
        return this.configuration.getLDAPMaxResults();
    }

    /**
     * @return the {@link LdapConnection}.
     */
    public LdapConnection getConnection()
    {
        return this.connection;
    }

    /**
     * @return the host to connect to
     */
    public String getLDAPHost()
    {
        return this.configuration.getLDAPParam("ldap_server", "localhost");
    }

    /**
     * @return the port to connect to
     */
    public int getLDAPPort()
    {
        return this.configuration.getLDAPPort();
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
        String ldapHost = this.getLDAPHost();

        // allow to use the given user and password also as the LDAP bind user and password
        String bindDN = this.configuration.getLDAPBindDN(ldapUserName, password);
        String bindPassword = this.configuration.getLDAPBindPassword(ldapUserName, password);

        boolean bind;
        boolean useTLS = "1".equals(this.configuration.getLDAPParam("ldap_tls", "0"));
        boolean useSSL = "1".equals(this.configuration.getLDAPParam("ldap_ssl", "0"));

        if (useTLS || useSSL) {
            String keyStore = this.configuration.getLDAPParam("ldap_ssl.keystore", "");

            LOGGER.debug("Connecting to LDAP using " +(useTLS?"TLS":"SSL"));

            bind = open(ldapHost, ldapPort, bindDN, bindPassword, keyStore, useTLS, useSSL, context);
        } else {
            bind = open(ldapHost, ldapPort, bindDN, bindPassword, null, false, false, context);
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
     * @param pathToKeys the path to TLS/SSL keystore to use.
     * @param tls if true connect using TLS.
     * @param ssl if true connect using SSL.
     * @param context the XWiki context.
     * @return true if the connection succeed, false otherwise.
     * @throws XWikiLDAPException error when trying to open connection.
     */
    public boolean open(String ldapHost, int ldapPort, String loginDN, String password, String pathToKeys,
        boolean tls, boolean ssl, XWikiContext context) throws XWikiLDAPException
    {
        int port = ldapPort;

        if (port <= 0) {
            port = ssl ? LdapConnectionConfig.DEFAULT_LDAPS_PORT : LdapConnectionConfig.DEFAULT_LDAP_PORT;
        }

        setBinaryAttributes(this.configuration.getBinaryAttributes());

        LdapConnectionConfig config = new LdapConnectionConfig();
        config.setUseTls(tls);
        if (!tls) {
            config.setUseSsl(ssl);
        } else {
            config.setUseSsl(false);
        }

        config.setLdapHost(ldapHost);
        config.setLdapPort(port);
        config.setTimeout(getTimeout());

        config.setBinaryAttributeDetector(new BinaryAttributeDetector()
        {
            @Override
            public boolean isBinary(String attributeId)
            {
                return isBinaryAttribute(attributeId);
            }
        });

        try {
            if (tls || ssl) {
                // Dynamically set JSSE as a security provider
                Security.addProvider(this.configuration.getSecureProvider());

                KeyStore ourKeyStore = null;
                if (pathToKeys != null && pathToKeys.length() > 0) {
                    // Dynamically set the property that JSSE uses to identify
                    // the keystore that holds trusted root certificates

                    System.setProperty("javax.net.ssl.trustStore", pathToKeys);
                    // obviously unnecessary: sun default pwd = "changeit"
                    // System.setProperty("javax.net.ssl.trustStorePassword", sslpwd);

                    ourKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(pathToKeys)) {
                        ourKeyStore.load(fis, null);
                    }
                }

                // DS API: use trust manager instead of secure provider
                TrustManagerFactory tm = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm(), this.configuration.getSecureProvider());
                tm.init(ourKeyStore);
                config.setTrustManagers(tm.getTrustManagers());
            }

        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException e) {
            throw new XWikiLDAPException("LDAP bind failed while loading SSL keystore.", e);
        }

        this.connection = new LdapNetworkConnection(config);
        bind(loginDN, password);
        return true;
    }

    /**
     * Bind to LDAP server.
     * 
     * @param loginDN the user DN to connect to LDAP server.
     * @param password the password to connect to LDAP server.
     * @throws XWikiLDAPException error when trying to bind.
     */
    public void bind(String loginDN, String password) throws XWikiLDAPException
    {
        LOGGER.debug("Binding to LDAP server with credentials login=[{}]", loginDN);

        // debug log sha256 sum of passwd just when sending it to the server
        try {
            final byte[] pwAsBytes = password.getBytes("UTF8");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String result = Base64.encode(digest.digest(pwAsBytes));
            LOGGER.debug("Binding to LDAP server with credentials passwdHash=[{}]", result);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            LOGGER.debug("no sha-256 or UTF-8 found", e);
        }

        BindRequest bind = new BindRequestImpl();
        bind.setName(loginDN);
        bind.setCredentials(password);

        try {
            // authenticate to the server
            BindResponse bindResponse = this.connection.bind(bind);
            ResultCodeEnum.processResponse(bindResponse);
        } catch (LdapException e) {
            throw new XWikiLDAPException("LDAP bind failed with LdapException.", e);
        }
    }

    /**
     * Close LDAP connection.
     */
    public void close()
    {
        try {
            if (this.connection != null) {
                this.connection.close();
            }
        } catch (IOException e) {
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
            return this.connection.compare(userDN, passwordField, password);
        } catch (LdapException e) {
            ResultCodeEnum errorCode = ResultCodeEnum.getResultCode(e);
            if (errorCode != null) {
                LOGGER.debug("Unable to verify password [{}]: message [{}]", errorCode.getResultCode(),
                    errorCode.getMessage());
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
        try (PagedLdapSearchResults searchResults = searchPaginated(baseDN, ldapScope, filter, attr, false)) {
            if (!searchResults.hasMore()) {
                return null;
            }

            Entry nextEntry = searchResults.next();
            String foundDN = nextEntry.getDn().getName();

            searchAttributeList = new ArrayList<>();

            searchAttributeList.add(new XWikiLDAPSearchAttribute("dn", foundDN));

            Collection<Attribute> attributeSet = nextEntry.getAttributes();

            ldapToXWikiAttribute(searchAttributeList, attributeSet);
        } catch (LdapException e) {
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
     * @return a result stream. {@link EntryCursor#close()} should be called when it's not needed anymore.
     * @throws LdapException error when searching
     */
    public EntryCursor search(String baseDN, String filter, String[] attr, int ldapScope) throws LdapException
    {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("LDAP search: baseDN=[{}] query=[{}] attr=[{}] ldapScope=[{}]", baseDN, filter,
                attr != null ? Arrays.asList(attr) : null, ldapScope);
        }

        // XXX: is copy & paste from PagedLdapSearchResults#search
        SearchRequest searchRequest = new SearchRequestImpl();
        searchRequest.setBase(new Dn(baseDN));
        searchRequest.setFilter(filter);
        searchRequest.setScope(SearchScope.getSearchScope(ldapScope));
        searchRequest.addAttributes(attr);
        searchRequest.setDerefAliases(AliasDerefMode.DEREF_ALWAYS);
        searchRequest.setTypesOnly(false);
        // NOTE: this seems to have no effect at the moment
        // instead referrals in the search throw an exception
        searchRequest.followReferrals();
        searchRequest.setSizeLimit(getMaxResults());

        SearchCursor searchResponse = this.connection.search(searchRequest);

        // TODO: should we return the plain SearchResponse here instead?
        return new EntryCursorImpl(searchResponse);
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
     * @return a result stream. PagedLdapSearchResults#close should be called when it's not needed anymore.
     * @throws LdapException error when searching
     * @since 9.3
     */
    public PagedLdapSearchResults searchPaginated(String base, int scope, String filter, String[] attrs,
        boolean typesOnly) throws LdapException
    {
        int pageSize = this.configuration.getSearchPageSize();

        return new PagedLdapSearchResults(this, base, scope, filter, attrs, typesOnly, pageSize);
    }

    /**
     * Fill provided <code>searchAttributeList</code> with provided LDAP attributes.
     * 
     * @param searchAttributeList the XWiki attributes.
     * @param attributeSet the LDAP attributes.
     */
    protected void ldapToXWikiAttribute(List<XWikiLDAPSearchAttribute> searchAttributeList,
        Collection<Attribute> attributeSet)
    {
        for (Attribute attribute : attributeSet) {
            String attributeName = attribute.getId();

            if (!isBinaryAttribute(attributeName)) {
                LOGGER.debug("  - values for attribute [{}]", attributeName);

                for (Value value : attribute) {
                    String strValue = value.getString();

                    LOGGER.debug("    |- [{}]", strValue);

                    searchAttributeList.add(new XWikiLDAPSearchAttribute(attributeName, strValue));
                }

            } else {
                LOGGER.debug("  - attribute [{}] is binary", attributeName);

                for (Value value : attribute) {
                    byte[] byteValue = value.getBytes();

                    if (byteValue == null) {
                        LOGGER.warn("ignore value for [{}] as it turns out not to be binary (or empty)",
                            attributeName);
                    } else {
                        searchAttributeList.add(new XWikiLDAPSearchAttribute(attributeName, byteValue));
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
        return StringUtils.isBlank(value) ? value : new Value(value).getEscaped();
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
        for (int i = 0, n = value.length(); i < n; i++) {
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
