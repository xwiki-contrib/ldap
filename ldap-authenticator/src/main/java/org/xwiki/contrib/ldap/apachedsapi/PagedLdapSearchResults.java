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
import java.util.Arrays;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.PagedResultsImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Paginated version of {@link LDAPSearchResults}.
 * 
 * @version $Id$
 * @since 9.3
 */
public class PagedLdapSearchResults implements AutoCloseable
{
    private static final Logger LOGGER = LoggerFactory.getLogger(PagedLdapSearchResults.class);

    private final XWikiLdapConnection connection;

    private final String base;

    private final SearchScope scope;

    private final String filter;

    private final String[] attrs;

    private final boolean typesOnly;

    private final int pageSize;

    private SearchCursor currentSearchResults;

    private boolean lastResult;

    /**
     * @param connection the connection
     * @param base The base distinguished name to search from.
     * @param scope The scope of the entries to search. The following are the valid options:
     *            <ul>
     *            <li>SCOPE_BASE - searches only the base DN
     *            <li>SCOPE_ONE - searches only entries under the base DN
     *            <li>SCOPE_SUB - searches the base DN and all entries within its subtree
     *            </ul>
     * @param filter The search filter specifying the search criteria.
     * @param attrs The names of attributes to retrieve.
     * @param typesOnly If true, returns the names but not the values of the attributes found. If false, returns the
     *            names and values for attributes found.
     * @param pageSize the maximum number of results to get in one page
     * @throws LdapException A general exception which includes an error message and an LDAP error code.
     */
    public PagedLdapSearchResults(XWikiLdapConnection connection, String base, int scope, String filter, String[] attrs,
        boolean typesOnly, int pageSize) throws LdapException
    {
        this.connection = connection;

        this.base = base;
        this.scope = SearchScope.getSearchScope(scope);
        // we must always pass in a search filter to the search api
        this.filter = (filter == null) ? "(objectClass=*)" : filter;
        this.attrs = attrs;
        this.typesOnly = typesOnly;

        this.pageSize = pageSize;

        // First search page
        search(null);
    }

    private void search(byte[] cookie) throws LdapException
    {
        PagedResults pageControl = new PagedResultsImpl();
        pageControl.setSize(pageSize);
        pageControl.setCookie(cookie);

        // XXX: has copy & paste in XWikiLdapConnection#search
        SearchRequest searchRequest = new SearchRequestImpl();
        searchRequest.setBase(new Dn(this.base));
        searchRequest.setFilter(this.filter);
        if (this.attrs != null) {
            searchRequest.addAttributes(attrs);
        }
        searchRequest.setScope(scope);
        searchRequest.setDerefAliases(AliasDerefMode.DEREF_ALWAYS);
        searchRequest.setTypesOnly(typesOnly);
        searchRequest.setSizeLimit(this.connection.getMaxResults());
        searchRequest.addControl(pageControl);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                "LDAP paginated search: base=[{}] query=[{}] attrs=[{}] scope=[{}] typesOnly=[{}]"
                    + " pageSize=[{}], cookie=[{}]",
                this.base, this.filter, this.attrs != null ? Arrays.asList(this.attrs) : null, this.scope,
                this.typesOnly, this.pageSize, cookieToString(cookie));
        }

        this.currentSearchResults = this.connection.getConnection().search(searchRequest);
    }

    private SearchCursor getCurrentLDAPSearchResults() throws LdapException
    {
        // note: "SearchCursor.isLast()" is not implemented, ".isDone()" works
        if (!this.lastResult && this.currentSearchResults.isDone()) {
            // Get next page (if any)

            byte[] nextCookie = null;
            SearchResultDone doneResult = this.currentSearchResults.getSearchResultDone();
            Control paged = (doneResult == null) ? null : doneResult.getControl(PagedResults.OID);
            if (paged instanceof PagedResults) {
                nextCookie = ((PagedResults) paged).getCookie();
            }

            nextLDAPSearchResults(nextCookie);
        }

        return this.currentSearchResults;
    }

    private void nextLDAPSearchResults(byte[] cookie) throws LdapException
    {
        if (!(cookie == null || cookie.length == 0)) {
            search(cookie);
        } else {
            // Mark that we reached the last page
            this.lastResult = true;
        }
    }

    /**
     * Reports if there are more search results.
     * Implementation note: this actually advances the cursor to the next result, and not the call to {@link #next()}.
     * @return true if there are more search results.
     */
    public boolean hasMore()
    {
        SearchCursor results;
        try {
            results = getCurrentLDAPSearchResults();
            if (this.lastResult) {
                return false;
            }
            // skip over all cursor results that are not entries
            while (results.next()) {
                if (results.isEntry()) {
                    return true;
                }
                // TODO: here we should throw an exception, as we likely got a referral, right?
            }

        } catch (LdapException | CursorException e) {
            LOGGER.warn("could not get current search results", e);
            return false;
        }

        // if we end up here we got a page full of non-entry results
        // we just try again with the next page
        return hasMore();
    }

    /**
     * Returns the next result as an LDAP Entry.
     * <p>
     * If automatic referral following is disabled or if a referral was not followed, next() will throw an
     * LDAPReferralException when the referral is received.
     * </p>
     *
     * @return The next search result as an LDAP Entry.
     * @exception LdapException A general exception which includes an error message and an LDAP error code.
     */
    public Entry next() throws LdapException
    {
        return this.currentSearchResults.getEntry();
    }

    /**
     * the connection used by this result
     * @return a {@link XWikiLdapConnection}
     */
    public XWikiLdapConnection getConnection()
    {
        return connection;
    }
    
    @Override
    public void close() throws LdapException
    {
        if (this.currentSearchResults != null) {
            try {
                this.currentSearchResults.close();
            } catch (IOException e) {
                LOGGER.debug("Exception when closing search", e);
            }
        }
    }

    /**
     * Helper for debugging output.
     * @param cookie a byte array
     * @return the hex representation of the bytes as a string
     */
    private String cookieToString(byte[] cookie)
    {
        if (cookie == null) {
            return "<null>";
        }
        StringBuilder byteStr = new StringBuilder();
        byteStr.append('<');
        byteStr.append(Hex.encodeHex(cookie));
        byteStr.append('>');
        return byteStr.toString();
    }
}
