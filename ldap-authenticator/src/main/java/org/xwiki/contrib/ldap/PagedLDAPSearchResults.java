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

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;

/**
 * Paginated version of {@link LDAPSearchResults}.
 * 
 * @version $Id$
 * @since 9.3
 */
public class PagedLDAPSearchResults implements AutoCloseable
{
    private static final Logger LOGGER = LoggerFactory.getLogger(PagedLDAPSearchResults.class);

    private final XWikiLDAPConnection connection;

    private final String base;

    private final int scope;

    private final String filter;

    private final String[] attrs;

    private final boolean typesOnly;

    private final int pageSize;

    private LDAPSearchResults currentSearchResults;

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
     * @throws LDAPException A general exception which includes an error message and an LDAP error code.
     */
    public PagedLDAPSearchResults(XWikiLDAPConnection connection, String base, int scope, String filter, String[] attrs,
        boolean typesOnly, int pageSize) throws LDAPException
    {
        this.connection = connection;

        this.base = base;
        this.scope = scope;
        this.filter = filter;
        this.attrs = attrs;
        this.typesOnly = typesOnly;

        this.pageSize = pageSize;

        // First search page
        search(null);
    }

    private void search(byte[] cookie) throws LDAPException
    {
        LDAPPagedResultsControl control = new LDAPPagedResultsControl(this.pageSize, cookie, false);
        LDAPSearchConstraints constraints = new LDAPSearchConstraints();
        constraints.setControls(control);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                "LDAP pagined search: base=[{}] query=[{}] attrs=[{}] scope=[{}] typesOnly=[{}]"
                    + " pageSize=[{}], cookie=[{}]",
                this.base, this.filter, this.attrs != null ? Arrays.asList(this.attrs) : null, this.scope,
                this.typesOnly, this.pageSize, cookie != null ? Arrays.asList(cookie) : null);
        }

        this.currentSearchResults = this.connection.getConnection().search(this.base, this.scope, this.filter,
            this.attrs, this.typesOnly, constraints);
    }

    private LDAPSearchResults getCurrentLDAPSearchResults() throws LDAPException
    {
        if (!this.lastResult && !this.currentSearchResults.hasMore()) {
            // Get next page (if any)
            LDAPControl[] controls = this.currentSearchResults.getResponseControls();
            if (controls != null) {
                for (LDAPControl resposeControl : controls) {
                    if (resposeControl instanceof LDAPPagedResultsResponse) {
                        LDAPPagedResultsResponse pagedResponse = (LDAPPagedResultsResponse) resposeControl;

                        // Get next page
                        nextLDAPSearchResults(pagedResponse.getCookie());

                        return this.currentSearchResults;
                    }
                }
            }

            // Mark that we reached the last page
            this.lastResult = true;
        }

        return this.currentSearchResults;
    }

    private void nextLDAPSearchResults(byte[] cookie) throws LDAPException
    {
        if (cookie != null) {
            search(cookie);
        } else {
            // Mark that we reached the last page
            this.lastResult = true;
        }
    }

    /**
     * Reports if there are more search results.
     *
     * @return true if there are more search results.
     */
    public boolean hasMore()
    {
        LDAPSearchResults results;
        try {
            results = getCurrentLDAPSearchResults();
        } catch (LDAPException e) {
            // TODO: log something

            return false;
        }

        return results.hasMore();
    }

    /**
     * Returns the next result as an LDAPEntry.
     * <p>
     * If automatic referral following is disabled or if a referral was not followed, next() will throw an
     * LDAPReferralException when the referral is received.
     * </p>
     *
     * @return The next search result as an LDAPEntry.
     * @exception LDAPException A general exception which includes an error message and an LDAP error code.
     * @exception LDAPReferralException A referral was received and not followed.
     */
    public LDAPEntry next() throws LDAPException
    {
        return getCurrentLDAPSearchResults().next();
    }

    @Override
    public void close() throws LDAPException
    {
        if (this.currentSearchResults != null) {
            this.connection.getConnection().abandon(this.currentSearchResults);
        }
    }
}
