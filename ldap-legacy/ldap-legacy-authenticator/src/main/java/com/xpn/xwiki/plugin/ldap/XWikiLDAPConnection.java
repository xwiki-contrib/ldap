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

import java.util.ArrayList;
import java.util.List;

/**
 * LDAP communication tool.
 * 
 * @version $Id$
 * @since 1.3 M2
 * @deprecated since 8.3, use {@link org.xwiki.contrib.ldap.XWikiLDAPConnection} instead
 */
@Deprecated
public class XWikiLDAPConnection extends org.xwiki.contrib.ldap.XWikiLDAPConnection
{
    /**
     * Default constructor.
     */
    public XWikiLDAPConnection()
    {
    }

    /**
     * @param connection the connection to copy
     */
    public XWikiLDAPConnection(org.xwiki.contrib.ldap.XWikiLDAPConnection connection)
    {
        super(connection);
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
    public List<org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute> searchLDAP(String baseDN, String filter, String[] attr,
        int ldapScope)
    {
        List<org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute> attributes =
            super.searchLDAP(baseDN, filter, attr, ldapScope);

        if (attributes != null) {
            List<org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute> deprecatedAttributes =
                new ArrayList<>(attributes.size());
            for (org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute attribute : attributes) {
                deprecatedAttributes.add(new XWikiLDAPSearchAttribute(attribute));
            }

            return deprecatedAttributes;
        }

        return null;
    }
}
