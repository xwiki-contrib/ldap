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
 * @deprecated since 8.3, use {@link org.xwiki.contrib.ldap.XWikiLDAPUtils} instead
 */
@Deprecated
public class XWikiLDAPUtils extends org.xwiki.contrib.ldap.XWikiLDAPUtils
{
    /**
     * Create an instance of {@link XWikiLDAPUtils}.
     * 
     * @param connection the XWiki LDAP connection tool.
     */
    public XWikiLDAPUtils(XWikiLDAPConnection connection)
    {
        super(connection);
    }

    @Override
    public XWikiLDAPConnection getConnection()
    {
        return new XWikiLDAPConnection(super.getConnection());
    }

    /**
     * @since 1.6M2
     */
    @Override
    public List<org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute> searchUserAttributesByUid(String uid,
        String[] attributeNameTable)
    {
        List<org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute> attributes =
            super.searchUserAttributesByUid(uid, attributeNameTable);

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
