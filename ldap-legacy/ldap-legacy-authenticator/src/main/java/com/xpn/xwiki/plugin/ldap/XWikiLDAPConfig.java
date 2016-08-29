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

import com.xpn.xwiki.XWikiContext;

/**
 * Access to LDAP configurations.
 * 
 * @version $Id$
 * @deprecated since 8.3, use {@link org.xwiki.contrib.ldap.XWikiLDAPConfig} instead
 */
@Deprecated
public final class XWikiLDAPConfig extends org.xwiki.contrib.ldap.XWikiLDAPConfig
{
    /**
     * Unique instance of {@link XWikiLDAPConfig}.
     */
    private static XWikiLDAPConfig instance;

    /**
     * Protected constructor. Use {@link #getInstance()}.
     */
    private XWikiLDAPConfig()
    {
        super(null, null);
    }

    /**
     * @return unique instance of {@link XWikiLDAPConfig}.
     */
    public static XWikiLDAPConfig getInstance()
    {
        if (instance == null) {
            instance = new XWikiLDAPConfig();
        }

        return instance;
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
            return super.getSecureProvider(context);
        } catch (org.xwiki.contrib.ldap.XWikiLDAPException e) {
            throw new XWikiLDAPException(e.getMessage(), e);
        }
    }
}
