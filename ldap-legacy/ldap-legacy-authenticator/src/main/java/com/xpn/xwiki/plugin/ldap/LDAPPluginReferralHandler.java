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

import com.xpn.xwiki.XWikiContext;

/**
 * Connected to referrals.
 * 
 * @version $Id$
 * @deprecated since 8.3, use {@link org.xwiki.contrib.ldap.LDAPPluginReferralHandler} instead
 */
@Deprecated
public class LDAPPluginReferralHandler extends org.xwiki.contrib.ldap.LDAPPluginReferralHandler
{
    /**
     * @param bindDN the DN to use when binding.
     * @param bindPassword the password to use when binding.
     * @param context the XWiki context.
     */
    public LDAPPluginReferralHandler(String bindDN, String bindPassword, XWikiContext context)
    {
        super(bindDN, bindPassword, context);
    }
}
