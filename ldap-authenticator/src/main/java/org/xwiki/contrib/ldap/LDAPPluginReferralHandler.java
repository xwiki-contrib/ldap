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

import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPAuthHandler;
import com.novell.ldap.LDAPAuthProvider;
import com.xpn.xwiki.XWikiContext;

/**
 * Connected to referrals.
 * 
 * @version $Id$
 * @since 8.3
 */
public class LDAPPluginReferralHandler implements LDAPAuthHandler
{
    /**
     * Logging tool.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LDAPPluginReferralHandler.class);

    /**
     * The DN to use when binding.
     */
    private String bindDN;

    /**
     * The password to use when binding.
     */
    private String bindPassword;

    /**
     * @param bindDN the DN to use when binding.
     * @param bindPassword the password to use when binding.
     * @param context the XWiki context.
     */
    public LDAPPluginReferralHandler(String bindDN, String bindPassword, XWikiContext context)
    {
        this.bindDN = bindDN;
        this.bindPassword = bindPassword;
    }

    @Override
    public LDAPAuthProvider getAuthProvider(String host, int port)
    {
        try {
            LOGGER.debug("Looking for auth for referral to {}:{}", host, port);

            return new LDAPAuthProvider(this.bindDN, this.bindPassword.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            LOGGER.error("Failed to create LDAPAuthProvider for referral {}:{}", host, port);

            return null;
        }
    }
}
