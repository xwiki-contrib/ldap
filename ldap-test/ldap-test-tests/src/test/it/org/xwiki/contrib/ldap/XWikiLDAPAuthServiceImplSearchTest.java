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

import org.junit.Before;
import org.junit.Test;
import org.xwiki.contrib.ldap.framework.LDAPTestSetup;
import org.xwiki.test.annotation.AllComponents;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Unit tests using embedded LDAP server (Apache DS). Theses test can be launched directly from JUnit plugin of EDI.
 * 
 * @version $Id$
 */
// TODO: get rid of @AllComponents
@AllComponents
public class XWikiLDAPAuthServiceImplSearchTest extends XWikiLDAPAuthServiceImplTest
{
    @Before
    @Override
    public void before() throws Exception
    {
        super.before();

        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.bind_DN",
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.bind_pass",
            LDAPTestSetup.HORATIOHORNBLOWER_PWD);
    }

    private XWikiDocument assertAuthenticateSSO(String remoteuser, String storedDn) throws XWikiException
    {
        return assertAuthenticateSSO(remoteuser, "xwiki:" + userProfileName(remoteuser), storedDn);
    }

    private XWikiDocument assertAuthenticateSSO(String remoteuser, String xwikiUserName, String storedDn)
        throws XWikiException
    {
        return assertAuthenticateSSO(remoteuser, xwikiUserName, storedDn, remoteuser);
    }

    private XWikiDocument assertAuthenticateSSO(String remoteuser, String xwikiUserName, String storedDn,
        String storedUid) throws XWikiException
    {
        return assertAuthenticate(remoteuser, null, xwikiUserName, storedDn, storedUid, true);
    }

    /**
     * Validate SSO LDAP authentication.
     */
    @Test
    public void testAuthenticateSSO() throws XWikiException
    {
        assertAuthenticateSSO(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }
}
