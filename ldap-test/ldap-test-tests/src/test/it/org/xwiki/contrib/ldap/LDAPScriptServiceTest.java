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

import static org.junit.Assert.*;

import org.junit.Test;
import org.xwiki.contrib.ldap.framework.AbstractLDAPTestCase;
import org.xwiki.contrib.ldap.framework.LDAPTestSetup;

/**
 * Test {@link LDAPScriptService}.
 * 
 * @version $Id$
 */
public class LDAPScriptServiceTest extends AbstractLDAPTestCase
{
    /**
     * Test open and close of the LDAP connection.
     * 
     * @throws XWikiLDAPException
     */
    @Test
    public void testCheckConnection() throws XWikiLDAPException
    {
        int port = LDAPTestSetup.getLDAPPort();

        XWikiLDAPConnection connection = new XWikiLDAPConnection(new XWikiLDAPConfig(null, null));

        assertEquals(true, connection.open("localhost", port, LDAPTestSetup.HORATIOHORNBLOWER_DN,
            LDAPTestSetup.HORATIOHORNBLOWER_PWD, null, false, this.mocker.getXWikiContext()));

        connection.close();
    }
}
