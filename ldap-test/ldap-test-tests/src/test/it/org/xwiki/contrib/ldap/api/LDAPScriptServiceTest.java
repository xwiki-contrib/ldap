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
package org.xwiki.contrib.ldap.api;

import static org.junit.Assert.*;

import org.junit.Rule;
import org.junit.Test;
import org.xwiki.contrib.ldap.framework.AbstractLDAPTestCase;
import org.xwiki.contrib.ldap.framework.LDAPTestSetup;
import org.xwiki.contrib.ldap.script.LDAPScriptService;
import org.xwiki.script.service.ScriptService;
import org.xwiki.test.mockito.MockitoComponentMockingRule;

import com.xpn.xwiki.XWikiContext;

/**
 * Test {@link LDAPScriptService}.
 * 
 * @version $Id$
 */
public class LDAPScriptServiceTest extends AbstractLDAPTestCase
{
    @Rule
    public MockitoComponentMockingRule<ScriptService> mocker = new MockitoComponentMockingRule<ScriptService>(
        LDAPScriptService.class);

    @Test
    public void testCheckConnection() throws Exception
    {
        LDAPScriptService ldapSS = (LDAPScriptService) mocker.getComponentUnderTest();
        
        int port = LDAPTestSetup.getLDAPPort();

        assertEquals(true, ldapSS.checkConnection("localhost", port, LDAPTestSetup.HORATIOHORNBLOWER_DN,
            LDAPTestSetup.HORATIOHORNBLOWER_PWD, null, false, new XWikiContext()));
    }
}