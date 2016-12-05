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
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.context.Execution;
import org.xwiki.context.ExecutionContext;
import org.xwiki.contrib.ldap.framework.AbstractLDAPTestCase;
import org.xwiki.contrib.ldap.framework.LDAPTestSetup;
import org.xwiki.contrib.ldap.script.LDAPScriptService;
import org.xwiki.test.mockito.MockitoComponentMockingRule;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.web.Utils;

/**
 * Test {@link LDAPScriptService}.
 * 
 * @version $Id$
 */
public class LDAPScriptServiceTest extends AbstractLDAPTestCase
{
    @Rule
    public MockitoComponentMockingRule<LDAPScriptService> mocker =
        new MockitoComponentMockingRule<>(LDAPScriptService.class);

    @Before
    public void setUp() throws Exception
    {
        // Setup mock  configuration sources since they're used by XWikiLDAPConfig.
        Utils.setComponentManager(mocker);
        mocker.registerMockComponent(ConfigurationSource.class, "wiki");
        mocker.registerMockComponent(ConfigurationSource.class, "xwikicfg");

        Execution execution = this.mocker.getInstance(Execution.class);
        when(execution.getContext()).thenReturn(mock(ExecutionContext.class));
    }

    @Test
    public void connectionSuccess() throws Exception
    {
        int port = LDAPTestSetup.getLDAPPort();

        assertEquals(true, mocker.getComponentUnderTest().checkConnection("localhost", port,
            LDAPTestSetup.HORATIOHORNBLOWER_DN, LDAPTestSetup.HORATIOHORNBLOWER_PWD, null, false,
            new XWikiContext()));
    }
    
    @Test
    public void connectionFailure() throws Exception
    {
        assertEquals(false, mocker.getComponentUnderTest().checkConnection("localhost", 444,
            LDAPTestSetup.HORATIOHORNBLOWER_DN, LDAPTestSetup.HORATIOHORNBLOWER_PWD, null, false,
            new XWikiContext()));
    }
}