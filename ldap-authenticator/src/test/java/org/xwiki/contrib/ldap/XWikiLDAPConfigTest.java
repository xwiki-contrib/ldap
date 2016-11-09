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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.test.mockito.MockitoComponentManagerRule;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.web.Utils;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

/**
 * Test {@link XWikiLDAPConfig}.
 * 
 * @version $Id$
 */
public class XWikiLDAPConfigTest
{
    @Rule
    public MockitoComponentManagerRule mocker = new MockitoComponentManagerRule();

    private static final String XADMINGROUP_FULLNAME = "XWiki.XWikiAdminGroup";

    private static final String XADMINGROUP2_FULLNAME = "XWiki.XWikiAdminGroup2";

    private static final String LDAPTITIGRP_DN = "cn=HMS Titi,ou=crews,ou=groups,o=sevenSeas";

    private static final String LDAPTOTOGRP_DN = "cn=HMS Toto,ou=crews,ou=groups,o=sevenSeas";

    private static final String FILTER = "(&(objectCategory=person)(objectClass=contact)(|(sn=Smith)(sn=Johnson)))";

    private static final String LDAPTITIGRP2_DN = "cn=HMS Titi,ou=crews,ou=groups,o=sevenSeas2";

    private static final String LDAPTOTOGRP2_DN = "cn=HMS Toto,ou=crews,ou=groups,o=sevenSeas2";

    private ConfigurationSource cfgConfigurationSource;

    private ConfigurationSource wikiConfigurationSource;

    private XWikiLDAPConfig config;

    private void setCfgPreference(String cfgName, String cfgValue)
    {
        when(this.cfgConfigurationSource.getProperty(cfgName)).thenReturn(cfgValue);
    }

    private void setWikiPreference(String prefName, String prefValue)
    {
        when(this.wikiConfigurationSource.getProperty(prefName)).thenReturn(prefValue);
    }

    @Before
    public void setUp() throws Exception
    {
        this.cfgConfigurationSource = this.mocker.registerMockComponent(ConfigurationSource.class, "xwikicfg");
        this.wikiConfigurationSource = this.mocker.registerMockComponent(ConfigurationSource.class, "wiki");
        Utils.setComponentManager(mocker);
        this.config = new XWikiLDAPConfig(null);
    }

    @Test
    public void getLDAPParam()
    {
        // No param set and no default used
        assertNull(this.config.getLDAPParam("wikiKey", "cfgKey", (String) null));
        assertNull(this.config.getLDAPParam("wikiKey", "cfgKey", (String) null), (XWikiContext) null);

        // No param set and default used
        assertEquals("1", this.config.getLDAPParam("wikiKey", "cfgKey", "1"));
        assertEquals("1",
            this.config.getLDAPParam("wikiKey", "cfgKey", "1", (XWikiContext) null));

        // Param set in xwiki.cfg only
        setCfgPreference("cfgKey", "1");
        assertEquals("1", this.config.getLDAPParam("wikiKey", "cfgKey", (String) null));

        // Param set in xwiki.cfg and with default used
        assertEquals("1",
            this.config.getLDAPParam("wikiKey", "cfgKey", "0"));

        // Param override in XWikiPreferences
        setWikiPreference("wikiKey", "0");
        assertEquals("0",
            this.config.getLDAPParam("wikiKey", "cfgKey", (String) null));

        // Param override in XWikiPreferences and with default used
        assertEquals("0",
            this.config.getLDAPParam("wikiKey", "cfgKey", "1"));
    }

    @Test
    public void isLDAPEnabled()
    {
        // No param set
        assertEquals(false, this.config.isLDAPEnabled());
        assertEquals(false, this.config.isLDAPEnabled(null));

        // Param set in xwiki.cfg only
        setCfgPreference("xwiki.authentication.ldap", "1");
        assertEquals(true, this.config.isLDAPEnabled());
        assertEquals(true, this.config.isLDAPEnabled(null));

        // Param override in XWikiPreferences
        setWikiPreference("ldap", "0");
        assertEquals(false, this.config.isLDAPEnabled());
        assertEquals(false, this.config.isLDAPEnabled(null));
    }

    @Test
    public void getLDAPPort()
    {
        // No param set
        assertEquals(0, this.config.getLDAPPort());
        assertEquals(0, this.config.getLDAPPort(null));

        // Param set in xwiki.cfg only
        setCfgPreference("xwiki.authentication.ldap.port", "11111");
        assertEquals(11111, this.config.getLDAPPort());
        assertEquals(11111, this.config.getLDAPPort(null));

        // Param override in XWikiPreferences
        setWikiPreference("ldap_port", "10000");
        assertEquals(10000, this.config.getLDAPPort());
        assertEquals(10000, this.config.getLDAPPort(null));
    }

    @Test
    public void getGroupMappings()
    {
        // No param set
        assertTrue(this.config.getGroupMappings().isEmpty());
        assertTrue(this.config.getGroupMappings(null).isEmpty());

        // Param set in xwiki.cfg only
        setCfgPreference("xwiki.authentication.ldap.group_mapping",
            XADMINGROUP_FULLNAME + "=" + LDAPTOTOGRP2_DN + "|" +
            XADMINGROUP_FULLNAME + "=" + LDAPTITIGRP2_DN + "|" +
            XADMINGROUP_FULLNAME + "=" + FILTER.replace("|", "\\|") + "|" +
            XADMINGROUP2_FULLNAME + "=" + LDAPTOTOGRP2_DN + "|" +
            XADMINGROUP2_FULLNAME + "=" + LDAPTITIGRP2_DN + "|" +
            XADMINGROUP2_FULLNAME + "=" + FILTER.replace("|", "\\|"));

        Map<String, Set<String>> expectedCfgLDAPGroups = new HashMap<>();
        Set<String> cfgLDAPGroups = new HashSet<String>();
        cfgLDAPGroups.add(LDAPTOTOGRP2_DN);
        cfgLDAPGroups.add(LDAPTITIGRP2_DN);
        cfgLDAPGroups.add(FILTER);
        expectedCfgLDAPGroups.put(XADMINGROUP_FULLNAME, cfgLDAPGroups);
        expectedCfgLDAPGroups.put(XADMINGROUP2_FULLNAME, cfgLDAPGroups);

        assertEquals(expectedCfgLDAPGroups, this.config.getGroupMappings());
        assertEquals(expectedCfgLDAPGroups, this.config.getGroupMappings(null));

        // Param override in XWikiPreferences
        setWikiPreference("ldap_group_mapping",
            XADMINGROUP_FULLNAME + "=" + LDAPTOTOGRP_DN + "|" +
            XADMINGROUP_FULLNAME + "=" + LDAPTITIGRP_DN + "|" +
            XADMINGROUP_FULLNAME + "=" + FILTER.replace("|", "\\|") + "|" +
            XADMINGROUP2_FULLNAME + "=" + LDAPTOTOGRP_DN + "|" +
            XADMINGROUP2_FULLNAME + "=" + LDAPTITIGRP_DN + "|" +
            XADMINGROUP2_FULLNAME + "=" + FILTER.replace("|", "\\|"));

        Map<String, Set<String>> expectedWikiLDAPGroups = new HashMap<>();
        Set<String> wikiLDAPGroups = new HashSet<>();
        wikiLDAPGroups.add(LDAPTOTOGRP_DN);
        wikiLDAPGroups.add(LDAPTITIGRP_DN);
        wikiLDAPGroups.add(FILTER);
        expectedWikiLDAPGroups.put(XADMINGROUP_FULLNAME, wikiLDAPGroups);
        expectedWikiLDAPGroups.put(XADMINGROUP2_FULLNAME, wikiLDAPGroups);

        assertEquals(expectedWikiLDAPGroups, this.config.getGroupMappings());
        assertEquals(expectedWikiLDAPGroups, this.config.getGroupMappings(null));
    }

    @Test
    public void getUserMappings()
    {
        // No param set
        List<String> attrList = new ArrayList<>();
        assertTrue(this.config.getUserMappings(attrList).isEmpty());
        assertTrue(this.config.getUserMappings(attrList, null).isEmpty());

        // Param set in xwiki.cfg only
        setCfgPreference("xwiki.authentication.ldap.fields_mapping", "name=uid2,last_name=sn2");

        List<String> cfgAttrList = new ArrayList<>();
        Map<String, String> cfgMappings = this.config.getUserMappings(cfgAttrList);

        Map<String, String> expectedCfgUserMappings = new HashMap<>();
        expectedCfgUserMappings.put("uid2", "name");
        expectedCfgUserMappings.put("sn2", "last_name");

        assertEquals("uid2", cfgAttrList.get(0));
        assertEquals("sn2", cfgAttrList.get(1));
        assertEquals(expectedCfgUserMappings, cfgMappings);

        // Param override in XWikiPreferences
        setWikiPreference("ldap_fields_mapping", "name=uid,last_name=sn");

        List<String> wikiAttrList = new ArrayList<>();
        Map<String, String> wikiMappings = this.config.getUserMappings(wikiAttrList);

        Map<String, String> expectedWikiUserMappings = new HashMap<>();
        expectedWikiUserMappings.put("uid", "name");
        expectedWikiUserMappings.put("sn", "last_name");
        assertEquals(expectedWikiUserMappings, wikiMappings);
    }

    @Test
    public void getCacheExpiration()
    {
        // No param set
        assertEquals(21600, this.config.getCacheExpiration());

        // Param set in xwiki.cfg only
        setCfgPreference("xwiki.authentication.ldap.groupcache_expiration", "11111");
        assertEquals(11111, this.config.getCacheExpiration());
        assertEquals(11111, this.config.getCacheExpiration(null));

        // Param override in XWikiPreferences
        setWikiPreference("ldap_groupcache_expiration", "10000");
        assertEquals(10000, this.config.getCacheExpiration());
        assertEquals(10000, this.config.getCacheExpiration(null));
    }

    @Test
    public void getGroupClasses()
    {
        // No param set
        Collection<String> expectedDefaultGroupClasses = new HashSet<>();
        expectedDefaultGroupClasses.add("group".toLowerCase());
        expectedDefaultGroupClasses.add("groupOfNames".toLowerCase());
        expectedDefaultGroupClasses.add("groupOfUniqueNames".toLowerCase());
        expectedDefaultGroupClasses.add("dynamicGroup".toLowerCase());
        expectedDefaultGroupClasses.add("dynamicGroupAux".toLowerCase());
        expectedDefaultGroupClasses.add("groupWiseDistributionList".toLowerCase());
        expectedDefaultGroupClasses.add("posixGroup".toLowerCase());
        expectedDefaultGroupClasses.add("apple-group".toLowerCase());
        assertEquals(expectedDefaultGroupClasses, this.config.getGroupClasses());
        assertEquals(expectedDefaultGroupClasses, this.config.getGroupClasses(null));

        // Param set in xwiki.cfg only
        setCfgPreference("xwiki.authentication.ldap.group_classes", "groupclass12");

        Collection<String> expectedCfgGroupClasses = new HashSet<>();
        expectedCfgGroupClasses.add("groupclass12");
        assertEquals(expectedCfgGroupClasses, this.config.getGroupClasses());
        assertEquals(expectedCfgGroupClasses, this.config.getGroupClasses(null));

        // Param override in XWikiPreferences
        setWikiPreference("ldap_group_classes", "groupclass1,groupclass2");

        Collection<String> expectedWikiGroupClasses = new HashSet<>();
        expectedWikiGroupClasses.add("groupclass1");
        expectedWikiGroupClasses.add("groupclass2");
        assertEquals(expectedWikiGroupClasses, this.config.getGroupClasses());
        assertEquals(expectedWikiGroupClasses, this.config.getGroupClasses(null));
    }

    @Test
    public void getGroupMemberFields()
    {
        // No param set
        Collection<String> expectedDefaultGroupMemberFields = new HashSet<>();
        expectedDefaultGroupMemberFields.add("member".toLowerCase());
        expectedDefaultGroupMemberFields.add("uniqueMember".toLowerCase());
        expectedDefaultGroupMemberFields.add("memberUid".toLowerCase());
        assertEquals(expectedDefaultGroupMemberFields, this.config.getGroupMemberFields());
        assertEquals(expectedDefaultGroupMemberFields, this.config.getGroupMemberFields(null));

        // Param set in xwiki.cfg only
        setCfgPreference("xwiki.authentication.ldap.group_memberfields", "groupmemberfield12");

        Collection<String> expectedCfgGroupMemberFields = new HashSet<>();
        expectedCfgGroupMemberFields.add("groupmemberfield12");
        assertEquals(expectedCfgGroupMemberFields, this.config.getGroupMemberFields());
        assertEquals(expectedCfgGroupMemberFields, this.config.getGroupMemberFields(null));

        // Param override in XWikiPreferences
        setWikiPreference("ldap_group_memberfields", "groupmemberfield1,groupmemberfield2");

        Collection<String> expectedWikiGroupMemberFields = new HashSet<>();
        expectedWikiGroupMemberFields.add("groupmemberfield1");
        expectedWikiGroupMemberFields.add("groupmemberfield2");
        assertEquals(expectedWikiGroupMemberFields, this.config.getGroupMemberFields());
        assertEquals(expectedWikiGroupMemberFields, this.config.getGroupMemberFields(null));
    }

    @Test
    public void parseRemoteUserWithNoConfiguration() throws Exception
    {
        XWikiLDAPConfig config = new XWikiLDAPConfig("remoteuser");
        assertEquals("remoteuser", config.getMemoryConfiguration().get("auth.input"));
        assertEquals("remoteuser", config.getMemoryConfiguration().get("uid"));

        XWikiLDAPConfig deprecatedConfig = new XWikiLDAPConfig("remoteuser", (XWikiContext) null);
        assertEquals("remoteuser", deprecatedConfig.getMemoryConfiguration().get("auth.input"));
        assertEquals("remoteuser", deprecatedConfig.getMemoryConfiguration().get("uid"));
    }

    @Test
    public void parseRemoteUserWithSimplePattern() throws Exception
    {
        setWikiPreference("ldap_remoteUserParser", "remote");

        XWikiLDAPConfig config = new XWikiLDAPConfig("remoteuser");

        assertEquals("remoteuser", config.getMemoryConfiguration().get("auth.input"));
        assertEquals("remote", config.getMemoryConfiguration().get("uid"));
    }

    @Test
    public void parseRemoteUserWithGroupsPattern() throws Exception
    {
        setWikiPreference("ldap_remoteUserParser", "(remote)(user)");
        setWikiPreference("ldap_remoteUserMapping.1", "uid");
        setWikiPreference("ldap_remoteUserMapping.2",
            "ldap_server,ldap_port,ldap_base_DN,ldap_bind_DN,ldap_bind_pass,ldap_group_mapping");

        XWikiLDAPConfig config = new XWikiLDAPConfig("remoteuser");

        assertEquals("remoteuser", config.getMemoryConfiguration().get("auth.input"));
        assertEquals("remote", config.getMemoryConfiguration().get("uid"));
        assertEquals("user", config.getMemoryConfiguration().get("ldap_server"));
        assertEquals("user", config.getMemoryConfiguration().get("ldap_base_DN"));
        assertEquals("user", config.getMemoryConfiguration().get("ldap_group_mapping"));
    }

    @Test
    public void parseRemoteUserWithGroupsPatternandConversions() throws Exception
    {
        setWikiPreference("ldap_remoteUserParser", "(.+)@(.+)");
        setWikiPreference("ldap_remoteUserMapping.1", "uid");
        setWikiPreference("ldap_remoteUserMapping.2",
            "ldap_server,ldap_port,ldap_base_DN,ldap_bind_DN,ldap_bind_pass,ldap_group_mapping");
        setWikiPreference("ldap_remoteUserMapping.ldap_server", "doMain=my.domain.com|domain2=my.domain2.com");
        setWikiPreference("ldap_remoteUserMapping.ldap_port", "doMain=388|domain2=387");
        setWikiPreference("ldap_remoteUserMapping.ldap_base_DN",
            "dOmain=dc=my,dc=domain,dc=com|domain2=dc=my,dc=domain2,dc=com");
        setWikiPreference("ldap_remoteUserMapping.ldap_bind_DN",
            "doMain=cn=bind,dc=my,dc=domain,dc=com|domain2=cn=bind,dc=my,dc=domain2,dc=com");
        setWikiPreference("ldap_remoteUserMapping.ldap_bind_pass", "doMain=password|domain2=password2");
        setWikiPreference("ldap_remoteUserMapping.ldap_group_mapping",
            "doMain=xgroup11=lgroup11\\|xgroup12=lgroup12|domain2=xgroup21=lgroup21\\|xgroup22=lgroup22");

        XWikiLDAPConfig config = new XWikiLDAPConfig("user@domain");

        assertEquals("user", config.getMemoryConfiguration().get("uid"));
        assertEquals("my.domain.com", config.getMemoryConfiguration().get("ldap_server"));
        assertEquals("388", config.getMemoryConfiguration().get("ldap_port"));
        assertEquals("dc=my,dc=domain,dc=com", config.getMemoryConfiguration().get("ldap_base_DN"));
        assertEquals("cn=bind,dc=my,dc=domain,dc=com", config.getMemoryConfiguration().get("ldap_bind_DN"));
        assertEquals("password", config.getMemoryConfiguration().get("ldap_bind_pass"));
        assertEquals("xgroup11=lgroup11|xgroup12=lgroup12",
            config.getMemoryConfiguration().get("ldap_group_mapping"));

        config = new XWikiLDAPConfig("user@domain2");

        assertEquals("user", config.getMemoryConfiguration().get("uid"));
        assertEquals("my.domain2.com", config.getMemoryConfiguration().get("ldap_server"));
        assertEquals("387", config.getMemoryConfiguration().get("ldap_port"));
        assertEquals("dc=my,dc=domain2,dc=com", config.getMemoryConfiguration().get("ldap_base_DN"));
        assertEquals("cn=bind,dc=my,dc=domain2,dc=com", config.getMemoryConfiguration().get("ldap_bind_DN"));
        assertEquals("password2", config.getMemoryConfiguration().get("ldap_bind_pass"));
        assertEquals("xgroup21=lgroup21|xgroup22=lgroup22",
            config.getMemoryConfiguration().get("ldap_group_mapping"));
    }
}
