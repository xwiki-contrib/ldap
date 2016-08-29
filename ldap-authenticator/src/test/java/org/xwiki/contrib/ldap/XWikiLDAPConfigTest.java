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

import org.junit.Assert;
import org.junit.Test;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiConfig;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.test.AbstractBridgedComponentTestCase;
import com.xpn.xwiki.web.XWikiEngineContext;

/**
 * Test {@link XWikiLDAPConfig}.
 * 
 * @version $Id$
 */
public class XWikiLDAPConfigTest extends AbstractBridgedComponentTestCase
{
    private XWikiContext prefContext;

    private XWikiContext cfgContext;

    private static final String XADMINGROUP_FULLNAME = "XWiki.XWikiAdminGroup";

    private static final String XADMINGROUP2_FULLNAME = "XWiki.XWikiAdminGroup2";

    private static final String LDAPTITIGRP_DN = "cn=HMS Titi,ou=crews,ou=groups,o=sevenSeas";

    private static final String LDAPTOTOGRP_DN = "cn=HMS Toto,ou=crews,ou=groups,o=sevenSeas";

    private static final String FILTER = "(&(objectCategory=person)(objectClass=contact)(|(sn=Smith)(sn=Johnson)))";

    private static final String LDAPTITIGRP2_DN = "cn=HMS Titi,ou=crews,ou=groups,o=sevenSeas2";

    private static final String LDAPTOTOGRP2_DN = "cn=HMS Toto,ou=crews,ou=groups,o=sevenSeas2";

    private Map<String, String> PREFERENCES = new HashMap<String, String>();

    private XWikiConfig CONFIG = new XWikiConfig();

    private Map<String, String> RESULT_CFG_USERMAPPING = new HashMap<String, String>();

    private Map<String, String> RESULT_PREF_USERMAPPING = new HashMap<String, String>();

    private Map<String, Set<String>> RESULT_CFG_GROUPMAPPING = new HashMap<String, Set<String>>();

    private Map<String, Set<String>> RESULT_PREF_GROUPMAPPING = new HashMap<String, Set<String>>();

    private Collection<String> RESULT_CFG_GROUPCLASSES = new HashSet<String>();

    private Collection<String> RESULT_PREF_GROUPCLASSES = new HashSet<String>();

    private Collection<String> RESULT_CFG_GROUPMEMBERFIELDS = new HashSet<String>();

    private Collection<String> RESULT_PREF_GROUPMEMBERFIELDS = new HashSet<String>();

    private void addProperty(String prefName, String cfgName, String prefValue, String cfgValue)
    {
        setPreference(prefName, prefValue);
        CONFIG.setProperty(cfgName, cfgValue);
    }

    private void setPreference(String prefName, String prefValue)
    {
        PREFERENCES.put(prefName, prefValue);
    }

    @Override
    public void setUp() throws Exception
    {
        super.setUp();

        CONFIG.setProperty("xwiki.authentication.ldap.authclass", "com.xpn.xwiki.user.impl.LDAP.LDAPAuthServiceImpl");

        addProperty("ldap", "xwiki.authentication.ldap", "0", "1");
        addProperty("ldap_server", "xwiki.authentication.ldap.server", "localhost", "127.0.0.1");
        addProperty("ldap_port", "xwiki.authentication.ldap.port", "10000", "11111");
        addProperty("ldap_check_level", "xwiki.authentication.ldap.check_level", "0", "1");
        addProperty("ldap_base_DN", "xwiki.authentication.ldap.base_DN", "o=sevenSeas", "o=sevenSeas2");
        addProperty("ldap_bind_DN", "xwiki.authentication.ldap.bind_DN", "cn={0},ou=people,o=sevenSeas",
            "cn={0},ou=people,o=sevenSeas2");
        addProperty("ldap_bind_pass", "xwiki.authentication.ldap.bind_pass", "{1}", "{1}2");
        addProperty("ldap_UID_attr", "xwiki.authentication.ldap.UID_attr", "uid", "uid2");
        addProperty("ldap_groupcache_expiration", "xwiki.authentication.ldap.groupcache_expiration", "10000", "11111");
        addProperty("ldap_user_group", "xwiki.authentication.ldap.user_group", "0", "1");
        addProperty("ldap_validate_password", "xwiki.authentication.ldap.validate_password", "1", "0");
        addProperty("ldap_update_user", "xwiki.authentication.ldap.update_user", "0", "1");
        addProperty("ldap_trylocal", "xwiki.authentication.ldap.trylocal", "0", "1");
        addProperty("ldap_mode_group_sync", "xwiki.authentication.ldap.mode_group_sync", "always", "create");

        addProperty("ldap_fields_mapping", "xwiki.authentication.ldap.fields_mapping", "name=uid,last_name=sn",
            "name=uid2,last_name=sn2");

        RESULT_PREF_USERMAPPING.put("uid", "name");
        RESULT_PREF_USERMAPPING.put("sn", "last_name");
        RESULT_CFG_USERMAPPING.put("uid2", "name");
        RESULT_CFG_USERMAPPING.put("sn2", "last_name");

        // @formatter:off
        addProperty("ldap_group_mapping", "xwiki.authentication.ldap.group_mapping",
            XADMINGROUP_FULLNAME + "=" + LDAPTOTOGRP_DN + "|" +
            XADMINGROUP_FULLNAME + "=" + LDAPTITIGRP_DN + "|" +
            XADMINGROUP_FULLNAME + "=" + FILTER.replace("|", "\\|") + "|" +
            XADMINGROUP2_FULLNAME + "=" + LDAPTOTOGRP_DN + "|" +
            XADMINGROUP2_FULLNAME + "=" + LDAPTITIGRP_DN + "|" +
            XADMINGROUP2_FULLNAME + "=" + FILTER.replace("|", "\\|"),

            XADMINGROUP_FULLNAME + "=" + LDAPTOTOGRP2_DN + "|" +
            XADMINGROUP_FULLNAME + "=" + LDAPTITIGRP2_DN + "|" +
            XADMINGROUP_FULLNAME + "=" + FILTER.replace("|", "\\|") + "|" +
            XADMINGROUP2_FULLNAME + "=" + LDAPTOTOGRP2_DN + "|" +
            XADMINGROUP2_FULLNAME + "=" + LDAPTITIGRP2_DN + "|" +
            XADMINGROUP2_FULLNAME + "=" + FILTER.replace("|", "\\|"));
        // @formatter:on

        Set<String> ldapgroups = new HashSet<String>();
        ldapgroups.add(LDAPTOTOGRP_DN);
        ldapgroups.add(LDAPTITIGRP_DN);
        ldapgroups.add(FILTER);

        RESULT_PREF_GROUPMAPPING.put(XADMINGROUP_FULLNAME, ldapgroups);
        RESULT_PREF_GROUPMAPPING.put(XADMINGROUP2_FULLNAME, ldapgroups);

        Set<String> ldapgroups2 = new HashSet<String>();
        ldapgroups2.add(LDAPTOTOGRP2_DN);
        ldapgroups2.add(LDAPTITIGRP2_DN);
        ldapgroups2.add(FILTER);

        RESULT_CFG_GROUPMAPPING.put(XADMINGROUP_FULLNAME, ldapgroups2);
        RESULT_CFG_GROUPMAPPING.put(XADMINGROUP2_FULLNAME, ldapgroups2);

        RESULT_PREF_GROUPCLASSES.add("groupclass1");
        RESULT_PREF_GROUPCLASSES.add("groupclass2");
        RESULT_CFG_GROUPCLASSES.add("groupclass12");

        addProperty("ldap_group_classes", "xwiki.authentication.ldap.group_classes", "groupclass1,groupclass2",
            "groupclass12");

        RESULT_PREF_GROUPMEMBERFIELDS.add("groupmemberfield1");
        RESULT_PREF_GROUPMEMBERFIELDS.add("groupmemberfield2");
        RESULT_CFG_GROUPMEMBERFIELDS.add("groupmemberfield12");

        addProperty("ldap_group_memberfields", "xwiki.authentication.ldap.group_memberfields",
            "groupmemberfield1,groupmemberfield2", "groupmemberfield12");

        this.prefContext = new XWikiContext();

        new XWiki(new XWikiConfig(), this.prefContext)
        {
            @Override
            public void initXWiki(XWikiConfig config, XWikiContext context, XWikiEngineContext engine_context,
                boolean noupdate) throws XWikiException
            {
                context.setWiki(this);
                setConfig(config);
            }

            @Override
            public String getXWikiPreference(String prefname, String default_value, XWikiContext context)
            {
                return PREFERENCES.get(prefname);
            }
        };

        this.cfgContext = new XWikiContext();

        new XWiki(CONFIG, this.cfgContext)
        {
            @Override
            public void initXWiki(XWikiConfig config, XWikiContext context, XWikiEngineContext engine_context,
                boolean noupdate) throws XWikiException
            {
                context.setWiki(this);
                setConfig(config);
            }

            @Override
            public String getXWikiPreference(String prefname, String default_value, XWikiContext context)
            {
                return default_value;
            }
        };

        for (Map.Entry<Object, Object> entry : CONFIG.entrySet()) {
            getConfigurationSource().setProperty((String) entry.getKey(), entry.getValue());
        }
    }

    // ///////////////////////////////////////////////////////////////////////////////////////:
    // Tests

    @Test
    public void testGetLDAPParam1()
    {
        Assert.assertEquals("0",
            XWikiLDAPConfig.getInstance().getLDAPParam("ldap", "xwiki.authentication.ldap", null, prefContext));
        Assert.assertEquals("1",
            XWikiLDAPConfig.getInstance().getLDAPParam("ldap", "xwiki.authentication.ldap", null, cfgContext));
    }

    @Test
    public void testGetLDAPParam2()
    {
        Assert.assertEquals("localhost", XWikiLDAPConfig.getInstance().getLDAPParam("ldap_server", null, prefContext));
        Assert.assertEquals("127.0.0.1", XWikiLDAPConfig.getInstance().getLDAPParam("ldap_server", null, cfgContext));
        Assert.assertEquals("127.0.0.1",
            XWikiLDAPConfig.getInstance().getLDAPParam("ldap_server", "default", cfgContext));
    }

    @Test
    public void testIsLDAPEnabled()
    {
        Assert.assertEquals(false, XWikiLDAPConfig.getInstance().isLDAPEnabled(prefContext));
        Assert.assertEquals(true, XWikiLDAPConfig.getInstance().isLDAPEnabled(cfgContext));
    }

    @Test
    public void testGetLDAPPort()
    {
        Assert.assertEquals(10000, XWikiLDAPConfig.getInstance().getLDAPPort(prefContext));
        Assert.assertEquals(11111, XWikiLDAPConfig.getInstance().getLDAPPort(cfgContext));
    }

    @Test
    public void testGetGroupMappings()
    {
        Map<String, Set<String>> prefMapping = XWikiLDAPConfig.getInstance().getGroupMappings(prefContext);

        Assert.assertEquals(RESULT_PREF_GROUPMAPPING, prefMapping);

        Map<String, Set<String>> cfgMapping = XWikiLDAPConfig.getInstance().getGroupMappings(cfgContext);

        Assert.assertEquals(RESULT_CFG_GROUPMAPPING, cfgMapping);
    }

    @Test
    public void testGetUserMappings()
    {
        List<String> prefAttrList = new ArrayList<String>();

        Map<String, String> prefMapping = XWikiLDAPConfig.getInstance().getUserMappings(prefAttrList, prefContext);

        Assert.assertEquals("uid", prefAttrList.get(0));
        Assert.assertEquals("sn", prefAttrList.get(1));

        Assert.assertEquals(RESULT_PREF_USERMAPPING, prefMapping);

        // ///

        List<String> cfgAttrList = new ArrayList<String>();

        Map<String, String> cfgMapping = XWikiLDAPConfig.getInstance().getUserMappings(cfgAttrList, cfgContext);

        Assert.assertEquals("uid2", cfgAttrList.get(0));
        Assert.assertEquals("sn2", cfgAttrList.get(1));

        Assert.assertEquals(RESULT_CFG_USERMAPPING, cfgMapping);
    }

    @Test
    public void testGetCacheExpiration()
    {
        Assert.assertEquals(10000, XWikiLDAPConfig.getInstance().getCacheExpiration(prefContext));
        Assert.assertEquals(11111, XWikiLDAPConfig.getInstance().getCacheExpiration(cfgContext));
    }

    @Test
    public void testGetGroupClasses()
    {
        Assert.assertEquals(RESULT_PREF_GROUPCLASSES, XWikiLDAPConfig.getInstance().getGroupClasses(prefContext));
        Assert.assertEquals(RESULT_CFG_GROUPCLASSES, XWikiLDAPConfig.getInstance().getGroupClasses(cfgContext));
    }

    @Test
    public void testGetGroupMemberFields()
    {
        Assert.assertEquals(RESULT_PREF_GROUPMEMBERFIELDS,
            XWikiLDAPConfig.getInstance().getGroupMemberFields(prefContext));
        Assert.assertEquals(RESULT_CFG_GROUPMEMBERFIELDS,
            XWikiLDAPConfig.getInstance().getGroupMemberFields(cfgContext));
    }

    @Test
    public void testParseRemoteUserWithNoConfiguration() throws Exception
    {
        XWikiLDAPConfig config = new XWikiLDAPConfig("remoteuser", this.prefContext);

        Assert.assertEquals("remoteuser", config.getMemoryConfiguration().get("auth.input"));
        Assert.assertEquals("remoteuser", config.getMemoryConfiguration().get("uid"));
    }

    @Test
    public void testParseRemoteUserWithSimplePattern() throws Exception
    {
        setPreference("ldap_remoteUserParser", "remote");

        XWikiLDAPConfig config = new XWikiLDAPConfig("remoteuser", this.prefContext);

        Assert.assertEquals("remoteuser", config.getMemoryConfiguration().get("auth.input"));
        Assert.assertEquals("remote", config.getMemoryConfiguration().get("uid"));
    }

    @Test
    public void testParseRemoteUserWithGroupsPattern() throws Exception
    {
        setPreference("ldap_remoteUserParser", "(remote)(user)");
        setPreference("ldap_remoteUserMapping.1", "uid");
        setPreference("ldap_remoteUserMapping.2",
            "ldap_server,ldap_port,ldap_base_DN,ldap_bind_DN,ldap_bind_pass,ldap_group_mapping");

        XWikiLDAPConfig config = new XWikiLDAPConfig("remoteuser", this.prefContext);

        Assert.assertEquals("remoteuser", config.getMemoryConfiguration().get("auth.input"));
        Assert.assertEquals("remote", config.getMemoryConfiguration().get("uid"));
        Assert.assertEquals("user", config.getMemoryConfiguration().get("ldap_server"));
        Assert.assertEquals("user", config.getMemoryConfiguration().get("ldap_base_DN"));
        Assert.assertEquals("user", config.getMemoryConfiguration().get("ldap_group_mapping"));
    }

    @Test
    public void testParseRemoteUserWithGroupsPatternandConversions() throws Exception
    {
        setPreference("ldap_remoteUserParser", "(.+)@(.+)");
        setPreference("ldap_remoteUserMapping.1", "uid");
        setPreference("ldap_remoteUserMapping.2",
            "ldap_server,ldap_port,ldap_base_DN,ldap_bind_DN,ldap_bind_pass,ldap_group_mapping");
        setPreference("ldap_remoteUserMapping.ldap_server", "doMain=my.domain.com|domain2=my.domain2.com");
        setPreference("ldap_remoteUserMapping.ldap_port", "doMain=388|domain2=387");
        setPreference("ldap_remoteUserMapping.ldap_base_DN",
            "dOmain=dc=my,dc=domain,dc=com|domain2=dc=my,dc=domain2,dc=com");
        setPreference("ldap_remoteUserMapping.ldap_bind_DN",
            "doMain=cn=bind,dc=my,dc=domain,dc=com|domain2=cn=bind,dc=my,dc=domain2,dc=com");
        setPreference("ldap_remoteUserMapping.ldap_bind_pass", "doMain=password|domain2=password2");
        setPreference("ldap_remoteUserMapping.ldap_group_mapping",
            "doMain=xgroup11=lgroup11\\|xgroup12=lgroup12|domain2=xgroup21=lgroup21\\|xgroup22=lgroup22");

        XWikiLDAPConfig config = new XWikiLDAPConfig("user@domain", this.prefContext);

        Assert.assertEquals("user", config.getMemoryConfiguration().get("uid"));
        Assert.assertEquals("my.domain.com", config.getMemoryConfiguration().get("ldap_server"));
        Assert.assertEquals("388", config.getMemoryConfiguration().get("ldap_port"));
        Assert.assertEquals("dc=my,dc=domain,dc=com", config.getMemoryConfiguration().get("ldap_base_DN"));
        Assert.assertEquals("cn=bind,dc=my,dc=domain,dc=com", config.getMemoryConfiguration().get("ldap_bind_DN"));
        Assert.assertEquals("password", config.getMemoryConfiguration().get("ldap_bind_pass"));
        Assert.assertEquals("xgroup11=lgroup11|xgroup12=lgroup12",
            config.getMemoryConfiguration().get("ldap_group_mapping"));

        config = new XWikiLDAPConfig("user@domain2", this.prefContext);

        Assert.assertEquals("user", config.getMemoryConfiguration().get("uid"));
        Assert.assertEquals("my.domain2.com", config.getMemoryConfiguration().get("ldap_server"));
        Assert.assertEquals("387", config.getMemoryConfiguration().get("ldap_port"));
        Assert.assertEquals("dc=my,dc=domain2,dc=com", config.getMemoryConfiguration().get("ldap_base_DN"));
        Assert.assertEquals("cn=bind,dc=my,dc=domain2,dc=com", config.getMemoryConfiguration().get("ldap_bind_DN"));
        Assert.assertEquals("password2", config.getMemoryConfiguration().get("ldap_bind_pass"));
        Assert.assertEquals("xgroup21=lgroup21|xgroup22=lgroup22",
            config.getMemoryConfiguration().get("ldap_group_mapping"));
    }
}
