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

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.contrib.ldap.framework.AbstractLDAPTestCase;
import org.xwiki.contrib.ldap.framework.LDAPTestSetup;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.test.annotation.AfterComponent;
import org.xwiki.test.annotation.AllComponents;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;

import static com.xpn.xwiki.test.mockito.OldcoreMatchers.anyXWikiContext;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests using embedded LDAP server (Apache DS). Theses test can be launched directly from JUnit plugin of EDI.
 * 
 * @version $Id$
 */
// TODO: get rid of @AllComponents
@AllComponents
public class XWikiLDAPAuthServiceImplTest extends AbstractLDAPTestCase
{
    private static final String MAIN_WIKI_NAME = "xwiki";

    private static final LocalDocumentReference USER_XCLASS_REFERENCE =
        new LocalDocumentReference("XWiki", "XWikiUsers");

    private static final LocalDocumentReference GROUP_XCLASS_REFERENCE =
        new LocalDocumentReference("XWiki", "XWikiGroups");

    private XWikiLDAPAuthServiceImpl ldapAuth;

    @AfterComponent
    public void afterComponent()
    {
        // Unregister xwikicfg component so that it's replaced by a mock
        this.mocker.getMocker().unregisterComponent(ConfigurationSource.class, "xwikicfg");
    }

    @Before
    public void before() throws Exception
    {
        // Make sure to reset group cache so that one test data is not reused in another test
        XWikiLDAPUtils.resetGroupCache();

        this.mocker.getXWikiContext().setWikiId(MAIN_WIKI_NAME);
        this.mocker.getXWikiContext().setMainXWiki(MAIN_WIKI_NAME);

        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap", "1");
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.server", LDAPTestSetup.LDAP_SERVER);
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.port", "" + LDAPTestSetup.getLDAPPort());
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.base_DN", LDAPTestSetup.LDAP_BASEDN);
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.bind_DN", LDAPTestSetup.LDAP_BINDDN_CN);
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.bind_pass",
            LDAPTestSetup.LDAP_BINDPASS_CN);
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.UID_attr",
            LDAPTestSetup.LDAP_USERUID_FIELD);
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.groupcache_expiration", "1");
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.try_local", "0");
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.update_user", "1");
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.fields_mapping",
            "last_name=sn,first_name=givenName,fullname=cn,email=mail,listfield=description");

        // Add a list field to user class
        this.mocker.getSpyXWiki().getUserClass(this.mocker.getXWikiContext());
        XWikiDocument userDocument =
            this.mocker.getSpyXWiki().getDocument(USER_XCLASS_REFERENCE, this.mocker.getXWikiContext());
        BaseClass userClass = userDocument.getXClass();
        userClass.addStaticListField("listfield", "List field", 30, true, "");
        this.mocker.getSpyXWiki().saveDocument(userDocument, this.mocker.getXWikiContext());

        this.ldapAuth = new XWikiLDAPAuthServiceImpl();
    }

    private String userProfileName(String uid)
    {
        return "XWiki." + XWikiLDAPUtils.cleanXWikiUserPageName(uid);
    }

    private XWikiDocument getDocument(String name) throws XWikiException
    {
        return this.mocker.getSpyXWiki().getDocument(name, this.mocker.getXWikiContext());
    }

    private void saveDocument(XWikiDocument document) throws XWikiException
    {
        this.mocker.getSpyXWiki().saveDocument(document, this.mocker.getXWikiContext());
    }

    private XWikiDocument assertAuthenticate(String login, String password, String storedDn) throws XWikiException
    {
        return assertAuthenticate(login, password, userProfileName(login), storedDn);
    }

    private XWikiDocument assertAuthenticate(String login, String password, String xwikiUserName, String storedDn)
        throws XWikiException
    {
        return assertAuthenticate(login, password, xwikiUserName, storedDn, login);
    }

    private XWikiDocument assertAuthenticate(String login, String password, String xwikiUserName, String storedDn,
        String storedUid) throws XWikiException
    {
        Principal principal = this.ldapAuth.authenticate(login, password, this.mocker.getXWikiContext());

        // Check that authentication return a valid Principal
        assertNotNull("Authentication failed", principal);

        // Check that the returned Principal has the good name
        assertEquals("Wrong returned principal", xwikiUserName, principal.getName());

        XWikiDocument userProfile = getDocument(xwikiUserName);

        // check hat user has been created
        assertTrue("The user profile has not been created", !userProfile.isNew());

        BaseObject userProfileObj = userProfile.getXObject(USER_XCLASS_REFERENCE);

        assertNotNull("The user profile document does not contains user object", userProfileObj);

        BaseObject ldapProfileObj = userProfile.getXObject(LDAPProfileXClass.LDAPPROFILECLASS_REFERENCE);

        assertNotNull("The user profile document does not contains ldap object", ldapProfileObj);

        assertEquals(storedDn.toLowerCase(),
            ldapProfileObj.getStringValue(LDAPProfileXClass.LDAP_XFIELD_DN).toLowerCase());
        assertEquals(storedUid.toLowerCase(),
            ldapProfileObj.getStringValue(LDAPProfileXClass.LDAP_XFIELD_UID).toLowerCase());

        // Register user profile document so that it's found by following searches
        when(
            this.mocker.getMockStore().searchDocuments(
                ", BaseObject as obj, StringProperty as prop where doc.fullName=obj.name and obj.className=? and obj.id=prop.id.id and prop.name=? and lower(prop.value)=?",
                false, false, false, 0, 0, Arrays.asList(LDAPProfileXClass.LDAP_XCLASS,
                    LDAPProfileXClass.LDAP_XFIELD_UID, storedUid.toLowerCase()),
                this.mocker.getXWikiContext())).thenReturn(Arrays.asList(userProfile));

        return userProfile;
    }

    // Tests

    /**
     * Validate "simple" LDAP authentication.
     */
    @Test
    public void testAuthenticate() throws XWikiException
    {
        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    /**
     * Make sure the "real" uid is used by default as XWiki user page name.
     */
    @Test
    public void testAuthenticateWithDifferentCase() throws XWikiException
    {
        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN.toLowerCase(), LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            userProfileName(LDAPTestSetup.HORATIOHORNBLOWER_CN), LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    /**
     * Validate authentication of a user from an allowed group.
     */
    @Test
    public void testAuthenticateWithIncludeGroup() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.user_group", LDAPTestSetup.HMSLYDIA_DN);

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    /**
     * Validate authentication of a user from an allowed group.
     */
    @Test
    public void testAuthenticateWithIncludeGroupAndPartialUid() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.user_group", LDAPTestSetup.HMSLYDIA_DN);

        Principal principal = this.ldapAuth.authenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN.substring(0, 2),
            LDAPTestSetup.HORATIOHORNBLOWER_PWD, this.mocker.getXWikiContext());

        // Check that authentication return a null Principal
        assertNull(principal);
    }

    /**
     * Validate authentication of a user not from an excluded group.
     */
    @Test
    public void testAuthenticateWithExcludeGroup() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.exclude_group",
            LDAPTestSetup.EXCLUSIONGROUP_DN);

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    /**
     * Validate authentication of a user from an allowed group.
     */
    @Test
    public void testAuthenticateWithIncludeAndExcludeGroup() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.user_group", LDAPTestSetup.HMSLYDIA_DN);
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.exclude_group",
            LDAPTestSetup.EXCLUSIONGROUP_DN);

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    /**
     * Validate "simple" LDAP authentication fail with wrong user.
     */
    @Test
    public void testAuthenticateWithWrongUser() throws XWikiException
    {
        Principal principal = this.ldapAuth.authenticate("WrongUser", "WrongPass", this.mocker.getXWikiContext());

        // Check that authentication return a null Principal
        assertNull(principal);

        XWikiDocument userProfile = getDocument("XWiki.WrongUser");

        // check hat user has not been created
        assertTrue("The user profile has been created", userProfile.isNew());
    }

    /**
     * Validate the same user profile is used when authentication is called twice for same user.
     */
    @Test
    public void testAuthenticateTwice() throws XWikiException
    {
        XWikiDocument document = assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN,
            LDAPTestSetup.HORATIOHORNBLOWER_PWD, LDAPTestSetup.HORATIOHORNBLOWER_DN);

        when(this.mocker.getMockStore().searchDocuments(anyString(), anyBoolean(), anyBoolean(), anyBoolean(), anyInt(),
            anyInt(), anyList(), anyXWikiContext())).thenReturn(Collections.singletonList(document));

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    /**
     * Validate the same user profile is used when authentication is called twice for same user even the uid used have
     * different case.
     */
    @Test
    public void testAuthenticateTwiceAndDifferentCase() throws XWikiException
    {
        XWikiDocument document = assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN,
            LDAPTestSetup.HORATIOHORNBLOWER_PWD, LDAPTestSetup.HORATIOHORNBLOWER_DN);

        when(this.mocker.getMockStore().searchDocuments(anyString(), anyBoolean(), anyBoolean(), anyBoolean(), anyInt(),
            anyInt(), anyList(), anyXWikiContext())).thenReturn(Collections.singletonList(document));

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN.toUpperCase(), LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            userProfileName(LDAPTestSetup.HORATIOHORNBLOWER_CN), LDAPTestSetup.HORATIOHORNBLOWER_DN,
            LDAPTestSetup.HORATIOHORNBLOWER_CN);
    }

    /**
     * Validate "simple" LDAP authentication when uid contains point(s).
     */
    @Test
    public void testAuthenticateWhenUidContainsPoints() throws XWikiException
    {
        assertAuthenticate(LDAPTestSetup.USERWITHPOINTS_CN, LDAPTestSetup.USERWITHPOINTS_PWD,
            "XWiki." + LDAPTestSetup.USERWITHPOINTS_CN.replaceAll("\\.", ""), LDAPTestSetup.USERWITHPOINTS_DN);
    }

    /**
     * Validate a different profile is used for different uid containing points but having same cleaned uid.
     */
    @Test
    public void testAuthenticateTwiceWhenDifferentUsersAndUidContainsPoints() throws XWikiException
    {
        assertAuthenticate(LDAPTestSetup.USERWITHPOINTS_CN, LDAPTestSetup.USERWITHPOINTS_PWD,
            "XWiki." + LDAPTestSetup.USERWITHPOINTS_CN.replaceAll("\\.", ""), LDAPTestSetup.USERWITHPOINTS_DN);

        assertAuthenticate(LDAPTestSetup.OTHERUSERWITHPOINTS_CN, LDAPTestSetup.OTHERUSERWITHPOINTS_PWD,
            "XWiki." + LDAPTestSetup.OTHERUSERWITHPOINTS_CN.replaceAll("\\.", "") + "_1",
            LDAPTestSetup.OTHERUSERWITHPOINTS_DN);
    }

    /**
     * Validate "simple" LDAP authentication when the user already exists but does not contains LDAP profile object.
     */
    @Test
    public void testAuthenticateWhenNonLDAPUserAlreadyExists() throws XWikiException
    {
        this.mocker.getSpyXWiki().createEmptyUser(LDAPTestSetup.HORATIOHORNBLOWER_CN, "edit",
            this.mocker.getXWikiContext());

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    /**
     * Validate "simple" LDAP authentication when the user profile default page already exists but does not contains
     * user object. In that case it is using another document to create the user.
     */
    @Test
    public void testAuthenticateWhenNonLDAPNonUserAlreadyExists() throws XWikiException
    {
        saveDocument(getDocument(userProfileName(LDAPTestSetup.HORATIOHORNBLOWER_CN)));

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            userProfileName(LDAPTestSetup.HORATIOHORNBLOWER_CN) + "_1", LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    @Test
    public void testAuthenticateWithGroupMembership() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.group_mapping",
            "XWiki.Group1=" + LDAPTestSetup.HMSLYDIA_DN);

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);

        List<BaseObject> groupList = getDocument("XWiki.Group1").getXObjects(GROUP_XCLASS_REFERENCE);

        assertTrue("No user has been added to the group", groupList != null && groupList.size() > 0);

        BaseObject groupObject = groupList.get(0);

        assertEquals(userProfileName(LDAPTestSetup.HORATIOHORNBLOWER_CN), groupObject.getStringValue("member"));
    }

    @Test
    public void testAuthenticateWithGroupMembershipWhenOneXWikiGroupMapTwoLDAPGroups() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.group_mapping",
            "XWiki.Group1=" + LDAPTestSetup.HMSLYDIA_DN + "|" + "XWiki.Group1=" + LDAPTestSetup.EXCLUSIONGROUP_DN);

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);

        List<BaseObject> groupList = getDocument("XWiki.Group1").getXObjects(GROUP_XCLASS_REFERENCE);

        assertTrue("No user has been added to the group", groupList != null && groupList.size() > 0);

        BaseObject groupObject = groupList.get(0);

        assertEquals(userProfileName(LDAPTestSetup.HORATIOHORNBLOWER_CN), groupObject.getStringValue("member"));
    }

    @Test
    public void testAuthenticateTwiceWithGroupMembership() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.group_mapping",
            "XWiki.Group1=" + LDAPTestSetup.HMSLYDIA_DN);

        when(this.mocker.getMockGroupService().getAllMatchedGroups(any(Object[][].class), anyBoolean(), anyInt(),
            anyInt(), any(Object[][].class), anyXWikiContext()))
                .thenReturn((List) Collections.singletonList("XWiki.Group1"));

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);

        when(this.mocker.getMockGroupService().getAllGroupsNamesForMember(anyString(), anyInt(), anyInt(),
            anyXWikiContext())).thenReturn(Collections.singletonList("XWiki.Group1"));

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);

        List<BaseObject> groupList = getDocument("XWiki.Group1").getXObjects(GROUP_XCLASS_REFERENCE);

        assertTrue("No user has been added to the group", groupList != null);

        assertTrue("The user has been added twice in the group", groupList.size() == 1);

        BaseObject groupObject = groupList.get(0);

        assertEquals(userProfileName(LDAPTestSetup.HORATIOHORNBLOWER_CN), groupObject.getStringValue("member"));

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    /**
     * Validate user field synchronization in "simple" LDAP authentication.
     */
    @Test
    public void testAuthenticateUserSync() throws XWikiException
    {
        XWikiDocument userProfile = assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN,
            LDAPTestSetup.HORATIOHORNBLOWER_PWD, LDAPTestSetup.HORATIOHORNBLOWER_DN);

        BaseObject userProfileObj = userProfile.getXObject(USER_XCLASS_REFERENCE);

        assertEquals(LDAPTestSetup.HORATIOHORNBLOWER_SN, userProfileObj.getStringValue("last_name"));
        assertEquals(LDAPTestSetup.HORATIOHORNBLOWER_GIVENNAME, userProfileObj.getStringValue("first_name"));
        assertEquals(LDAPTestSetup.HORATIOHORNBLOWER_MAIL, userProfileObj.getStringValue("email"));
        assertEquals(LDAPTestSetup.HORATIOHORNBLOWER_DESCRIPTION, userProfileObj.getListValue("listfield"));

        // Check non mapped properties are not touched

        userProfileObj.setStringValue("customproperty", "customvalue");

        userProfile = assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);

        userProfileObj = userProfile.getXObject(USER_XCLASS_REFERENCE);

        assertEquals("customvalue", userProfileObj.getStringValue("customproperty"));

        // Authenticate again

        XWikiDocument userProfile2 = assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN,
            LDAPTestSetup.HORATIOHORNBLOWER_PWD, LDAPTestSetup.HORATIOHORNBLOWER_DN);

        // Make sure the user document was not touched
        assertSame(userProfile, userProfile2);
    }

    @Test
    public void testAuthenticateUserSyncWithoutMapping() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.fields_mapping", "");

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    @Test
    public void testAuthenticateUserSyncWithEmptyMapping() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().removeProperty("xwiki.authentication.ldap.fields_mapping");

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    @Test
    public void testAuthenticateUserSyncWithWrongMapping() throws XWikiException
    {
        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.fields_mapping", "wrongfield=wrongfield");

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    @Test
    public void testAuthenticateWhenLDAPDNChanged() throws XWikiException
    {
        XWikiDocument userProfile = assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN,
            LDAPTestSetup.HORATIOHORNBLOWER_PWD, LDAPTestSetup.HORATIOHORNBLOWER_DN);

        BaseObject ldapProfileObj = userProfile.getXObject(LDAPProfileXClass.LDAPPROFILECLASS_REFERENCE);
        ldapProfileObj.setStringValue(LDAPProfileXClass.LDAP_XFIELD_DN, "oldDN");

        when(this.mocker.getMockStore().searchDocuments(anyString(), anyBoolean(), anyBoolean(), anyBoolean(), anyInt(),
            anyInt(), anyList(), anyXWikiContext())).thenReturn(Collections.singletonList(userProfile));

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);
    }

    @Test
    public void testAuthenticateWithOUMembership() throws XWikiException
    {
        saveDocument(getDocument("XWiki.Group1"));

        this.mocker.getMockXWikiCfg().setProperty("xwiki.authentication.ldap.group_mapping",
            "XWiki.Group1=" + LDAPTestSetup.USERS_OU);

        assertAuthenticate(LDAPTestSetup.HORATIOHORNBLOWER_CN, LDAPTestSetup.HORATIOHORNBLOWER_PWD,
            LDAPTestSetup.HORATIOHORNBLOWER_DN);

        List<BaseObject> groupList = getDocument("XWiki.Group1").getXObjects(GROUP_XCLASS_REFERENCE);

        assertTrue("No user has been added to the group", groupList != null && groupList.size() > 0);

        BaseObject groupObject = groupList.get(0);

        assertEquals(userProfileName(LDAPTestSetup.HORATIOHORNBLOWER_CN), groupObject.getStringValue("member"));
    }
}
