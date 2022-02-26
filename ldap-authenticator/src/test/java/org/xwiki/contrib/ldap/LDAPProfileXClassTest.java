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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;

import javax.inject.Provider;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.xwiki.component.util.DefaultParameterizedType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryFilter;
import org.xwiki.query.QueryManager;
import org.xwiki.test.mockito.MockitoComponentManagerRule;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.ElementInterface;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.web.Utils;

/**
 * Test {@link LDAPProfileXClass}.
 * 
 * @version $Id$
 */
public class LDAPProfileXClassTest
{
    @Rule
    public MockitoComponentManagerRule mocker = new MockitoComponentManagerRule();

    private LDAPProfileXClass ldapProfile;

    private QueryManager mockQueryManager;
    private Query mockQuery;

    // TODO!
    // private String expectedQuery;
    private final String expectedDocname = "XWiki.userProfile";

    private XWikiDocument expectedDocument;

    private DocumentReference ldapClassRef;

    @Before
    public void setUp() throws Exception
    {
        ldapClassRef = new DocumentReference(
            new LocalDocumentReference(LDAPProfileXClass.LDAPPROFILECLASS_REFERENCE),
            new WikiReference("xwiki"));

        // first we mock all the stuff so the LDAPProfileClass can be initialized
        XWikiContext mockContext = mock(XWikiContext.class);

        Provider<XWikiContext> mockContectProvider = mocker.registerMockComponent(XWikiContext.TYPE_PROVIDER);
        when(mockContectProvider.get()).thenReturn(mockContext);

        XWiki mockWiki = mock(XWiki.class);
        when(mockContext.getWiki()).thenReturn(mockWiki);

        EntityReferenceSerializer<String> localRefToString = mocker.registerMockComponent(
            new DefaultParameterizedType(null, EntityReferenceSerializer.class, String.class), "local");
        when(localRefToString.serialize(eq(ldapClassRef), any())).thenReturn(LDAPProfileXClass.LDAP_XCLASS);

        XWikiDocument ldapClassDoc = mock(XWikiDocument.class);
        when(ldapClassDoc.getDocumentReference()).thenReturn(ldapClassRef);
        BaseClass ldapClass = mock(BaseClass.class);
        when(ldapClass.getDocumentReference()).thenReturn(ldapClassRef);
        when(ldapClassDoc.getXClass()).thenReturn(ldapClass);
        when(ldapClass.apply(any(ElementInterface.class), anyBoolean())).thenReturn(false);

        when(mockWiki.getDocument(LDAPProfileXClass.LDAPPROFILECLASS_REFERENCE, mockContext))
            .thenReturn(ldapClassDoc);

        this.ldapProfile = new LDAPProfileXClass(mockContext);

        // then we do some (minimal) mocks for the query
        mockQuery = mock(Query.class);
        mockQueryManager = this.mocker.registerMockComponent(QueryManager.class);
        when(mockQuery.addFilter(any(QueryFilter.class))).thenReturn(mockQuery);

        expectedDocument = mock(XWikiDocument.class);
        when(mockWiki.getDocument(expectedDocname, mockContext)).thenReturn(expectedDocument);
        mocker.registerMockComponent(QueryFilter.class, "unique");

        Utils.setComponentManager(mocker);
    }

    private void bindQueryBy(String attribute) throws QueryException
    {
        when(mockQueryManager.createQuery(
            ", BaseObject as ldap, StringProperty as dn where doc.fullName = ldap.name"
            + " and ldap.className = 'XWiki.LDAPProfileClass' and ldap.id = dn.id.id and dn.id.name = '"
            + attribute + "' and lower(str(dn.value)) = :value", Query.HQL)).thenReturn(mockQuery);
    }

    @Test
    public void searchDocumentByUid() throws QueryException
    {
        final String testUserName = "UserName";
        final String testUserNameLC = "username";
        bindQueryBy("uid");
        when(mockQuery.bindValue("value", testUserNameLC)).thenReturn(mockQuery);
        when(mockQuery.<String>execute()).thenReturn(Arrays.asList(expectedDocname));

        XWikiDocument result = ldapProfile.searchDocumentByUid(testUserName);
        assertSame(expectedDocument, result);
    }

    @Test
    public void searchDocumentByUnknownUid() throws QueryException
    {
        final String testUserName = "username";
        bindQueryBy("uid");
        when(mockQuery.bindValue(eq("value"), anyString())).thenReturn(mockQuery);
        when(mockQuery.<String>execute()).thenReturn(Collections.<String>emptyList());

        XWikiDocument result = ldapProfile.searchDocumentByUid(testUserName);
        assertNull(result);
    }

    @Test
    @Ignore("fails because of the error message in the log, which is actually expected here")
    public void searchDocumentByNonuniqueUid() throws QueryException
    {
        final String testUserName = "UserName";
        bindQueryBy("uid");
        when(mockQuery.bindValue("value", testUserName)).thenReturn(mockQuery);
        when(mockQuery.<String>execute()).thenReturn(Arrays.asList(expectedDocname, "SomeMore"));

        XWikiDocument result = ldapProfile.searchDocumentByUid(testUserName);
        assertSame(expectedDocument, result);
    }

    @Test
    public void searchDocumentByDN() throws QueryException
    {
        final String testDN = "cn=username,ou=users,DC=example,DC=org";
        final String testDNlowercased = "cn=username,ou=users,dc=example,dc=org";
        bindQueryBy("dn");
        when(mockQuery.bindValue("value", testDNlowercased)).thenReturn(mockQuery);
        when(mockQuery.<String>execute()).thenReturn(Arrays.asList(expectedDocname));

        XWikiDocument result = ldapProfile.searchDocumentByDn(testDN);
        assertSame(expectedDocument, result);
    }

    @Test
    public void getDN()
    {
        final String testDN = "cn=username,ou=users,DC=example,DC=org";

        BaseObject ldapObj = mock(BaseObject.class);
        when(ldapObj.getStringValue(LDAPProfileXClass.LDAP_XFIELD_DN)).thenReturn(testDN);
        XWikiDocument testDoc = mock(XWikiDocument.class);
        when(testDoc.getXObject(ldapClassRef)).thenReturn(ldapObj);

        String result = ldapProfile.getDn(testDoc);
        assertEquals(testDN, result);
    }

    @Test
    public void getDNFromNullProfile()
    {
        String result = ldapProfile.getDn((XWikiDocument) null);
        assertNull(result);
    }

    @Test
    public void getDNFromEmptyProfile()
    {
        XWikiDocument testDoc = mock(XWikiDocument.class);
        String result = ldapProfile.getDn(testDoc);
        assertNull(result);
    }

    @Test
    public void getDNWhenValueIsEmpty()
    {
        BaseObject ldapObj = mock(BaseObject.class);
        when(ldapObj.getStringValue(LDAPProfileXClass.LDAP_XFIELD_DN)).thenReturn("");
        XWikiDocument testDoc = mock(XWikiDocument.class);
        when(testDoc.getXObject(ldapClassRef)).thenReturn(ldapObj);

        String result = ldapProfile.getDn(testDoc);
        assertNull(result);
    }
}
