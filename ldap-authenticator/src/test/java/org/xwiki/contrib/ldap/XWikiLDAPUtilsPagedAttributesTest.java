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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.xpn.xwiki.XWikiContext;

/**
 * Test {@link XWikiLDAPUtils} fetching paged member attributes. This is a special feature of ActiveDirectory which uses
 * paging when a single result has too many attribute values, like a group with with more than, say 1500 members. See
 * LDAP-155
 *
 * @version $Id$
 */
public class XWikiLDAPUtilsPagedAttributesTest
{
    private static final String LDAP_BASE_DN = "o=sevenSeas";

    private static final String LDAP_TEST_GROUP_DN = "cn=group,o=sevenSeas";

    private static final String UID_ATTR = "cn";

    private static final String LDAP_TEST_USER_FMT_DN = UID_ATTR + "=user%04d,o=sevenSeas";

    private static final Pattern LDAP_TEST_USER_DN_PATTERN = Pattern
        .compile(UID_ATTR + "=(user[0-9]{4}),o=sevenSeas");

    private static final Pattern LDAP_MEMBER_ATTR_PATTERN = Pattern.compile("member;range=([0-9]+)-\\*");

    /* uncomment for larger test data:
    // typical page size of AD:
    private static final int PAGE_SIZE = 1500;
    // our expected test member size, made out of three pages
    // 1500 + 1500 + 1321 = 4321
    private static final int MEMBER_COUNT = 4321;
    */

    private static final int PAGE_SIZE = 3;
    // our expected test member size, made out of three pages
    // 3 + 3 + 2 = 8
    private static final int MEMBER_COUNT = 8;

    private XWikiContext mockContext;
    private XWikiLDAPConnection connection;
    private XWikiLDAPConfig configuration;

    // the three result pages retuned by the mock
    private LDAPEntry firstPageEntry;
    private LDAPEntry secondPageEntry;
    private LDAPEntry lastPageEntry;

    // and helpers to return a result enumeration with a single entry
    private final ThreadLocal<LDAPEntry> singlePagedResult = new ThreadLocal<>();
    private final ThreadLocal<LDAPEntry> singleLdapResult = new ThreadLocal<>();

    // to collect expected calls
    private List<String> requestedUserDNs;

    // object under test
    public XWikiLDAPUtils ldapUtils;


    /**
     * A slightly more elaborate mock to return only one entry.
     *
     * This is not thread safe (or even safe against recurrent calls
     * due to the use of a thread local.
     *
     * @param entry
     *            the entry to return
     * @return a result enumeration with only one entry
     * @throws LDAPException
     *             should not happen
     */
    private PagedLDAPSearchResults singleResultMock(LDAPEntry entry) throws LDAPException
    {
        assertNull("last paged result should have been fetched", singlePagedResult.get());
        singlePagedResult.set(entry);
        PagedLDAPSearchResults mockResult = Mockito.mock(PagedLDAPSearchResults.class);
        when(mockResult.hasMore()).thenReturn(singlePagedResult.get() != null);
        when(mockResult.next()).thenAnswer(new Answer<LDAPEntry>()
        {
            @Override
            public LDAPEntry answer(InvocationOnMock invocation) throws Throwable
            {
                LDAPEntry result = singlePagedResult.get();
                singlePagedResult.set(null);
                return result;
            }
        });
        return mockResult;
    }

    /**
     * Same for the LdapSearchResults.
     *
     * This is not thread safe either due to the use of a thread local.
     *
     * @param entry
     *            the entry to return
     * @return a result enumeration with only one entry
     * @throws LDAPException
     *             should not happen
     */
    private LDAPSearchResults singleLdapResultMock(LDAPEntry entry) throws LDAPException
    {
        assertNull("last ldap result should have been fetched", singleLdapResult.get());
        singleLdapResult.set(entry);
        LDAPSearchResults mockResult = Mockito.mock(LDAPSearchResults.class);
        when(mockResult.hasMore()).thenReturn(singleLdapResult.get() != null);
        when(mockResult.next()).thenAnswer(new Answer<LDAPEntry>()
        {
            @Override
            public LDAPEntry answer(InvocationOnMock invocation) throws Throwable
            {
                LDAPEntry result = singleLdapResult.get();
                singleLdapResult.remove();
                return result;
            }
        });

        return mockResult;
    }

    @Before
    public void setUp() throws LDAPException
    {
        mockContext = Mockito.mock(XWikiContext.class);

        connection = Mockito.mock(XWikiLDAPConnection.class);
        configuration = Mockito.mock(XWikiLDAPConfig.class);

        LDAPAttribute dnAttr = new LDAPAttribute("DN", LDAP_TEST_GROUP_DN);
        LDAPAttribute groupClassAttr = new LDAPAttribute("objectClass", "group");

        // the first entry contains an empty "member" attribute and the actual results in member;range=0-2
        {
            LDAPAttributeSet firstPageAttrs = new LDAPAttributeSet();
            firstPageAttrs.add(dnAttr);
            firstPageAttrs.add(groupClassAttr);
            LDAPAttribute emptyMemberAttr = new LDAPAttribute("member", new String[] {});
            firstPageAttrs.add(emptyMemberAttr);
            String[] firstPageMembers = new String[PAGE_SIZE];
            for (int i = 0; i < PAGE_SIZE; i++) {
                firstPageMembers[i] = String.format(LDAP_TEST_USER_FMT_DN, i);
            }
            LDAPAttribute memberPagesAttr = new LDAPAttribute(
                String.format("member;range=%d-%d", 0, (PAGE_SIZE - 1)), firstPageMembers);
            firstPageAttrs.add(memberPagesAttr);
            firstPageEntry = new LDAPEntry(LDAP_TEST_GROUP_DN, firstPageAttrs);
        }

        // the second entry contains an empty "member;3-*" attribute and the actual results in member;range=3-5
        {
            LDAPAttributeSet secondPageAttrs = new LDAPAttributeSet();
            secondPageAttrs.add(dnAttr);
            secondPageAttrs.add(groupClassAttr);
            // secondPageAttrs.add(emptyMemberAttr);
            LDAPAttribute secondMemberAttr = new LDAPAttribute(
                String.format("member;range=%d-%s", PAGE_SIZE, "*"), new String[] {});
            secondPageAttrs.add(secondMemberAttr);
            String[] secondPageMembers = new String[PAGE_SIZE];
            for (int i = 0; i < PAGE_SIZE; i++) {
                secondPageMembers[i] = String.format(LDAP_TEST_USER_FMT_DN, i + PAGE_SIZE);
            }
            LDAPAttribute secondMemberPagesAttr = new LDAPAttribute(
                String.format("member;range=%d-%d", PAGE_SIZE, (2 * PAGE_SIZE - 1)), secondPageMembers);
            secondPageAttrs.add(secondMemberPagesAttr);
            secondPageEntry = new LDAPEntry(LDAP_TEST_GROUP_DN, secondPageAttrs);
        }

        // the last entry contains an empty "member;6-*" attribute and the actual results in member;range=6-7
        {
            LDAPAttributeSet lastPageAttrs = new LDAPAttributeSet();
            lastPageAttrs.add(dnAttr);
            lastPageAttrs.add(groupClassAttr);
            // lastPageAttrs.add(emptyMemberAttr);
            LDAPAttribute lastPageMemberAttr = new LDAPAttribute(
                String.format("member;range=%d-%s", 2 * PAGE_SIZE, "*"), new String[] {});
            lastPageAttrs.add(lastPageMemberAttr);

            String[] lastPageMembers = new String[MEMBER_COUNT - 2 * PAGE_SIZE];
            for (int i = 0; i < lastPageMembers.length; i++) {
                lastPageMembers[i] = String.format(LDAP_TEST_USER_FMT_DN, i + 2 * PAGE_SIZE);
            }
            LDAPAttribute lastMemberPagesAttr = new LDAPAttribute(
                String.format("member;range=%d-%d", 2 * PAGE_SIZE, (MEMBER_COUNT - 1)), lastPageMembers);
            lastPageAttrs.add(lastMemberPagesAttr);

            lastPageEntry = new LDAPEntry(LDAP_TEST_GROUP_DN, lastPageAttrs);
        }

        // users are looked up via paginated search by member
        // note: if they are looked up as "group search", return nothing
        when(connection.searchPaginated(Mockito.anyString(), Mockito.anyInt(), Mockito.anyString(),
            Mockito.any(), Mockito.anyBoolean())).thenAnswer(new Answer<PagedLDAPSearchResults>()
            {

                @Override
                public PagedLDAPSearchResults answer(InvocationOnMock invocation) throws Throwable
                {
                    Object[] args = invocation.getArguments();

                    String baseDn = (String) args[0];
                    int searchScope = (int) args[1];
                    String filter = (String) args[2];

                    // check if the member attribute is considered a filter, despite being a dn
                    // in that case just return nothing
                    if (filter != null) {
                        Matcher filterMatch = LDAP_TEST_USER_DN_PATTERN.matcher(filter);
                        if (filterMatch.matches()) {
                            // System.err.println("tried to look up user as group search query; ignore");
                            return singleResultMock(null);
                        }
                    }

                    // then check if we got asked for a user
                    // these are looked up by dn
                    Matcher userMatch = LDAP_TEST_USER_DN_PATTERN.matcher(baseDn);
                    // XXX why subtree when it is a DN lookup?
                    assertEquals("search scope should be subtree", LDAPConnection.SCOPE_SUB, searchScope);
                    if (userMatch.matches()) {
                        String userCn = userMatch.group(1);
                        LDAPAttributeSet userAttrs = new LDAPAttributeSet();
                        userAttrs.add(new LDAPAttribute("dn", baseDn));
                        userAttrs.add(new LDAPAttribute(UID_ATTR, userCn));

                        requestedUserDNs.add(baseDn);
                        LDAPEntry singleUser = new LDAPEntry(baseDn, userAttrs);

                        return singleResultMock(singleUser);
                    }

                    for (int i = 0; i < args.length; i++) {
                        System.err.println("Arg " + i + " is " + args[i]);
                        if (args[i] instanceof String[]) {
                            String[] val = (String[]) args[i];
                            for (int j = 0; j < val.length; j++) {
                                System.err.println("  - [" + j + "] = {" + val[j] + '}');
                            }
                        }
                    }
                    fail("the dn [" + baseDn + "] did not match " + LDAP_TEST_USER_DN_PATTERN.pattern());

                    return singleResultMock(null);
                }
            });

        // groups and their members are looked up by direct ldap search (as it is basically a dn lookup)
        LDAPConnection ldapConnection = Mockito.mock(LDAPConnection.class);
        when(ldapConnection.search(Mockito.anyString(), Mockito.anyInt(), Mockito.anyString(), Mockito.any(),
            Mockito.anyBoolean())).thenAnswer(new Answer<LDAPSearchResults>()
            {

                @Override
                public LDAPSearchResults answer(InvocationOnMock invocation) throws Throwable
                {
                    Object[] args = invocation.getArguments();

                    String baseDn = (String) args[0];
                    int searchScope = (int) args[1];
                    String filter = (String) args[2];
                    String[] attrs = (String[]) args[3];

                    assertNull("expect null filter", filter);
                    assertFalse("expect not only types", (boolean) args[4]);
                    assertEquals("should have one requested attribute", 1, attrs.length);
                    String wantedAttr = attrs[0];

                    LDAPEntry result = null;
                    boolean emptyOk = false;
                    if (LDAP_TEST_GROUP_DN.equals(baseDn) && searchScope == LDAPConnection.SCOPE_BASE) {
                        Matcher members = LDAP_MEMBER_ATTR_PATTERN.matcher(wantedAttr);
                        if (members.matches()) {
                            String lowerLimit = members.group(1);
                            if (String.valueOf(PAGE_SIZE).equals(lowerLimit)) {
                                result = secondPageEntry;
                            } else if (String.valueOf(2 * PAGE_SIZE).equals(lowerLimit)) {
                                result = lastPageEntry;
                            } else {
                                // currently the code looks a last time for member;range=MEMBER_COUNT-*
                                // which should return an empty result.
                                // this might not be necessary, but is accepted here:
                                if (String.valueOf(MEMBER_COUNT).equals(lowerLimit)) {
                                    emptyOk = true;
                                } else {
                                    fail("unexpected start range : " + lowerLimit);
                                }
                            }
                        } else {
                            fail("no match for member attr [" + wantedAttr + "]");
                        }
                    }

                    if (result == null && !emptyOk) {
                        System.err.println("unexpected ldap search query; return empty result");
                        /*
                         * for debugging: show arguments
                         */
                        for (int i = 0; i < args.length; i++) {
                            System.err.println("SArg " + i + " is " + args[i]);
                            if (args[i] instanceof String[]) {
                                String[] val = (String[]) args[i];
                                for (int j = 0; j < val.length; j++) {
                                    System.err.println("    - [" + j + "] = {" + val[j] + '}');
                                }
                            }
                        }

                    }
                    return singleLdapResultMock(result);
                }

            });

        when(connection.getConnection()).thenReturn(ldapConnection);

        requestedUserDNs = new ArrayList<>();

        ldapUtils = new XWikiLDAPUtils(connection, configuration);
        ldapUtils.setUidAttributeName(UID_ATTR);
        ldapUtils.setBaseDN(LDAP_BASE_DN);
    }

    @Test
    public void testMemberAttributePaging() throws LDAPException
    {
        assertNotNull(ldapUtils);

        // result to fill in the members
        Map<String, String> memberResult = new HashMap<>();
        // and to fill in the groups
        List<String> subgroups = new ArrayList<String>();

        boolean result = ldapUtils.getGroupMembers(memberResult, subgroups, firstPageEntry, mockContext);
        assertTrue("result should be a group", result);

        assertEquals("expected members", MEMBER_COUNT, memberResult.size());
        assertEquals("expected members requested", MEMBER_COUNT, requestedUserDNs.size());
    }
}
