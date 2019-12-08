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
package org.xwiki.contrib.ldap.apachedsapi;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.MessageFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import javax.inject.Inject;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.message.SearchScope;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.cache.Cache;
import org.xwiki.cache.CacheException;
import org.xwiki.cache.config.CacheConfiguration;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.ldap.LDAPProfileXClass;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute;
import org.xwiki.contrib.ldap.apachedsapi.internal.DefaultXWikiLDAPConfigImpl;
import org.xwiki.contrib.ldap.apachedsapi.internal.LdapGroupsCache;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.rendering.syntax.Syntax;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.objects.classes.ListClass;
import com.xpn.xwiki.objects.classes.PropertyClass;

/**
 * LDAP utilities.
 * This variant uses the Apache DS API.
 * 
 * @version $Id$
 * @since 10.0
 */
@Component(roles = XWikiLDAPUtils.class)
public class XWikiLDAPUtils
{
    /**
     * Logging tool.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiLDAPUtils.class);

    /**
     * LDAP objectClass parameter.
     */
    private static final String LDAP_OBJECTCLASS = "objectClass";

    /**
     * The name of the XWiki group member field.
     */
    private static final String XWIKI_GROUP_MEMBERFIELD = "member";

    /**
     * The XWiki space where users are stored.
     */
    private static final String XWIKI_USER_SPACE = "XWiki";

    /**
     * The name of the LDAP object field "dn".
     */
    private static final String LDAP_FIELD_DN = "dn";

    @Inject
    private XWikiLdapConfig configuration;

    @Inject
    private LdapGroupsCache caches;


    public XWikiLDAPUtils()
    {
        // component constructor
    }

    /**
     * @return the LDAP base DN from where to executes LDAP queries.
     */
    public String getBaseDN()
    {
        return configuration.getBaseDN();
    }


    /**
     * @return the user search format string.
     */
    public String getUserSearchFormatString()
    {
        return configuration.getLDAPParam("ldap_user_search_fmt", "({0}={1})");
    }


    /**
     * @return true if sub groups should be resolved too
     */
    public boolean isResolveSubgroups()
    {
        return configuration.getLDAPParamAsLong("ldap_group_sync_resolve_subgroups", 1) == 1;
    }


    /**
     * Force to empty the group cache.
     */
    public void resetGroupCache()
    {
        caches.reset();
    }

    /**
     * @return get {@link DefaultXWikiLDAPConfigImpl}
     */
    public XWikiLdapConfig getConfiguration()
    {
        return this.configuration;
    }

    /**
     * Execute LDAP query to get all group's members.
     * 
     * @param groupDN the group to retrieve the members of and scan for subgroups.
     * @return the LDAP search result.
     * @throws XWikiLDAPException failed to execute LDAP query
     */
    private PagedLDAPSearchResults searchGroupsMembersByDN(XWikiLDAPConnection connection, String groupDN) throws LdapException
    {
        String[] attrs = new String[2 + configuration.getGroupMemberFields().size()];

        int i = 0;
        attrs[i++] = LDAP_OBJECTCLASS;
        for (String groupMember : configuration.getGroupMemberFields()) {
            attrs[i++] = groupMember;
        }

        // in case it's a organization unit get the users ids
        attrs[i] = configuration.getUidAttributeName();

        return connection.searchPaginated(groupDN, SearchScope.SUBTREE.getScope(), null, attrs, false);
    }

    /**
     * Execute LDAP query to get all group's members.
     * 
     * @param filter the LDAP filter to search with.
     * @return the LDAP search result.
     * @throws XWikiLDAPException failed to execute LDAP query
     */
    private PagedLDAPSearchResults searchGroupsMembersByFilter(XWikiLDAPConnection connection, String filter) throws LdapException
    {
        String[] attrs = new String[2 + configuration.getGroupMemberFields().size()];

        int i = 0;
        attrs[i++] = LDAP_OBJECTCLASS;
        for (String groupMember : configuration.getGroupMemberFields()) {
            attrs[i++] = groupMember;
        }

        // in case it's a organization unit get the users ids
        attrs[i] = configuration.getUidAttributeName();

        return connection.searchPaginated(getBaseDN(), SearchScope.SUBTREE.getScope(), filter, attrs, false);
    }

    /**
     * Extract group's members from provided LDAP search result.
     * 
     * @param searchAttributeList the LDAP search result.
     * @param memberMap the result: maps DN to member id.
     * @param subgroups return all the subgroups identified.
     * @param context the XWiki context.
     */
    private void getGroupMembersFromSearchResult(XWikiLDAPConnection connection, List<XWikiLDAPSearchAttribute> searchAttributeList,
        Map<String, String> memberMap, List<String> subgroups, XWikiContext context)
    {
        for (XWikiLDAPSearchAttribute searchAttribute : searchAttributeList) {
            String key = searchAttribute.name;
            if (configuration.getGroupMemberFields().contains(key.toLowerCase())) {

                // or subgroup
                String member = searchAttribute.value;

                if (StringUtils.isNotBlank(member)) {
                    // we check for subgroups recursive call to scan all subgroups and identify members
                    // and their uid
                    getGroupMembers(connection, member, memberMap, subgroups, context);
                }
            }
        }
    }

    /**
     * Extract group's members from provided LDAP search result.
     * 
     * @param ldapEntry the LDAP search result.
     * @param memberMap the result: maps DN to member id.
     * @param subgroups return all the subgroups identified.
     * @param context the XWiki context.
     * @since 9.3
     */
    private void getGroupMembersFromLDAPEntry(XWikiLDAPConnection connection, Entry ldapEntry, Map<String, String> memberMap,
        List<String> subgroups, XWikiContext context)
    {
        for (String memberField : configuration.getGroupMemberFields()) {
            LOGGER.debug("try attr [{}] for membership", memberField); // debug log, remove
            Attribute attribute = ldapEntry.get(memberField);
            if (attribute != null) {
                LOGGER.debug("we got an attr [{}]", attribute.getId()); // debug log, remove

                for (Value value : attribute) {
                    String member = value.getString();
                    LOGGER.debug("check value [{}]", member); // debug log, remove

                    if (StringUtils.isNotBlank(member)) {
                        LOGGER.debug("  |- Member value [{}] found. Trying to resolve it.", member);

                        // we check for subgroups recursive call to scan all subgroups and identify members
                        // and their uid
                        getGroupMembers(connection, member, memberMap, subgroups, context);
                    }
                }
                LOGGER.debug("check values [{}]: done", attribute.getId()); // debug log, remove
            }
        }
    }

    /**
     * Get all members of a given group based on the groupDN. If the group contains subgroups get these members as well.
     * Retrieve an identifier for each member.
     * 
     * @param groupDN the group to retrieve the members of and scan for subgroups.
     * @param memberMap the result: maps DN to member id.
     * @param subgroups all the subgroups identified.
     * @param searchAttributeList the groups members found in LDAP search.
     * @param context the XWiki context.
     * @return whether the groupDN is actually a group.
     */
    public boolean getGroupMembers(XWikiLDAPConnection connection, String groupDN, Map<String, String> memberMap, List<String> subgroups,
        List<XWikiLDAPSearchAttribute> searchAttributeList, XWikiContext context)
    {
        boolean isGroup = false;

        String id = null;

        for (XWikiLDAPSearchAttribute searchAttribute : searchAttributeList) {
            String key = searchAttribute.name;

            if (key.equalsIgnoreCase(LDAP_OBJECTCLASS)) {
                String objectName = searchAttribute.value;
                if (configuration.getGroupClasses().contains(objectName.toLowerCase())) {
                    isGroup = true;
                }
            } else if (key.equalsIgnoreCase(configuration.getUidAttributeName())) {
                id = searchAttribute.value;
            }
        }

        if (!isGroup) {
            if (id == null) {
                LOGGER.error("Could not find attribute [{}] for LDAP dn [{}]", configuration.getUidAttributeName(), groupDN);
            }

            if (!memberMap.containsKey(groupDN.toLowerCase())) {
                memberMap.put(groupDN.toLowerCase(), id == null ? "" : id.toLowerCase());
            }
        } else {
            // remember this group
            if (subgroups != null) {
                subgroups.add(groupDN.toLowerCase());
            }

            getGroupMembersFromSearchResult(connection, searchAttributeList, memberMap, subgroups, context);
        }

        return isGroup;
    }

    /**
     * Get all members of a given group based on the groupDN. If the group contains subgroups get these members as well.
     * Retrieve an identifier for each member.
     * 
     * @param memberMap the result: maps DN to member id.
     * @param subgroups all the subgroups identified.
     * @param ldapEntry the ldap entry returned by a search members found in LDAP search.
     * @param context the XWiki context.
     * @return whether the groupDN is actually a group.
     * @throws LDAPException error when parsing the provided LDAP entry
     * @since 3.3M1
     */
    public boolean getGroupMembers(XWikiLDAPConnection connection, Map<String, String> memberMap, List<String> subgroups, Entry ldapEntry,
        XWikiContext context) throws LdapException
    {
        boolean isGroup = false;

        final Collection<String> groupClasses = configuration.getGroupClasses();
        // Check if the entry is a group
        Attribute objClasses = ldapEntry.get(LDAP_OBJECTCLASS);
        if (objClasses != null) {
            for (Value value : objClasses) {
                String strValue = value.getString();
                if (groupClasses.contains(strValue.toLowerCase())) {
                    isGroup = true;
                    break;
                }
            }
        }

        // Get members or user id if it's a user

        final String lowerCaseDn = ldapEntry.getDn().getName().toLowerCase();
        if (isGroup) {
            // remember this group
            if (subgroups != null) {
                subgroups.add(lowerCaseDn);
            }

            getGroupMembersFromLDAPEntry(connection, ldapEntry, memberMap, subgroups, context);
        } else {
            Attribute uidAttribute = ldapEntry.get(configuration.getUidAttributeName());

            if (uidAttribute != null) {
                String uid = uidAttribute.getString();

                if (!memberMap.containsKey(lowerCaseDn)) {
                    memberMap.put(lowerCaseDn, uid.toLowerCase());
                }
            } else {
                LOGGER.debug("Probably a organization unit or a search");
            }
        }

        return isGroup;
    }

    /**
     * Get all members of a given group based on the groupDN. If the group contains subgroups get these members as well.
     * Retrieve an identifier for each member.
     * 
     * @param userOrGroup the group to retrieve the members of and scan for subgroups. Can be
     *            <ul>
     *            <li>a group DN</li>
     *            <li>a user DN</li>
     *            <li>a group id</li>
     *            <li>a user id</li>
     *            </ul>
     * @param memberMap the result: maps DN to member id.
     * @param subgroups all the subgroups identified.
     * @param context the XWiki context.
     * @return whether the identifier is actually a group.
     */
    public boolean getGroupMembers(XWikiLDAPConnection connection, String userOrGroup, Map<String, String> memberMap, List<String> subgroups,
        XWikiContext context)
    {
        boolean isGroup = false;

        int nbMembers = memberMap.size();
        if (XWikiLDAPUtils.isValidDN(userOrGroup)) {
            LOGGER.debug("[{}] is a valid DN, lets try to get corresponding entry.", userOrGroup);

            // Stop there if passed used is already a resolved member
            if (memberMap.containsKey(userOrGroup.toLowerCase())) {
                LOGGER.debug("[{}] is already resolved", userOrGroup);

                return false;
            }

            // Stop there if subgroup resolution is disabled
            if (!subgroups.isEmpty() && !isResolveSubgroups()) {
                LOGGER.debug("Group members resolve is disabled to add [{}] as group member directly", userOrGroup);

                memberMap.put(userOrGroup.toLowerCase(), userOrGroup);

                return false;
            }

            isGroup = getGroupMembersFromDN(connection, userOrGroup, memberMap, subgroups, context);
        }

        if (!isGroup && nbMembers == memberMap.size()) {
            // Probably not a DN, lets try as filter or id
            LOGGER.debug("Looks like [{}] is not a DN, lets try filter or id", userOrGroup);

            try {
                // Test if it's valid LDAP filter syntax
                FilterParser.parse(userOrGroup);
                isGroup = getGroupMembersFromFilter(connection, userOrGroup, memberMap, subgroups, context);
            } catch (ParseException e) {
                LOGGER.debug("[{}] is not a valid LDAP filter, lets try id", userOrGroup);

                // Not a valid filter, try as uid
                List<XWikiLDAPSearchAttribute> searchAttributeList =
                    searchUserAttributesByUid(connection, userOrGroup, new String[] { LDAP_FIELD_DN });

                if (searchAttributeList != null && !searchAttributeList.isEmpty()) {
                    String dn = searchAttributeList.get(0).value;

                    // Stop there if passed used is already a resolved member
                    if (memberMap.containsKey(dn.toLowerCase())) {
                        LOGGER.debug("[{}] is already resolved", dn);

                        return false;
                    }

                    // Stop there if subgroup resolution is disabled
                    if (!subgroups.isEmpty() && !isResolveSubgroups()) {
                        LOGGER.debug("Group members resolve is disabled to add [{}] as group member directly", dn);

                        memberMap.put(dn.toLowerCase(), dn);

                        return false;
                    }

                    isGroup = getGroupMembers(connection, dn, memberMap, subgroups, context);
                }
            }
        }

        return isGroup;
    }

    /**
     * Get all members of a given group based on the groupDN. If the group contains subgroups get these members as well.
     * Retrieve an identifier for each member.
     * 
     * @param userOrGroupDN the group DN to retrieve the members from or the user DN to add in the members map.
     * @param memberMap the result: maps DN to member id.
     * @param subgroups all the subgroups identified.
     * @param context the XWiki context.
     * @return whether the provided DN is actually a group or not.
     */
    public boolean getGroupMembersFromDN(XWikiLDAPConnection connection, String userOrGroupDN, Map<String, String> memberMap, List<String> subgroups,
        XWikiContext context)
    {
        boolean isGroup = false;

        // break out if there is a loop of groups
        if (subgroups != null && subgroups.contains(userOrGroupDN.toLowerCase())) {
            LOGGER.debug("[{}] groups already resolved.", userOrGroupDN);

            return true;
        }

        PagedLDAPSearchResults result;
        try {
            result = searchGroupsMembersByDN(connection, userOrGroupDN);
        } catch (LdapException e) {
            LOGGER.debug("Failed to search for [{}]", userOrGroupDN, e);

            return false;
        }

        try {
            isGroup = getGroupMembersSearchResult(result, memberMap, subgroups, context);
        } finally {
            if (result.hasMore()) {
                try {
                    result.close();
                } catch (LdapException e) {
                    LOGGER.debug("LDAP Search clean up failed", e);
                }
            }
        }

        return isGroup;
    }

    /**
     * Get all members of a given group based on the groupDN. If the group contains subgroups get these members as well.
     * Retrieve an identifier for each member.
     * 
     * @param filter the LDAP filter to search with.
     * @param memberMap the result: maps DN to member id.
     * @param subgroups all the subgroups identified.
     * @param context the XWiki context.
     * @return whether the provided DN is actually a group or not.
     */
    public boolean getGroupMembersFromFilter(XWikiLDAPConnection connection, String filter, Map<String, String> memberMap, List<String> subgroups,
        XWikiContext context)
    {
        boolean isGroup = false;

        PagedLDAPSearchResults result;
        try {
            result = searchGroupsMembersByFilter(connection, filter);
        } catch (LdapException e) {
            LOGGER.debug("Failed to search for [{}]", filter, e);

            return false;
        }

        try {
            isGroup = getGroupMembersSearchResult(result, memberMap, subgroups, context);
        } finally {
            if (result.hasMore()) {
                try {
                    result.close();
                } catch (LdapException e) {
                    LOGGER.debug("LDAP Search clean up failed", e);
                }
            }
        }

        return isGroup;
    }

 
    /**
     * Get all members of a given group based on the the result of a LDAP search. If the group contains subgroups get
     * these members as well. Retrieve an identifier for each member.
     * 
     * @param result the result of a LDAP search.
     * @param memberMap the result: maps DN to member id.
     * @param subgroups all the subgroups identified.
     * @param context the XWiki context.
     * @return whether the provided DN is actually a group or not.
     */
    public boolean getGroupMembersSearchResult(PagedLDAPSearchResults result, Map<String, String> memberMap,
        List<String> subgroups, XWikiContext context)
    {
        boolean isGroup = false;

        Entry resultEntry = null;
        // For some weird reason result.hasMore() is always true before the first call to next() even if nothing is
        // found
        if (result.hasMore()) {
            try {
                resultEntry = result.next();
            } catch (LdapException e) {
                LOGGER.debug("Failed to get group members", e);
            }
        }

        if (resultEntry != null) {
            do {
                try {
                    isGroup |= getGroupMembers(result.getConnection(), memberMap, subgroups, resultEntry, context);

                    resultEntry = result.hasMore() ? result.next() : null;
                } catch (LdapException e) {
                    LOGGER.debug("Failed to get group members", e);
                }
            } while (resultEntry != null);
        }

        return isGroup;
    }

    /**
     * Get group members from cache or update it from LDAP if it is not already cached.
     * 
     * @param groupDN the name of the group.
     * @param context the XWiki context.
     * @return the members of the group.
     * @throws XWikiException error when getting the group cache.
     */
    public Map<String, String> getGroupMembers(XWikiLDAPConnection connection, String groupDN, XWikiContext context) throws XWikiException
    {
        Map<String, String> groupMembers = null;

        Cache<Map<String, String>> cache;
        try {
            cache = caches.getGroupCache();

            synchronized (cache) {
                groupMembers = cache.get(groupDN);

                if (groupMembers == null) {
                    Map<String, String> members = new HashMap<>();

                    LOGGER.debug("Retrieving Members of the group [{}]", groupDN);

                    boolean isGroup = getGroupMembers(connection, groupDN, members, new ArrayList<String>(), context);

                    if (isGroup || !members.isEmpty()) {
                        groupMembers = members;
                        cache.set(groupDN, groupMembers);
                    }
                } else {
                    LOGGER.debug("Found cache entry for group [{}]", groupDN);
                }
            }
        } catch (CacheException e) {
            LOGGER.error("Unknown error with cache", e);
        }

        LOGGER.debug("Found group [{}] members [{}]", groupDN, groupMembers);

        return groupMembers;
    }

    /**
     * Check if provided DN is in provided LDAP group.
     * 
     * @param memberDN the DN to find in the provided group.
     * @param groupDN the DN of the group where to search.
     * @param context the XWiki context.
     * @return true if provided members in the provided group.
     * @throws XWikiException error when searching for group members.
     */
    public boolean isMemberOfGroup(XWikiLDAPConnection connection, String memberDN, String groupDN, XWikiContext context) throws XWikiException
    {
        Map<String, String> groupMembers = getGroupMembers(connection, groupDN, context);

        if (groupMembers != null) {
            for (String memberDNEntry : groupMembers.keySet()) {
                if (memberDNEntry.equals(memberDN.toLowerCase())) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if provided DN is in one of the provided LDAP groups.
     * 
     * @param memberDN the DN to find in the provided groups.
     * @param groupDNList the list of DN of the groups where to search.
     * @param context the XWiki context.
     * @return true if provided members in one of the provided groups.
     * @throws XWikiException error when searching for group members.
     */
    public boolean isMemberOfGroups(XWikiLDAPConnection connection, String memberDN, Collection<String> groupDNList, XWikiContext context)
        throws XWikiException
    {
        for (String groupDN : groupDNList) {
            if (isMemberOfGroup(connection, memberDN, groupDN, context)) {
                return true;
            }
        }

        return false;
    }


    /**
     * Locates the user in the Map: either the user is a value or the key starts with the LDAP syntax.
     * 
     * @param userName the name of the user.
     * @param groupMembers the members of LDAP group.
     * @return the full user name.
     */
    protected String findUidInGroup(String userName, Map<String, String> groupMembers)
    {
        Pattern ldapuserPattern = Pattern
            .compile("^" + Pattern.quote(configuration.getUidAttributeName()) + "=" + Pattern.quote(userName.toLowerCase()) + " *,");

        for (Map.Entry<String, String> entry : groupMembers.entrySet()) {
            // implementing it case-insensitive for now
            if (userName.equalsIgnoreCase(entry.getValue()) || ldapuserPattern.matcher(entry.getKey()).find()) {
                return entry.getKey();
            }
        }

        return null;
    }

    /**
     * Locates the user in the Map: either the user is a value or the key starts with the LDAP syntax.
     * 
     * @param userDN the name of the user.
     * @param groupMembers the members of LDAP group.
     * @return the full user name.
     */
    protected String findDNInGroup(String userDN, Map<String, String> groupMembers)
    {
        if (groupMembers.containsKey(userDN.toLowerCase())) {
            return userDN;
        }

        return null;
    }

    /**
     * Check if user is in provided LDAP group and return source DN.
     * 
     * @param uid the user name.
     * @param dn the user dn.
     * @param groupDN the LDAP group DN.
     * @param context the XWiki context.
     * @return LDAP user's DN if the user is in the LDAP group, null otherwise.
     * @throws XWikiException error when getting the group cache.
     */
    public String isInGroup(XWikiLDAPConnection connection, String uid, String dn, String groupDN, XWikiContext context) throws XWikiException
    {
        String userDN = null;

        if (groupDN.length() > 0) {
            Map<String, String> groupMembers = null;

            try {
                groupMembers = getGroupMembers(connection, groupDN, context);
            } catch (Exception e) {
                // Ignore exception to allow negative match for exclusion
                LOGGER.debug("Unable to retrieve group members of group [{}]", groupDN, e);
            }

            // no match when a user does not have access to the group
            if (groupMembers != null) {
                // check if user is in the list
                if (dn == null) {
                    userDN = findUidInGroup(uid, groupMembers);
                } else {
                    userDN = findDNInGroup(dn, groupMembers);
                }

                LOGGER.debug("Found user dn in user group [{}]", userDN);
            }
        }

        return userDN;
    }

    /**
     * Check if user is in provided LDAP group and return source DN.
     * 
     * @param userName the user name.
     * @param groupDN the LDAP group DN.
     * @param context the XWiki context.
     * @return LDAP user's DN if the user is in the LDAP group, null otherwise.
     * @throws XWikiException error when getting the group cache.
     */
    public String isUidInGroup(XWikiLDAPConnection connection, String userName, String groupDN, XWikiContext context) throws XWikiException
    {
        return isInGroup(connection, userName, null, groupDN, context);
    }

    /**
     * Check if the DN is in provided LDAP group and return source DN.
     * 
     * @param dn the user DN.
     * @param groupDN the LDAP group DN.
     * @param context the XWiki context.
     * @return LDAP user's DN if the user is in the LDAP group, null otherwise.
     * @throws XWikiException error when getting the group cache.
     */
    public String isDNInGroup(XWikiLDAPConnection connection,String dn, String groupDN, XWikiContext context) throws XWikiException
    {
        return isInGroup(connection, null, dn, groupDN, context);
    }

    /**
     * @param uid the unique identifier of the user in the LDAP server.
     * @param attributeNameTable the names of the LDAP user attributes to query.
     * @return the found LDAP attributes.
     */
    public List<XWikiLDAPSearchAttribute> searchUserAttributesByUid(XWikiLDAPConnection connection, String uid, String[] attributeNameTable)
    {
        // search for the user in LDAP
        String filter = MessageFormat.format(this.getUserSearchFormatString(),
            XWikiLDAPConnection.escapeLDAPSearchFilter(this.configuration.getUidAttributeName()),
            XWikiLDAPConnection.escapeLDAPSearchFilter(uid));

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Searching for the user in LDAP: user [{}] base [{}] query [{}] uid [{}]", uid, this.getBaseDN(),
                filter, this.configuration.getUidAttributeName());
        }

        return connection.searchLDAP(this.getBaseDN(), filter, attributeNameTable, SearchScope.SUBTREE.getScope());
    }

    /**
     * @param uid the unique identifier of the user in the LDAP server.
     * @return the user DN, return null if no user was found.
     * @since 1.6M2
     */
    public String searchUserDNByUid(XWikiLDAPConnection connection, String uid)
    {
        String userDN = null;

        List<XWikiLDAPSearchAttribute> searchAttributes =
            searchUserAttributesByUid(connection, uid, new String[] { LDAP_FIELD_DN });

        if (searchAttributes != null && !searchAttributes.isEmpty()) {
            userDN = searchAttributes.get(0).value;
        }

        return userDN;
    }

    /**
     * Update or create XWiki user base on LDAP.
     * 
     * @param userProfile the name of the user.
     * @param ldapDn the LDAP user DN.
     * @param authInput the input used to identify the user
     * @param attributes the attributes of the LDAP user.
     * @param context the XWiki context.
     * @return the XWiki user document
     * @throws XWikiException error when updating or creating XWiki user.
     */
    public XWikiDocument syncUser(XWikiLDAPConnection connection, XWikiDocument userProfile, List<XWikiLDAPSearchAttribute> attributes, String ldapDn,
        String authInput, XWikiContext context) throws XWikiException
    {
        // check if we have to create the user
        if (userProfile == null || userProfile.isNew()
            || this.configuration.getLDAPParam("ldap_update_user", "0").equals("1")) {
            LOGGER.debug("LDAP attributes will be used to update XWiki attributes.");

            // Get attributes from LDAP if we don't already have them

            if (attributes == null) {
                // didn't get attributes before, so do it now
                attributes =
                    connection.searchLDAP(ldapDn, null, getAttributeNameTable(context), SearchScope.OBJECT.getScope());
            }

            if (attributes == null) {
                LOGGER.error("Can't find any attributes for user [{}]", ldapDn);
            }

            // Load XWiki user document if we don't already have them

            if (userProfile == null) {
                userProfile = getAvailableUserProfile(attributes, context);
            }

            if (userProfile.isNew()) {
                LOGGER.debug("Creating new XWiki user based on LDAP attribues located at [{}]", ldapDn);

                createUserFromLDAP(userProfile, attributes, ldapDn, authInput, context);

                LOGGER.debug("New XWiki user created: [{}]", userProfile.getDocumentReference());
            } else {
                LOGGER.debug("Updating existing user with LDAP attribues located at [{}]", ldapDn);

                try {
                    updateUserFromLDAP(userProfile, attributes, ldapDn, authInput, context);
                } catch (XWikiException e) {
                    LOGGER.error("Failed to synchronise user's informations", e);
                }
            }
        }

        return userProfile;
    }

    /**
     * Not everything is supported in XWiki user page name so clean clean it a bit.
     * 
     * @param pageName the name of the XWiki user page
     * @return the clean name of the XWiki user page
     * @since 9.0
     */
    public static String cleanXWikiUserPageName(String pageName)
    {
        // Protected from characters not well supported in user page name depending on the version of XWiki
        String cleanPageName = StringUtils.remove(pageName, '.');
        cleanPageName = StringUtils.remove(cleanPageName, ' ');
        cleanPageName = StringUtils.remove(cleanPageName, '/');

        return cleanPageName;
    }

    /**
     * Synchronize user XWiki membership with it's LDAP membership.
     * 
     * @param xwikiUserName the name of the user.
     * @param userDN the LDAP DN of the user.
     * @param groupMappings the mapping between XWiki groups names and LDAP groups names.
     * @param context the XWiki context.
     * @throws XWikiException error when synchronizing user membership.
     */
    public void syncGroupsMembership(XWikiLDAPConnection connection, String xwikiUserName, String userDN, Map<String, Set<String>> groupMappings,
        XWikiContext context) throws XWikiException
    {
        LOGGER.debug("Updating group membership for the user [{}]", xwikiUserName);

        Collection<String> xwikiUserGroupList =
            context.getWiki().getGroupService(context).getAllGroupsNamesForMember(xwikiUserName, 0, 0, context);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("The user belongs to following XWiki groups: ");
            for (String userGroupName : xwikiUserGroupList) {
                LOGGER.debug(userGroupName);
            }
        }

        // go through mapped groups to locate the user
        for (Map.Entry<String, Set<String>> entry : groupMappings.entrySet()) {
            String xwikiGroupName = entry.getKey();
            Set<String> groupDNSet = entry.getValue();

            if (xwikiUserGroupList.contains(xwikiGroupName)) {
                if (!this.isMemberOfGroups(connection, userDN, groupDNSet, context)) {
                    removeUserFromXWikiGroup(xwikiUserName, xwikiGroupName, context);
                }
            } else {
                if (this.isMemberOfGroups(connection, userDN, groupDNSet, context)) {
                    addUserToXWikiGroup(xwikiUserName, xwikiGroupName, context);
                }
            }
        }

        if (LOGGER.isDebugEnabled()) { // XXX: debug output: remove ?
            Collection<String> xwikiUserGroupListAfterSynch =
                context.getWiki().getGroupService(context).getAllGroupsNamesForMember(xwikiUserName, 0, 0, context);

            LOGGER.debug("After sync membership the user belongs to following XWiki groups:");
            for (String userGroupName : xwikiUserGroupListAfterSynch) {
                LOGGER.debug(userGroupName);
            }
        }
    }

    /**
     * @param context the XWiki context.
     * @return the LDAP user attributes names.
     */
    public String[] getAttributeNameTable(XWikiContext context)
    {
        LOGGER.debug("Getting the list of user fields to synchronize");

        String[] attributeNameTable = null;

        List<String> attributeNameList = new ArrayList<>();
        this.configuration.getUserMappings(attributeNameList);

        // Add avatar field
        if (this.configuration.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_UPDATE_PHOTO, "0").equals("1")) {
            LOGGER.debug("LDAP avatar photo synchronisation is enabled");

            String ldapPhotoAttribute = this.configuration.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_PHOTO_ATTRIBUTE,
                XWikiLDAPConfig.DEFAULT_PHOTO_ATTRIBUTE);

            LOGGER.debug("LDAP avatar photo field name: {}", ldapPhotoAttribute);

            attributeNameList.add(ldapPhotoAttribute);
        } else {
            LOGGER.debug("LDAP avatar photo synchronisation is disabled");
        }

        int lsize = attributeNameList.size();
        if (lsize > 0) {
            attributeNameTable = attributeNameList.toArray(new String[lsize]);
        }

        LOGGER.debug("LDAP user fields to synchronize: {}", attributeNameList);

        return attributeNameTable;
    }

    private void set(List<XWikiLDAPSearchAttribute> searchAttributes, Map<String, String> userMappings,
        BaseObject userObject, XWikiContext xcontext) throws XWikiException
    {
        if (searchAttributes != null) {
            // Convert LDAP attributes to a map usable with BaseClass#fromValueMap
            Map<String, Object> map = toMap(searchAttributes, userMappings, xcontext);

            // Set properties in the user object
            userObject.getXClass(xcontext).fromMap(map, userObject);
        }
    }

    private Map<String, Object> toMap(List<XWikiLDAPSearchAttribute> searchAttributes, Map<String, String> userMappings,
        XWikiContext xcontext) throws XWikiException
    {
        BaseClass userClass = xcontext.getWiki().getUserClass(xcontext);

        Map<String, Object> map = new HashMap<>();
        if (searchAttributes != null) {
            for (XWikiLDAPSearchAttribute lattr : searchAttributes) {
                String lval = lattr.value;
                String xattr = userMappings.get(lattr.name.toLowerCase());

                if (xattr == null) {
                    continue;
                }

                PropertyClass pclass = (PropertyClass) userClass.get(xattr);

                if (pclass != null) {
                    if (pclass instanceof ListClass) {
                        Object mapValue = map.get(xattr);
                        if (mapValue == null) {
                            mapValue = new ArrayList<>();
                            map.put(xattr, mapValue);
                        }
                        ((List) mapValue).add(lval);
                    } else {
                        map.put(xattr, lval);
                    }
                }
            }
        }

        return map;
    }

    /**
     * Create an XWiki user and set all mapped attributes from LDAP to XWiki attributes.
     * 
     * @param userProfile the XWiki user profile.
     * @param attributes the attributes.
     * @param ldapDN the LDAP DN of the user.
     * @param ldapUid the LDAP unique id of the user.
     * @param context the XWiki context.
     * @throws XWikiException error when creating XWiki user.
     */
    protected void createUserFromLDAP(XWikiDocument userProfile, List<XWikiLDAPSearchAttribute> attributes,
        String ldapDN, String ldapUid, XWikiContext context) throws XWikiException
    {
        Map<String, String> userMappings = this.configuration.getUserMappings(null);

        LOGGER.debug("Start first synchronization of LDAP profile [{}] with new user profile based on mapping [{}]",
            attributes, userMappings);

        Map<String, Object> map = toMap(attributes, userMappings, context);

        // Mark user active
        map.put("active", "1");

        XWikiException createUserError = null;
        try {
            context.getWiki().createUser(userProfile.getDocumentReference().getName(), map, context);
        } catch (XWikiException e) {
            createUserError = e;
        }

        XWikiDocument createdUserProfile = context.getWiki().getDocument(userProfile.getDocumentReference(), context);
        if (createdUserProfile.isNew()) {
            if (createUserError != null) {
                throw createUserError;
            } else {
                throw new XWikiLDAPException(
                    "User [" + userProfile.getDocumentReference() + "] hasn't been created for unknown reason");
            }
        } else if (createUserError != null) {
            // Whatever crashed the createUser API it was after the actual user creation so let's log an error and
            // continue
            LOGGER.error("Unexpected error when creating user [{}]", userProfile.getDocumentReference(),
                createUserError);
        }

        // Update ldap profile object
        LDAPProfileXClass ldapXClass = new LDAPProfileXClass(context);

        // Add user photo from LDAP
        updateAvatarFromLdap(attributes, createdUserProfile, context);

        if (ldapXClass.updateLDAPObject(createdUserProfile, ldapDN, ldapUid)) {
            context.getWiki().saveDocument(createdUserProfile, "Created user profile from LDAP server", context);
        }
    }

    /**
     * Sets attributes on the user object based on attribute values provided by the LDAP.
     * 
     * @param userProfile the XWiki user profile document.
     * @param attributes the attributes of the LDAP user to update.
     * @param ldapDN the DN of the LDAP user to update
     * @param ldapUid value of the unique identifier for the user to update.
     * @param context the XWiki context.
     * @throws XWikiException error when updating XWiki user.
     */
    protected void updateUserFromLDAP(XWikiDocument userProfile, List<XWikiLDAPSearchAttribute> attributes,
        String ldapDN, String ldapUid, XWikiContext context) throws XWikiException
    {
        Map<String, String> userMappings = this.configuration.getUserMappings(null);

        BaseClass userClass = context.getWiki().getUserClass(context);

        BaseObject userObj = userProfile.getXObject(userClass.getDocumentReference());

        LOGGER.debug("Start synchronization of LDAP profile [{}] with existing user profile based on mapping [{}]",
            attributes, userMappings);

        // Clone the user object
        BaseObject clonedUser = userObj.clone();

        // Apply all attributes to the clone
        set(attributes, userMappings, clonedUser, context);

        // Let BaseObject#apply tell us if something changed or not
        boolean needsUpdate = userObj.apply(clonedUser, false);

        // Sync user photo with LDAP
        needsUpdate |= updateAvatarFromLdap(attributes, userProfile, context);

        // Update ldap profile object
        LDAPProfileXClass ldaXClass = new LDAPProfileXClass(context);
        needsUpdate |= ldaXClass.updateLDAPObject(userProfile, ldapDN, ldapUid);

        if (needsUpdate) {
            context.getWiki().saveDocument(userProfile, "Synchronized user profile with LDAP server", true, context);
        }
    }

    /**
     * Sync user avatar with LDAP
     * 
     * @param ldapUid value of the unique identifier for the user to update.
     * @param userProfile the XWiki user profile document.
     * @param context the XWiki context.
     * @return true if avatar was updated, false otherwise.
     * @throws XWikiException
     */
    private boolean updateAvatarFromLdap(List<XWikiLDAPSearchAttribute> ldapAttributes, XWikiDocument userProfile,
        XWikiContext context) throws XWikiException
    {
        // Check if avatar update is enabled
        if (!this.configuration.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_UPDATE_PHOTO, "0").equals("1")) {
            return false;
        }

        BaseClass userClass = context.getWiki().getUserClass(context);
        BaseObject userObj = userProfile.getXObject(userClass.getDocumentReference());

        // Get current user avatar
        String userAvatar = userObj.getStringValue("avatar");
        XWikiAttachment currentPhoto = null;
        if (userAvatar != null) {
            currentPhoto = userProfile.getAttachment(userAvatar);
        }

        // Get properties
        String photoAttachmentName =
            this.configuration.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_PHOTO_ATTACHMENT_NAME, "ldapPhoto");

        // Proceed only if any of conditions are true:
        // 1. User do not have avatar currently
        // 2. User have avatar and avatar file name is equals to PREF_LDAP_PHOTO_ATTACHMENT_NAME
        if (StringUtils.isEmpty(userAvatar) || photoAttachmentName.equals(FilenameUtils.getBaseName(userAvatar))
            || currentPhoto == null) {
            // Obtain photo from LDAP
            byte[] ldapPhoto = null;
            if (ldapAttributes != null) {
                String ldapPhotoAttribute = this.configuration.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_PHOTO_ATTRIBUTE,
                    XWikiLDAPConfig.DEFAULT_PHOTO_ATTRIBUTE);

                // searchUserAttributesByUid method may return «dn» as 1st element
                // Let's iterate over array and search ldapPhotoAttribute
                for (XWikiLDAPSearchAttribute attribute : ldapAttributes) {
                    if (attribute.name.equals(ldapPhotoAttribute)) {
                        ldapPhoto = attribute.byteValue;
                    }
                }
            }

            if (ldapPhoto != null) {
                ByteArrayInputStream ldapPhotoInputStream = new ByteArrayInputStream(ldapPhoto);
                // Try to guess image type
                String ldapPhotoType = guessImageType(ldapPhotoInputStream);
                ldapPhotoInputStream.reset();

                if (ldapPhotoType != null) {
                    String photoAttachmentFullName = photoAttachmentName + "." + ldapPhotoType.toLowerCase();

                    if (!StringUtils.isEmpty(userAvatar) && currentPhoto != null) {
                        try {
                            // Compare current xwiki avatar and LDAP photo
                            if (!IOUtils.contentEquals(currentPhoto.getContentInputStream(context),
                                ldapPhotoInputStream)) {
                                ldapPhotoInputStream.reset();

                                // Store photo
                                return addAvatarToProfile(userProfile, context, ldapPhotoInputStream,
                                    photoAttachmentFullName);
                            }
                        } catch (IOException ex) {
                            LOGGER.error(ex.getMessage());
                        }
                    } else if (addAvatarToProfile(userProfile, context, ldapPhotoInputStream,
                        photoAttachmentFullName)) {
                        PropertyClass avatarProperty = (PropertyClass) userClass.getField("avatar");
                        userObj.safeput("avatar", avatarProperty.fromString(photoAttachmentFullName));

                        return true;
                    }
                } else {
                    LOGGER.info("Unable to determine LDAP photo image type.");
                }
            } else if (currentPhoto != null) {
                // Remove current avatar
                PropertyClass avatarProperty = (PropertyClass) userClass.getField("avatar");
                userObj.safeput("avatar", avatarProperty.fromString(""));

                return true;
            }
        }

        return false;
    }

    /**
     * Add photo to user profile as attachment.
     * 
     * @param userProfile the XWiki user profile document.
     * @param context the XWiki context.
     * @param photoInputStream InputStream containing photo.
     * @param attachmentName attachment name for provided photo.
     * @return true if photo was saved to user profile, false otherwise.
     */
    private boolean addAvatarToProfile(XWikiDocument userProfile, XWikiContext context, InputStream photoInputStream,
        String attachmentName)
    {
        XWikiAttachment attachment;
        try {
            attachment = userProfile.addAttachment(attachmentName, photoInputStream, context);
        } catch (IOException | XWikiException ex) {
            LOGGER.error(ex.getMessage());
            return false;
        }

        attachment.resetMimeType(context);

        return true;
    }

    /**
     * Guess image type of InputStream.
     * 
     * @param imageInputStream InputStream containing image.
     * @return type of image as String.
     */
    private String guessImageType(InputStream imageInputStream)
    {
        ImageInputStream imageStream;
        try {
            imageStream = ImageIO.createImageInputStream(imageInputStream);
        } catch (IOException ex) {
            LOGGER.error(ex.getMessage());
            return null;
        }

        Iterator<ImageReader> it = ImageIO.getImageReaders(imageStream);
        if (!it.hasNext()) {
            LOGGER.warn("No image readers found for provided stream.");
            return null;
        }

        ImageReader imageReader = it.next();
        imageReader.setInput(imageStream);

        try {
            return imageReader.getFormatName();
        } catch (IOException ex) {
            LOGGER.error(ex.getMessage());
            return null;
        } finally {
            imageReader.dispose();
        }
    }

    /**
     * Add user name to provided XWiki group.
     * 
     * @param xwikiUserName the full name of the user.
     * @param groupName the name of the group.
     * @param context the XWiki context.
     */
    // TODO move this methods in a toolkit for all platform.
    protected void addUserToXWikiGroup(String xwikiUserName, String groupName, XWikiContext context)
    {
        try {
            LOGGER.debug("Adding user [{}] to xwiki group [{}]", xwikiUserName, groupName);

            BaseClass groupClass = context.getWiki().getGroupClass(context);

            // Get document representing group
            XWikiDocument groupDoc = context.getWiki().getDocument(groupName, context);

            synchronized (groupDoc) {
                // Make extra sure the group cannot contain duplicate (even if this method is not supposed to be called
                // in this case)
                List<BaseObject> xobjects = groupDoc.getXObjects(groupClass.getDocumentReference());
                if (xobjects != null) {
                    for (BaseObject memberObj : xobjects) {
                        if (memberObj != null) {
                            String existingMember = memberObj.getStringValue(XWIKI_GROUP_MEMBERFIELD);
                            if (existingMember != null && existingMember.equals(xwikiUserName)) {
                                LOGGER.warn("User [{}] already exist in group [{}]", xwikiUserName,
                                    groupDoc.getDocumentReference());
                                return;
                            }
                        }
                    }
                }

                // Add a member object to document
                BaseObject memberObj = groupDoc.newXObject(groupClass.getDocumentReference(), context);
                Map<String, String> map = new HashMap<>();
                map.put(XWIKI_GROUP_MEMBERFIELD, xwikiUserName);
                groupClass.fromMap(map, memberObj);

                // If the document is new, set its content
                if (groupDoc.isNew()) {
                    groupDoc.setSyntax(Syntax.XWIKI_2_0);
                    groupDoc.setContent("{{include reference='XWiki.XWikiGroupSheet' /}}");
                }

                // Save modifications
                context.getWiki().saveDocument(groupDoc, context);
            }

            LOGGER.debug("Finished adding user [{}] to xwiki group [{}]", xwikiUserName, groupName);
        } catch (Exception e) {
            LOGGER.error("Failed to add a user [{}] to a group [{}]", xwikiUserName, groupName, e);
        }
    }

    /**
     * Remove user name from provided XWiki group.
     * 
     * @param xwikiUserName the full name of the user.
     * @param groupName the name of the group.
     * @param context the XWiki context.
     */
    // TODO move this methods in a toolkit for all platform.
    protected void removeUserFromXWikiGroup(String xwikiUserName, String groupName, XWikiContext context)
    {
        try {
            BaseClass groupClass = context.getWiki().getGroupClass(context);

            // Get the XWiki document holding the objects comprising the group membership list
            XWikiDocument groupDoc = context.getWiki().getDocument(groupName, context);

            synchronized (groupDoc) {
                // Get and remove the specific group membership object for the user
                BaseObject groupObj =
                    groupDoc.getXObject(groupClass.getDocumentReference(), XWIKI_GROUP_MEMBERFIELD, xwikiUserName);
                if (groupObj != null) {
                    groupDoc.removeXObject(groupObj);
                }

                // Save modifications
                context.getWiki().saveDocument(groupDoc, context);
            }
        } catch (Exception e) {
            LOGGER.error("Failed to remove a user from a group [{}] group: [{}]", xwikiUserName, groupName, e);
        }
    }

    /**
     * @param validXWikiUserName the valid XWiki name of the user to get the profile for. Used for fast lookup relying
     *            on the document cache before doing a database search.
     * @param userId the UID to get the profile for
     * @param context the XWiki context
     * @return the XWiki document of the user with the passed UID
     * @throws XWikiException when a problem occurs while retrieving the user profile
     */
    public XWikiDocument getUserProfileByUid(String validXWikiUserName, String userId, XWikiContext context)
        throws XWikiException
    {
        LDAPProfileXClass ldapXClass = new LDAPProfileXClass(context);

        // Try default profile name (generally in the cache)
        XWikiDocument userProfile;
        if (validXWikiUserName != null) {
            userProfile = context.getWiki()
                .getDocument(new DocumentReference(context.getWikiId(), XWIKI_USER_SPACE, validXWikiUserName), context);
        } else {
            userProfile = null;
        }

        if (!userId.equalsIgnoreCase(ldapXClass.getUid(userProfile))) {
            // Search for existing profile with provided uid
            userProfile = ldapXClass.searchDocumentByUid(userId);

            // Resolve default profile patch of an uid
            if (userProfile == null && validXWikiUserName != null) {
                userProfile = getAvailableUserProfile(validXWikiUserName, context);
            }
        }

        return userProfile;
    }

    /**
     * @param validXWikiUserName a valid XWiki username for which to get a profile document
     * @param context the XWiki context
     * @return a (new) XWiki document for the passed username
     * @throws XWikiException when a problem occurs while retrieving the user profile
     */
    private XWikiDocument getAvailableUserProfile(String validXWikiUserName, XWikiContext context) throws XWikiException
    {
        DocumentReference userReference =
            new DocumentReference(context.getWikiId(), XWIKI_USER_SPACE, validXWikiUserName);

        // Check if the default profile document is available
        for (int i = 0; true; ++i) {
            if (i > 0) {
                userReference =
                    new DocumentReference(context.getWikiId(), XWIKI_USER_SPACE, validXWikiUserName + "_" + i);
            }

            XWikiDocument doc = context.getWiki().getDocument(userReference, context);

            // Don't use non user existing document
            if (doc.isNew()) {
                return doc;
            }
        }
    }

    /**
     * @param attributes the LDAP attributes of the user
     * @param context the XWiki context
     * @return the name of the XWiki user profile page
     * @throws XWikiException when a problem occurs while retrieving the user profile
     */
    private XWikiDocument getAvailableUserProfile(List<XWikiLDAPSearchAttribute> attributes, XWikiContext context)
        throws XWikiException
    {
        String pageName = getUserPageName(attributes);

        return getAvailableUserProfile(pageName, context);
    }

    /**
     * @param attributes the LDAP attributes of the user
     * @param context the XWiki context
     * @return the name of the XWiki user profile page
     */
    private String getUserPageName(List<XWikiLDAPSearchAttribute> attributes)
    {
        String userPageName = getConfiguration().getLDAPParam("userPageName", "${uid}");

        Map<String, String> valueMap = new HashMap<>(getConfiguration().getMemoryConfiguration());
        if (attributes != null) {
            for (XWikiLDAPSearchAttribute attribute : attributes) {
                valueMap.put("ldap." + attribute.name, attribute.value);
                if (attribute.name.equals(this.configuration.getUidAttributeName())) {
                    // Override the default uid value with the real one coming from LDAP
                    valueMap.put("uid", attribute.value);
                }
            }
        }

        String pageName = StrSubstitutor.replace(userPageName, valueMap);

        pageName = cleanXWikiUserPageName(pageName);

        LOGGER.debug("UserPageName: {}", pageName);

        return pageName;
    }

    public static boolean isValidDN(String bindDN)
    {
        // FIXME: better solution than checking for an exception?
        try {
            // constructor throws exception, if argument is invalid
            new Dn(bindDN);
            return true;
        } catch (LdapInvalidDnException e) {
            return false;
        }
    }
}
