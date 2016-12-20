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

import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.context.Execution;
import org.xwiki.context.ExecutionContext;
import org.xwiki.text.StringUtils;

import com.novell.ldap.LDAPDN;
import com.novell.ldap.LDAPException;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * This class provides an authentication method that validates a user trough LDAP against a directory. It gives LDAP
 * users access if they belong to a particular group, creates XWiki users if they have never logged in before and
 * synchronizes membership to XWiki groups based on membership to LDAP groups.
 * 
 * @version $Id$
 * @since 8.3
 */
public class XWikiLDAPAuthServiceImpl extends XWikiAuthServiceImpl
{
    /**
     * Default unique user field name.
     */
    private static final String LDAP_DEFAULT_UID = "cn";

    /**
     * Logging tool.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiLDAPAuthServiceImpl.class);

    private static final String CONTEXT_CONFIGURATION = "ldap.configuration";

    private Execution execution;

    protected ExecutionContext getExecutionContext()
    {
        if (this.execution == null) {
            this.execution = Utils.getComponent(Execution.class);
        }

        return this.execution.getContext();
    }

    /**
     * @deprecated since 9.1.1, use {@link #initConfiguration(String)} instead
     */
    @Deprecated
    protected XWikiLDAPConfig initConfiguration(String authInput, XWikiContext xcontext)
    {
        return initConfiguration(authInput);
    }

    /**
     * @since 9.1.1
     */
    protected XWikiLDAPConfig initConfiguration(String authInput)
    {
        ExecutionContext econtext = getExecutionContext();

        if (econtext != null) {
            XWikiLDAPConfig configuration = createXWikiLDAPConfig(authInput);

            econtext.setProperty(CONTEXT_CONFIGURATION, configuration);

            return configuration;
        }

        return XWikiLDAPConfig.getInstance();
    }

    /**
     * Allow extenders of this class to override this method and provide their own XWikiLDAPConfig instance (for
     * example in order to use a different configuration source).
     *
     * @since 9.1.1
     */
    protected XWikiLDAPConfig createXWikiLDAPConfig(String authInput)
    {
        return new XWikiLDAPConfig(authInput);
    }

    protected void removeConfiguration()
    {
        ExecutionContext econtext = getExecutionContext();

        if (econtext != null) {
            econtext.removeProperty(CONTEXT_CONFIGURATION);
        }
    }

    protected XWikiLDAPConfig getConfiguration()
    {
        ExecutionContext econtext = getExecutionContext();

        if (econtext != null) {
            XWikiLDAPConfig configuration = (XWikiLDAPConfig) econtext.getProperty(CONTEXT_CONFIGURATION);

            if (configuration != null) {
                return configuration;
            }
        }

        return XWikiLDAPConfig.getInstance();
    }

    // REMOTE_USER

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        String httpHeader = getConfiguration().getHttpHeader();

        XWikiUser user = null;
        String remoteUser;

        if (StringUtils.isEmpty(httpHeader)) {
            remoteUser = context.getRequest().getRemoteUser();
        } else {
            remoteUser = context.getRequest().getHeader(httpHeader);
        }

        if (remoteUser != null) {
            LOGGER.debug("RemoteUser: {}", remoteUser);
            user = checkAuthSSO(remoteUser, context);
        }

        if (user == null) {
            user = super.checkAuth(context);
        }

        LOGGER.debug("XWikiUser: {}", user);

        return user;
    }

    private XWikiUser checkAuthSSO(String remoteUser, XWikiContext context)
    {
        // Remember various stuff in the session so that callback can access it
        XWikiRequest request = context.getRequest();

        // Check if the user is already authenticated
        Principal principal =
            (Principal) request.getSession().getAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY);
        if (principal != null) {
            String storedRemoteUser = (String) request.getSession().getAttribute("ldap.remoteuser");
            if (!remoteUser.equals(storedRemoteUser)) {
                // If the remote user changed authenticate again
                principal = null;
            }
        }

        XWikiUser user;

        // Authenticate
        if (principal == null) {
            principal = ldapAuthenticate(remoteUser, null, true, context);
            if (principal == null) {
                return null;
            }

            // Remember user in the session
            request.getSession().setAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY, principal);
            request.getSession().setAttribute("ldap.remoteuser", context.getRequest().getRemoteUser());

            user = new XWikiUser(principal.getName());
        } else {
            user = new XWikiUser(principal.getName().startsWith(context.getWikiId())
                ? principal.getName().substring(context.getWikiId().length() + 1) : principal.getName());
        }

        LOGGER.debug("XWikiUser=" + user);

        removeConfiguration();

        return user;
    }

    // LOGIN/PASS

    @Override
    public Principal authenticate(String userId, String password, XWikiContext context) throws XWikiException
    {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Starting LDAP authentication");
        }

        /*
         * TODO: Put the next 4 following "if" in common with XWikiAuthService to ensure coherence This method was
         * returning null on failure so I preserved that behaviour, while adding the exact error messages to the context
         * given as argument. However, the right way to do this would probably be to throw XWikiException-s.
         */

        if (userId == null) {
            // If we can't find the username field then we are probably on the login screen

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("The provided user is null."
                    + " We don't try to authenticate, it probably means the user is in non logged mode.");
            }

            return null;
        }

        // Check for empty usernames
        if (userId.equals("")) {
            context.put("message", "nousername");

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("LDAP authentication failed: login empty");
            }

            return null;
        }

        // Check for empty passwords
        if ((password == null) || (password.trim().equals(""))) {
            context.put("message", "nopassword");

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("LDAP authentication failed: password null or empty");
            }

            return null;
        }

        // Check for superadmin
        if (isSuperAdmin(userId)) {
            return authenticateSuperAdmin(password, context);
        }

        // Try authentication against ldap
        Principal principal = ldapAuthenticate(userId, password, false, context);

        if (principal == null) {
            // Fallback to local DB only if trylocal is true
            principal = xwikiAuthenticate(userId, password, context);
        }

        if (LOGGER.isDebugEnabled()) {
            if (principal != null) {
                LOGGER.debug("LDAP authentication succeed with principal [{}]", principal.getName());
            } else {
                LOGGER.debug("LDAP authentication failed for user [{}]", userId);
            }
        }

        removeConfiguration();

        return principal;
    }

    /**
     * @param name the name to convert.
     * @return a valid XWiki user name:
     *         <ul>
     *         <li>Remove '.'</li>
     *         </ul>
     * @deprecated since 9.0, use {@link XWikiLDAPUtils#cleanXWikiUserPageName(String)} instead
     */
    @Deprecated
    protected String getValidXWikiUserName(String name)
    {
        return XWikiLDAPUtils.cleanXWikiUserPageName(name);
    }

    /**
     * Try both local and global ldap login and return {@link Principal}.
     * 
     * @param userId the id of the user provided in input
     * @param password the password of the user to log in.
     * @param context the XWiki context.
     * @return the {@link Principal}.
     */
    protected Principal ldapAuthenticate(String userId, String password, XWikiContext context)
    {
        Principal principal = ldapAuthenticate(userId, password, false, context);
        removeConfiguration();
        return principal;
    }

    /**
     * Try both local and global ldap login and return {@link Principal}.
     * 
     * @param userId the id of the user provided in input
     * @param password the password of the user to log in.
     * @param trusted is it a trusted authentication (should the credentials be validated)
     * @param context the XWiki context.
     * @return the {@link Principal}.
     */
    private Principal ldapAuthenticate(String userId, String password, boolean trusted, XWikiContext context)
    {
        Principal principal = null;

        // First we check in the local context for a valid ldap user
        try {
            principal = ldapAuthenticateInContext(userId, null, password, trusted, context, true);
        } catch (Exception e) {
            // continue
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Local LDAP authentication failed.", e);
            }
        }

        // If local ldap failed, try global ldap
        if (principal == null && !context.isMainWiki()) {
            // Then we check in the main database
            String db = context.getWikiId();
            try {
                context.setWikiId(context.getMainXWiki());
                try {
                    principal = ldapAuthenticateInContext(userId, null, password, trusted, context, false);
                } catch (Exception e) {
                    // continue
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Global LDAP authentication failed.", e);
                    }
                }
            } finally {
                context.setWikiId(db);
            }
        }

        return principal;
    }

    /**
     * Try both local and global DB login if trylocal is true {@link Principal}.
     * 
     * @param userId the id of the user provided in input
     * @param ldapPassword the password of the user to log in.
     * @param context the XWiki context.
     * @return the {@link Principal}.
     * @throws XWikiException error when checking user name and password.
     */
    protected Principal xwikiAuthenticate(String userId, String ldapPassword, XWikiContext context)
        throws XWikiException
    {
        Principal principal = null;

        String trylocal = getConfiguration().getTryLocal();

        if ("1".equals(trylocal)) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Trying authentication against XWiki DB");
            }

            principal = super.authenticate(userId, ldapPassword, context);
        }

        return principal;
    }

    /**
     * Try LDAP login for given context and return {@link Principal}.
     * 
     * @param userId the id of the user provided in input
     * @param validXWikiUserName the name of the XWiki user to log in.
     * @param password the password of the user to log in.
     * @param context the XWiki context.
     * @return the {@link Principal}.
     * @throws XWikiException error when login.
     * @throws UnsupportedEncodingException error when login.
     * @throws LDAPException error when login.
     */
    protected Principal ldapAuthenticateInContext(String userId, String validXWikiUserName, String password,
        XWikiContext context) throws XWikiException, UnsupportedEncodingException, LDAPException
    {
        return ldapAuthenticateInContext(userId, validXWikiUserName, password, context, false);
    }

    /**
     * Try LDAP login for given context and return {@link Principal}.
     * 
     * @param userId the id of the user provided in input
     * @param password the password of the user to log in.
     * @param context the XWiki context.
     * @return the {@link Principal}.
     * @throws XWikiException error when login.
     * @throws UnsupportedEncodingException error when login.
     * @throws LDAPException error when login.
     */
    protected Principal ldapAuthenticateInContext(String userId, String password, XWikiContext context)
        throws XWikiException, UnsupportedEncodingException, LDAPException
    {
        return ldapAuthenticateInContext(userId, password, context, false);
    }

    /**
     * Try LDAP login for given context and return {@link Principal}.
     * 
     * @param userId the id of the user provided in input
     * @param password the password of the user to log in.
     * @param context the XWiki context.
     * @param local indicate if it's a local authentication. Supposed to return a local user {@link Principal} (without
     *            the wiki name).
     * @return the {@link Principal}.
     * @throws XWikiException error when login.
     * @throws UnsupportedEncodingException error when login.
     * @throws LDAPException error when login.
     */
    protected Principal ldapAuthenticateInContext(String userId, String password, XWikiContext context, boolean local)
        throws XWikiException, UnsupportedEncodingException, LDAPException
    {
        return ldapAuthenticateInContext(userId, null, password, context, local);
    }

    /**
     * Try LDAP login for given context and return {@link Principal}.
     * 
     * @param userId the id of the user provided in input
     * @param validXWikiUserName the name of the XWiki user to log in.
     * @param password the password of the user to log in.
     * @param context the XWiki context.
     * @param local indicate if it's a local authentication. Supposed to return a local user {@link Principal} (without
     *            the wiki name).
     * @return the {@link Principal}.
     * @throws XWikiException error when login.
     * @throws UnsupportedEncodingException error when login.
     * @throws LDAPException error when login.
     */
    protected Principal ldapAuthenticateInContext(String userId, String validXWikiUserName, String password,
        XWikiContext context, boolean local) throws XWikiException, UnsupportedEncodingException, LDAPException
    {
        return ldapAuthenticateInContext(userId, validXWikiUserName, password, false, context, local);
    }

    /**
     * Try LDAP login for given context and return {@link Principal}.
     * 
     * @param authInput the id of the user provided in input
     * @param validXWikiUserName the name of the XWiki user to log in.
     * @param password the password of the user to log in.
     * @param trusted true in case of trusted authentication (i.e. should the credentials be validated or not)
     * @param context the XWiki context.
     * @param local indicate if it's a local authentication. Supposed to return a local user {@link Principal} (without
     *            the wiki name).
     * @return the {@link Principal}.
     * @throws XWikiException error when login.
     * @throws UnsupportedEncodingException error when login.
     * @throws LDAPException error when login.
     * @since 9.0
     */
    protected Principal ldapAuthenticateInContext(String authInput, String validXWikiUserName, String password,
        boolean trusted, XWikiContext context, boolean local)
        throws XWikiException, UnsupportedEncodingException, LDAPException
    {
        Principal principal = null;

        XWikiLDAPConfig configuration = initConfiguration(authInput);
        XWikiLDAPConnection connector = new XWikiLDAPConnection(configuration);
        XWikiLDAPUtils ldapUtils = new XWikiLDAPUtils(connector, configuration);

        ldapUtils.setUidAttributeName(configuration.getUidAttributeName());
        ldapUtils.setGroupClasses(configuration.getGroupClasses());
        ldapUtils.setGroupMemberFields(configuration.getGroupMemberFields());
        ldapUtils.setBaseDN(configuration.getBaseDN());
        ldapUtils.setUserSearchFormatString(configuration.getUserSearchFormatString());
        ldapUtils.setResolveSubgroups(configuration.getResolveSubgroups() == 1);

        String uid = configuration.getMemoryConfiguration().get("uid");

        // ////////////////////////////////////////////////////////////////////
        // 1. check if ldap authentication is off => authenticate against db
        // ////////////////////////////////////////////////////////////////////

        if (!configuration.isLDAPEnabled()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("LDAP authentication failed: LDAP not activ");
            }

            return principal;
        }

        // ////////////////////////////////////////////////////////////////////
        // 2. bind to LDAP => if failed try db
        // ////////////////////////////////////////////////////////////////////

        if (!connector.open(authInput, password, context)) {
            throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                "Bind to LDAP server failed.");
        }

        // ////////////////////////////////////////////////////////////////////
        // 3. find XWiki user profile page
        // ////////////////////////////////////////////////////////////////////

        XWikiDocument userProfile = ldapUtils.getUserProfileByUid(validXWikiUserName, authInput, context);
        if (userProfile == null) {
            // Try to search just the UID (in case this user was created before a move to multidomain)
            if (!authInput.equals(uid) && getConfiguration().getTestLoginFor().contains(authInput)) {
                userProfile = ldapUtils.getUserProfileByUid(validXWikiUserName, uid, context);
            }
        }

        // ////////////////////////////////////////////////////////////////////
        // 4. check if bind DN is user DN
        // ////////////////////////////////////////////////////////////////////

        String ldapDn = null;

        String bindDNFormat = configuration.getLDAPBindDN();
        String bindDN = configuration.getLDAPBindDN(authInput, password);

        // Active directory support a special non DN form for bind but does not accept it at search level
        if (!bindDNFormat.equals(bindDN) && LDAPDN.isValid(bindDN)) {
            ldapDn = bindDN;
        }

        // ////////////////////////////////////////////////////////////////////
        // 5. if group param, verify group membership (& get DN)
        // ////////////////////////////////////////////////////////////////////

        String filterGroupDN = configuration.getLDAPParam("ldap_user_group", "");

        if (filterGroupDN.length() > 0) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Checking if the user belongs to the user group: {}", filterGroupDN);
            }

            ldapDn = ldapUtils.isInGroup(uid, ldapDn, filterGroupDN, context);

            if (ldapDn == null) {
                throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                    "LDAP user {0} does not belong to LDAP group {1}.", null, new Object[] {uid, filterGroupDN});
            }
        }

        // ////////////////////////////////////////////////////////////////////
        // 6. if exclude group param, verify group membership
        // ////////////////////////////////////////////////////////////////////

        String excludeGroupDN = configuration.getLDAPParam("ldap_exclude_group", "", context);

        if (excludeGroupDN.length() > 0) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Checking if the user does not belongs to the exclude group: {}", excludeGroupDN);
            }

            if (ldapUtils.isInGroup(uid, ldapDn, excludeGroupDN, context) != null) {
                throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                    "LDAP user {0} should not belong to LDAP group {1}.", null, new Object[] {uid, filterGroupDN});
            }
        }

        // ////////////////////////////////////////////////////////////////////
        // 7. if no dn search for user
        // ////////////////////////////////////////////////////////////////////

        List<XWikiLDAPSearchAttribute> searchAttributes = null;

        // if we still don't have a dn, search for it. Also get the attributes, we might need
        // them
        if (ldapDn == null) {
            searchAttributes = ldapUtils.searchUserAttributesByUid(uid, ldapUtils.getAttributeNameTable(context));

            if (searchAttributes != null) {
                for (XWikiLDAPSearchAttribute searchAttribute : searchAttributes) {
                    if ("dn".equals(searchAttribute.name)) {
                        ldapDn = searchAttribute.value;

                        break;
                    }
                }
            }
        }

        if (ldapDn == null) {
            throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                "Can't find LDAP user DN for input [" + authInput + "]");
        }

        // ////////////////////////////////////////////////////////////////////
        // 8. apply validate_password property or if user used for LDAP connection is not the one
        // authenticated try to bind
        // ////////////////////////////////////////////////////////////////////

        if (!trusted) {
            if ("1".equals(configuration.getLDAPParam("ldap_validate_password", "0"))) {
                String passwordField = configuration.getLDAPParam("ldap_password_field", "userPassword");
                if (!connector.checkPassword(ldapDn, password, passwordField)) {
                    LOGGER.debug("Password comparison failed, are you really sure you need validate_password ?"
                        + " If you don't enable it, it does not mean user credentials are not validated."
                        + " The goal of this property is to bypass standard LDAP bind"
                        + " which is usually bad unless you really know what you do.");

                    throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                        "LDAP authentication failed:" + " could not validate the password: wrong password for "
                            + ldapDn);
                }
            } else if (!ldapDn.equals(bindDN)) {
                // Validate user credentials
                connector.bind(ldapDn, password);

                // Rebind admin user
                connector.bind(bindDN, configuration.getLDAPBindPassword(authInput, password));
            }
        }

        // ////////////////////////////////////////////////////////////////////
        // 9. sync user
        // ////////////////////////////////////////////////////////////////////

        boolean isNewUser = userProfile == null || userProfile.isNew();

        userProfile = syncUser(userProfile, searchAttributes, ldapDn, authInput, ldapUtils, context);

        // from now on we can enter the application
        if (local) {
            principal = new SimplePrincipal(userProfile.getFullName());
        } else {
            principal = new SimplePrincipal(userProfile.getPrefixedFullName());
        }

        // ////////////////////////////////////////////////////////////////////
        // 10. sync groups membership
        // ////////////////////////////////////////////////////////////////////

        try {
            syncGroupsMembership(userProfile.getFullName(), ldapDn, isNewUser, ldapUtils, context);
        } catch (XWikiException e) {
            LOGGER.error("Failed to synchronise user's groups membership", e);
        }

        return principal;
    }

    /**
     * Update or create XWiki user base on LDAP.
     * 
     * @param userProfile the XWiki user profile page.
     * @param searchAttributeListIn the attributes.
     * @param ldapDn the LDAP user DN.
     * @param authInput the input used to identify the user
     * @param ldapUtils the LDAP communication tool.
     * @param context the XWiki context.
     * @return the XWiki user document
     * @throws XWikiException error when updating or creating XWiki user.
     */
    protected XWikiDocument syncUser(XWikiDocument userProfile, List<XWikiLDAPSearchAttribute> searchAttributeListIn,
        String ldapDn, String authInput, XWikiLDAPUtils ldapUtils, XWikiContext context) throws XWikiException
    {
        return ldapUtils.syncUser(userProfile, searchAttributeListIn, ldapDn, authInput, context);
    }

    /**
     * Synchronize user XWiki membership with it's LDAP membership.
     * 
     * @param xwikiUserName the name of the user.
     * @param ldapDn the LDAP DN of the user.
     * @param createuser indicate if the user is created or updated.
     * @param ldapUtils the LDAP communication tool.
     * @param context the XWiki context.
     * @throws XWikiException error when synchronizing user membership.
     */
    protected void syncGroupsMembership(String xwikiUserName, String ldapDn, boolean createuser,
        XWikiLDAPUtils ldapUtils, XWikiContext context) throws XWikiException
    {
        XWikiLDAPConfig configuration = getConfiguration();

        // got valid group mappings
        Map<String, Set<String>> groupMappings = configuration.getGroupMappings();

        // update group membership, join and remove from given groups
        // sync group membership for this user
        if (groupMappings.size() > 0) {
            // flag if always sync or just on create of the user
            String syncmode = configuration.getLDAPParam("ldap_mode_group_sync", "always");

            if (!syncmode.equalsIgnoreCase("create") || createuser) {
                syncGroupsMembership(xwikiUserName, ldapDn, groupMappings, ldapUtils, context);
            }
        }
    }

    /**
     * Synchronize user XWiki membership with it's LDAP membership.
     * 
     * @param xwikiUserName the name of the user.
     * @param userDN the LDAP DN of the user.
     * @param groupMappings the mapping between XWiki groups names and LDAP groups names.
     * @param ldapUtils the LDAP communication tool.
     * @param context the XWiki context.
     * @throws XWikiException error when synchronizing user membership.
     */
    protected void syncGroupsMembership(String xwikiUserName, String userDN, Map<String, Set<String>> groupMappings,
        XWikiLDAPUtils ldapUtils, XWikiContext context) throws XWikiException
    {
        ldapUtils.syncGroupsMembership(xwikiUserName, userDN, groupMappings, context);
    }

}
