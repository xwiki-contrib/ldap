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
package com.xpn.xwiki.user.impl.LDAP;

import org.xwiki.model.reference.EntityReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;

/**
 * Helper to manager LDAP profile XClass and XObject.
 * 
 * @version $Id$
 */
public class LDAPProfileXClass extends org.xwiki.contrib.ldap.LDAPProfileXClass
{
    public static final String LDAP_XCLASS = org.xwiki.contrib.ldap.LDAPProfileXClass.LDAP_XCLASS;

    public static final String LDAP_XFIELD_DN = org.xwiki.contrib.ldap.LDAPProfileXClass.LDAP_XFIELD_DN;

    public static final String LDAP_XFIELDPN_DN = org.xwiki.contrib.ldap.LDAPProfileXClass.LDAP_XFIELDPN_DN;

    public static final String LDAP_XFIELD_UID = org.xwiki.contrib.ldap.LDAPProfileXClass.LDAP_XFIELD_UID;

    public static final String LDAP_XFIELDPN_UID = org.xwiki.contrib.ldap.LDAPProfileXClass.LDAP_XFIELDPN_UID;

    public static final EntityReference LDAPPROFILECLASS_REFERENCE =
        org.xwiki.contrib.ldap.LDAPProfileXClass.LDAPPROFILECLASS_REFERENCE;

    public LDAPProfileXClass(XWikiContext context) throws XWikiException
    {
        super(context);
    }
}
