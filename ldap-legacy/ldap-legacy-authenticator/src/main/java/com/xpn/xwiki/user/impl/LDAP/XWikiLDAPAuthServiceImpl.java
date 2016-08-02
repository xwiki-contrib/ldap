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

/**
 * This class provides an authentication method that validates a user trough LDAP against a directory. It gives LDAP
 * users access if they belong to a particular group, creates XWiki users if they have never logged in before and
 * synchronizes membership to XWiki groups based on membership to LDAP groups.
 * 
 * @version $Id$
 * @since 1.3 M2
 */
public class XWikiLDAPAuthServiceImpl extends org.xwiki.contrib.ldap.XWikiLDAPAuthServiceImpl
{
}
