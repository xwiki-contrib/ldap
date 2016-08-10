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
package com.xpn.xwiki.plugin.ldap;

/**
 * Represent an LDAP attribute.
 * 
 * @version $Id$
 * @since 1.3 M2
 * @deprecated since 8.3, use {@link org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute} instead
 */
@Deprecated
public class XWikiLDAPSearchAttribute extends org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute
{
    /**
     * Create attribute instance.
     * 
     * @param name attribute name.
     * @param value attribute value.
     */
    public XWikiLDAPSearchAttribute(String name, String value)
    {
        super(name, value);
    }

    /**
     * Create attribute instance.
     * 
     * @param name attribute name.
     * @param byteValue attribute value.
     * @since 8.1M2
     */
    public XWikiLDAPSearchAttribute(String name, byte[] byteValue)
    {
        super(name, byteValue);
    }

    /**
     * @param attribute the attribute to copy
     * @since 8.5
     */
    public XWikiLDAPSearchAttribute(org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute attribute)
    {
        super(attribute);
    }
}
