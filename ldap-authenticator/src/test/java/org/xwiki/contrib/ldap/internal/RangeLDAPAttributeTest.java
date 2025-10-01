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
package org.xwiki.contrib.ldap.internal;

import org.junit.Test;
import org.xwiki.contrib.ldap.internal.RangeLDAPAttribute.Range;

import com.novell.ldap.LDAPAttribute;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Validate {@link RangeLDAPAttribute}.
 * 
 * @version $Id$
 */
public class RangeLDAPAttributeTest
{
    @Test
    public void rangeParseString()
    {
        assertEquals(new Range(1L, 2L), RangeLDAPAttribute.Range.parse("range=1-2"));
        assertEquals(new Range(1L, null), RangeLDAPAttribute.Range.parse("range=1-*"));
    }

    @Test
    public void rangeParseAttribute()
    {
        assertNull(RangeLDAPAttribute.Range.parse(new LDAPAttribute("attribute")));

        assertEquals(new Range(1L, 2L), RangeLDAPAttribute.Range.parse(new LDAPAttribute("attribute;range=1-2")));
        assertEquals(new Range(1L, null), RangeLDAPAttribute.Range.parse(new LDAPAttribute("attribute;range=1-*")));
    }

    @Test
    public void rangeSerialize()
    {
        assertEquals("range=1500-*", RangeLDAPAttribute.Range.serialize(new Range(1500L, null)));
        assertEquals("range=1500-42", RangeLDAPAttribute.Range.serialize(new Range(1500L, 42L)));
    }
}
