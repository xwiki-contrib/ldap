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

import java.util.List;

import org.xwiki.component.annotation.Role;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.stability.Unstable;

/**
 * Helper class that allows to perform common operations to manage documents created by the LDAP application.
 *
 * @version $Id$
 * @since 9.9.2
 */
@Role
@Unstable
public interface LDAPDocumentHelper
{
    /**
     * Based on the given parameters, compute the document name.
     *
     * @param uidAttributeName the name of the LDAP attribute containing the entity UID
     * @param attributes the LDAP attributes of the entity
     * @param documentNameFormat the page name format that should be used
     * @param config the current LDAP configuration
     * @return the name of the XWiki page
     */
    String getDocumentName(String documentNameFormat, String uidAttributeName,
        List<XWikiLDAPSearchAttribute> attributes, XWikiLDAPConfig config);

    /**
     * From the given document name and space reference, return a reference to a document that does not exist yet in
     * space.
     *
     * @param documentName a valid document name
     * @param space the document space
     * @return a reference to a non-existing document
     */
    DocumentReference getAvailableDocument(String documentName, SpaceReference space);
}
