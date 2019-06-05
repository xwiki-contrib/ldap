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

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.model.reference.PartialEntityReference;
import org.xwiki.model.reference.RegexEntityReference;
import org.xwiki.observation.EventListener;
import org.xwiki.observation.event.Event;
import org.xwiki.stability.Unstable;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.event.XObjectPropertyAddedEvent;
import com.xpn.xwiki.internal.event.XObjectPropertyDeletedEvent;
import com.xpn.xwiki.internal.event.XObjectPropertyUpdatedEvent;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Event listener to reset group cache when the ldap_groupcache_expiration property is updated.
 *
 * @version $Id$
 * @since 9.3.7
 */
@Component
@Singleton
@Unstable
@Named("GroupCacheExpirationEventListener")
public class GroupCacheExpirationEventListener implements EventListener
{
    private static final String LDAP_GROUP_CACHE_EXPIRATION = "ldap_groupcache_expiration";

    private static final LocalDocumentReference LOCAL_CLASS_REFERENCE =
        new LocalDocumentReference("XWiki", "XWikiPreferences");

    /**
     * A regular expression to match only the XWiki.XWikiPreferences objects.
     */
    private static final RegexEntityReference OBJECT_MATCHER =
        new RegexEntityReference(Pattern.compile(".*:" + "XWiki.XWikiPreferences" + "\\[\\d*\\]"), EntityType.OBJECT);

    /**
     * An entity reference to match only the ldap_groupcache_expiration property reference from any
     * XWiki.XWikiPreferences object.
     */
    private static final PartialEntityReference PROPERTY_MATCHER =
        new PartialEntityReference(LDAP_GROUP_CACHE_EXPIRATION, EntityType.OBJECT_PROPERTY, OBJECT_MATCHER);

    private static final List<Event> EVENTS = Arrays.<Event>asList(new XObjectPropertyAddedEvent(PROPERTY_MATCHER),
        new XObjectPropertyDeletedEvent(PROPERTY_MATCHER), new XObjectPropertyUpdatedEvent(PROPERTY_MATCHER));

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        XWikiDocument doc = (XWikiDocument) source;
        XWikiDocument originalDoc = doc.getOriginalDocument();

        BaseObject newPreferencesObj = doc.getXObject(LOCAL_CLASS_REFERENCE);
        BaseObject originalPreferencesObj = originalDoc.getXObject(LOCAL_CLASS_REFERENCE);

        if (newPreferencesObj != null && originalPreferencesObj != null
            && newPreferencesObj.getStringValue(LDAP_GROUP_CACHE_EXPIRATION)
                .equals(originalPreferencesObj.getStringValue(LDAP_GROUP_CACHE_EXPIRATION))) {
            return;
        }

        XWikiLDAPUtils.resetGroupCache();
    }

    @Override
    public String getName()
    {
        return "GroupCacheExpirationEventListener";
    }

    @Override
    public List<Event> getEvents()
    {
        return EVENTS;
    }
}
