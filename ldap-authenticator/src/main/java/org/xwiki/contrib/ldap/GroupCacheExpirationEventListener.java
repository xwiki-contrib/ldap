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
import org.xwiki.model.reference.PartialEntityReference;
import org.xwiki.model.reference.RegexEntityReference;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;
import org.xwiki.stability.Unstable;

import com.xpn.xwiki.internal.event.XObjectPropertyAddedEvent;
import com.xpn.xwiki.internal.event.XObjectPropertyDeletedEvent;
import com.xpn.xwiki.internal.event.XObjectPropertyUpdatedEvent;

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
public class GroupCacheExpirationEventListener extends AbstractEventListener
{
    /**
     * The name of the listener.
     */
    private static final String NAME = "GroupCacheExpirationEventListener";

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
        new PartialEntityReference("ldap_groupcache_expiration", EntityType.OBJECT_PROPERTY, OBJECT_MATCHER);

    /**
     * The events to listen to in order to trigger the group cache reset.
     */
    private static final List<Event> EVENTS = Arrays.<Event>asList(new XObjectPropertyAddedEvent(PROPERTY_MATCHER),
        new XObjectPropertyDeletedEvent(PROPERTY_MATCHER), new XObjectPropertyUpdatedEvent(PROPERTY_MATCHER));

    /**
     * The default constructor.
     */
    public GroupCacheExpirationEventListener()
    {
        super(NAME, EVENTS);
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        XWikiLDAPUtils.resetGroupCache();
    }
}
