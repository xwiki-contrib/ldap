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
package org.xwiki.contrib.ldap.apachedsapi.internal;

import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.cache.Cache;
import org.xwiki.cache.CacheException;
import org.xwiki.cache.CacheManager;
import org.xwiki.cache.config.LRUCacheConfiguration;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLifecycleException;
import org.xwiki.component.phase.Disposable;
import org.xwiki.contrib.ldap.apachedsapi.XWikiLdapUtils;
import org.xwiki.contrib.ldap.apachedsapi.XWikiLdapConfig;

/**
 * The cache of LDAP groups members.
 * This variant uses the Apache DS API.
 * 
 * @version $Id$
 * @since 10.0
 */
@Component(roles = LdapGroupsCache.class)
@Singleton
public class LdapGroupsCache implements Disposable
{
    /**
     * The name of the LDAP groups cache.
     */
    private static final String CACHE_NAME_GROUPS = "ldap.groups";

    @Inject
    private CacheManager cacheManager;

    @Inject
    private XWikiLdapConfig ldapConfig;

    /**
     * Contains caches for each LDAP host:port.
     */
    private Map<String, Map<String, Cache<Map<String, String>>>> cachePool = new HashMap<>();

    /**
     * Get the cache with the provided name for a particular LDAP server.
     * 
     * @return the cache.
     * @throws CacheException error when creating the cache.
     */
    public Cache<Map<String, String>> getGroupCache() throws CacheException
    {
        Cache<Map<String, String>> cache;

        String cacheKey = ldapConfig.getUidAttributeName() + "." + ldapConfig.getLDAPHost() + ":"
            + ldapConfig.getLDAPPort();

        synchronized (cachePool) {
            Map<String, Cache<Map<String, String>>> cacheMap;

            if (cachePool.containsKey(cacheKey)) {
                cacheMap = cachePool.get(cacheKey);
            } else {
                cacheMap = new HashMap<>();
                cachePool.put(cacheKey, cacheMap);
            }

            LRUCacheConfiguration cacheConfiguration = createCacheConfiguration();

            cache = cacheMap.get(cacheConfiguration.getConfigurationId());

            if (cache == null) {
                cache = this.cacheManager.createNewCache(cacheConfiguration);
                cacheMap.put(cacheConfiguration.getConfigurationId(), cache);
            }
        }

        return cache;
    }

    /**
     * @param config the current LDAP configuration
     * @return the cache configuration
     */
    public LRUCacheConfiguration createCacheConfiguration()
    {
        LRUCacheConfiguration cacheConfiguration = new LRUCacheConfiguration(CACHE_NAME_GROUPS);
        cacheConfiguration.getLRUEvictionConfiguration().setLifespan(ldapConfig.getCacheExpiration());

        return cacheConfiguration;
    }

    /**
     * Force to empty the group cache.
     */
    public void reset()
    {
        synchronized (this.cachePool) {
            for (Map<String, Cache<Map<String, String>>> caches : this.cachePool.values()) {
                for (Cache<Map<String, String>> cache : caches.values()) {
                    cache.dispose();
                }
            }
        }

        this.cachePool.clear();
    }

    @Override
    public void dispose() throws ComponentLifecycleException
    {
        reset();
    }
}
