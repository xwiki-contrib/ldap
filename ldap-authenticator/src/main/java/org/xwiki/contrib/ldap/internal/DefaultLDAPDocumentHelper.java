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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.ldap.LDAPDocumentHelper;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute;

import static org.xwiki.contrib.ldap.XWikiLDAPUtils.cleanXWikiUserPageName;

/**
 * Default implementation of {@link LDAPDocumentHelper}.
 *
 * @version $Id$
 * @since 9.10
 */
@Component
@Singleton
public class DefaultLDAPDocumentHelper implements LDAPDocumentHelper
{
    @Inject
    private Logger logger;

    @Override
    public String getDocumentName(String documentNameFormat, String uidAttributeName,
        List<XWikiLDAPSearchAttribute> attributes, XWikiLDAPConfig config)
    {
        Map<String, String> memoryConfiguration = config.getMemoryConfiguration();
        Map<String, String> valueMap = new HashMap<>();
        if (attributes != null) {
            // Complete existing configuration
            for (Map.Entry<String, String> entry : memoryConfiguration.entrySet()) {
                putVariable(valueMap, entry.getKey(), entry.getValue());
            }

            // Inject attributes
            for (XWikiLDAPSearchAttribute attribute : attributes) {
                putVariable(valueMap, "ldap." + attribute.name, attribute.value);
                if (attribute.name.equals(uidAttributeName)) {
                    // Override the default uid value with the real one coming from LDAP
                    putVariable(valueMap, "uid", attribute.value);
                }
            }
        }

        String documentName = StrSubstitutor.replace(documentNameFormat, valueMap);

        // Do the minimal needed cleanup anyway, even if it is not requested.
        documentName = cleanXWikiUserPageName(documentName);
        logger.debug("Generated document name : [{}]", documentName);

        return documentNameFormat;
    }

    private void putVariable(Map<String, String> map, String key, String value)
    {
        if (value != null) {
            map.put(key, value);

            map.put(key + "._lowerCase", value.toLowerCase());
            map.put(key + "._upperCase", value.toUpperCase());

            String cleanValue = clean(value);
            map.put(key + "._clean", cleanValue);
            map.put(key + "._clean._lowerCase", cleanValue.toLowerCase());
            map.put(key + "._clean._upperCase", cleanValue.toUpperCase());
        }
    }

    private String clean(String str)
    {
        return StringUtils.removePattern(str, "[\\.\\:\\s,@\\^\\/]");
    }
}
