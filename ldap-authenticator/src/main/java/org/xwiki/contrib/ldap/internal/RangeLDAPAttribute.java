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

import java.util.Objects;

import org.apache.commons.lang3.builder.HashCodeBuilder;

import com.novell.ldap.LDAPAttribute;

/**
 * @version $Id$
 * @since 9.16.0
 */
public class RangeLDAPAttribute
{
    /**
     * A MS range (min/max).
     * 
     * @version $Id$
     * @since 9.16.0
     */
    public static class Range
    {
        private static final String RANGE_PREFIX = "range=";

        private final long min;

        private final Long max;

        /**
         * @param min the minimum value
         * @param max the maximum value, or null for no maximum
         */
        public Range(long min, Long max)
        {
            this.min = min;
            this.max = max;
        }

        /**
         * @param attribute the attribute to parse
         * @return the range
         */
        public static Range parse(LDAPAttribute attribute)
        {
            for (String subType : attribute.getSubtypes()) {
                if (subType.startsWith(RANGE_PREFIX)) {
                    return parse(subType);
                }
            }

            return null;
        }

        /**
         * @param range the string to parse
         * @return the range
         */
        public static Range parse(String range)
        {
            String rangeValue = range.substring(RANGE_PREFIX.length());

            int index = rangeValue.indexOf('-');

            if (index > 0) {
                try {
                    String minString = rangeValue.substring(0, index);
                    String maxString = rangeValue.substring(index + 1);

                    return new Range(Long.parseLong(minString),
                        maxString.equals("*") ? null : Long.parseLong(maxString));
                } catch (Exception e) {
                    // Invalid range, just return null
                }
            }

            return null;
        }

        /**
         * @param range the range
         * @return the String version of the range
         */
        public static String serialize(Range range)
        {
            StringBuilder builder = new StringBuilder(RANGE_PREFIX);

            builder.append(range.getMin());

            builder.append('-');

            if (range.getMax() != null) {
                builder.append(range.getMax());
            } else {
                builder.append('*');
            }

            return builder.toString();
        }

        /**
         * @return the minimum index
         */
        public long getMin()
        {
            return this.min;
        }

        /**
         * @return the maximum index, or null for as many as possible according to server maximum
         */
        public Long getMax()
        {
            return this.max;
        }

        @Override
        public int hashCode()
        {
            HashCodeBuilder builder = new HashCodeBuilder();

            builder.append(getMin());
            builder.append(getMax());

            return builder.build();
        }

        @Override
        public boolean equals(Object obj)
        {
            if (obj instanceof Range) {
                Range otherRanger = (Range) obj;

                return getMin() == otherRanger.getMin() && Objects.equals(getMax(), otherRanger.getMax());
            }

            return false;
        }

        @Override
        public String toString()
        {
            return serialize(this);
        }
    }

    private final LDAPAttribute attribute;

    private final Range range;

    /**
     * @param attribute the attribute
     * @param range the range
     */
    public RangeLDAPAttribute(LDAPAttribute attribute, Range range)
    {
        this.attribute = attribute;
        this.range = range;
    }

    /**
     * @return the attribute
     */
    public LDAPAttribute getAttribute()
    {
        return attribute;
    }

    /**
     * @return the range
     */
    public Range getRange()
    {
        return range;
    }
}
