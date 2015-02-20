/* 
 * Copyright 2015 Tirasa.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.saml.store;

import java.util.Date;
import java.util.Map;
import org.apache.commons.lang.builder.ReflectionToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

public class SAMLSessionInfo {

    private final String nameId;

    private final Map<String, String> attributes;

    private final Date validTo;

    public SAMLSessionInfo(final String nameId, final Map<String, String> attributes, final Date validTo) {
        this.nameId = nameId;
        this.attributes = attributes;
        this.validTo = validTo;
    }

    public String getNameId() {
        return nameId;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public Date getValidTo() {
        return validTo;
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
    }
}
