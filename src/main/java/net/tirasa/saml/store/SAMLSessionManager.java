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

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.servlet.http.HttpSession;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;

public class SAMLSessionManager {

    public static String SAML_SESSION_INFO = "SAML_SESSION_INFO";

    private static SAMLSessionManager instance = new SAMLSessionManager();

    private SAMLSessionManager() {
    }

    public static SAMLSessionManager getInstance() {
        return instance;
    }

    public void createSAMLSession(
            final HttpSession session,
            final SAMLMessageContext<Response, SAMLObject, NameID> samlMessageContext) {
        final List<Assertion> assertions = samlMessageContext.getInboundSAMLMessage().getAssertions();
        final NameID nameId = (assertions.isEmpty() || assertions.get(0).getSubject() == null)
                ? null : assertions.get(0).getSubject().getNameID();
        final String nameValue = nameId == null ? null : nameId.getValue();
        final SAMLSessionInfo samlSessionInfo = new SAMLSessionInfo(
                nameValue,
                getAttributesMap(getSAMLAttributes(assertions)),
                getSAMLSessionValidTo(assertions));
        session.setAttribute(SAML_SESSION_INFO, samlSessionInfo);
    }

    public boolean isSAMLSessionValid(final HttpSession session) {
        SAMLSessionInfo samlSessionInfo = (SAMLSessionInfo) session.getAttribute(SAML_SESSION_INFO);
        if (samlSessionInfo == null) {
            return false;
        }
        return samlSessionInfo.getValidTo() == null || new Date().before(samlSessionInfo.getValidTo());
    }

    public void destroySAMLSession(final HttpSession session) {
        session.removeAttribute(SAML_SESSION_INFO);
    }

    public List<Attribute> getSAMLAttributes(final List<Assertion> assertions) {
        final List<Attribute> attributes = new ArrayList<>();
        if (assertions != null) {
            for (Assertion assertion : assertions) {
                for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
                    for (Attribute attribute : attributeStatement.getAttributes()) {
                        attributes.add(attribute);
                    }
                }
            }
        }
        return attributes;
    }

    public Date getSAMLSessionValidTo(final List<Assertion> assertions) {
        org.joda.time.DateTime sessionNotOnOrAfter = null;
        if (assertions != null) {
            for (Assertion assertion : assertions) {
                for (AuthnStatement statement : assertion.getAuthnStatements()) {
                    sessionNotOnOrAfter = statement.getSessionNotOnOrAfter();
                }
            }
        }

        return sessionNotOnOrAfter == null ? null:sessionNotOnOrAfter.toCalendar(Locale.getDefault()).getTime();
    }

    public Map<String, String> getAttributesMap(final List<Attribute> attributes) {
        final Map<String, String> result = new HashMap<>();
        for (Attribute attribute : attributes) {
            result.put(attribute.getName(), attribute.getDOM().getTextContent());
        }
        return result;
    }
}
