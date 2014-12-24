/* 
 * Copyright 2014 Expression project.organization is undefined on line 4, column 57 in unknown..
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

    public void createSAMLSession(HttpSession session,
            SAMLMessageContext<Response, SAMLObject, NameID> samlMessageContext) {
        List<Assertion> assertions = samlMessageContext.getInboundSAMLMessage().getAssertions();
        NameID nameId = (assertions.size() != 0 && assertions.get(0).getSubject() != null) ? assertions.get(0).
                getSubject().getNameID() : null;
        String nameValue = nameId == null ? null : nameId.getValue();
        SAMLSessionInfo samlSessionInfo = new SAMLSessionInfo(nameValue,
                getAttributesMap(getSAMLAttributes(assertions)),
                getSAMLSessionValidTo(assertions));
        session.setAttribute(SAML_SESSION_INFO, samlSessionInfo);
    }

    public boolean isSAMLSessionValid(HttpSession session) {
        SAMLSessionInfo samlSessionInfo = (SAMLSessionInfo) session.getAttribute(SAML_SESSION_INFO);
        if (samlSessionInfo == null) {
            return false;
        }
        return samlSessionInfo.getValidTo() == null || new Date().before(samlSessionInfo.getValidTo());
    }

    public void destroySAMLSession(HttpSession session) {
        session.removeAttribute(SAML_SESSION_INFO);
    }

    public List<Attribute> getSAMLAttributes(List<Assertion> assertions) {
        List<Attribute> attributes = new ArrayList<Attribute>();
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

    public Date getSAMLSessionValidTo(List<Assertion> assertions) {
        org.joda.time.DateTime sessionNotOnOrAfter = null;
        if (assertions != null) {
            for (Assertion assertion : assertions) {
                for (AuthnStatement statement : assertion.getAuthnStatements()) {
                    sessionNotOnOrAfter = statement.getSessionNotOnOrAfter();
                }
            }
        }

        return sessionNotOnOrAfter != null ? sessionNotOnOrAfter.toCalendar(Locale.getDefault()).getTime() : null;
    }

    public Map<String, String> getAttributesMap(List<Attribute> attributes) {
        Map<String, String> result = new HashMap<String, String>();
        for (Attribute attribute : attributes) {
            result.put(attribute.getName(), attribute.getDOM().getTextContent());
        }
        return result;
    }
}
