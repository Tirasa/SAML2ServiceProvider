/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
