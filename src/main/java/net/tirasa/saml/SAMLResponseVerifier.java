/* 
 * Copyright 2014 Tirasa.
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
package net.tirasa.saml;

import net.tirasa.saml.util.SAMLUtils;
import net.tirasa.saml.store.SAMLRequestStore;
import java.util.List;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLResponseVerifier {

    private static final Logger log = LoggerFactory.getLogger(SAMLResponseVerifier.class);

    private final SAMLRequestStore samlRequestStore = SAMLRequestStore.getInstance();

    public void verify(final SAMLMessageContext<Response, SAMLObject, NameID> samlMessageContext)
            throws SAMLException {
        Response samlResponse = samlMessageContext.getInboundSAMLMessage();

        log.debug("SAML Response message : {}", SAMLUtils.SAMLObjectToString(samlResponse));

        verifyInResponseTo(samlResponse);
        Status status = samlResponse.getStatus();
        StatusCode statusCode = status.getStatusCode();
        String statusCodeURI = statusCode.getValue();

        if (!statusCodeURI.equals(StatusCode.SUCCESS_URI)) {
            log.warn("Incorrect SAML message code : {} ", statusCode.getStatusCode().getValue());
            throw new SAMLException("Incorrect SAML message code : " + statusCode.getValue());
        }

        if (samlResponse.getAssertions().isEmpty()) {
            log.error("Response does not contain any acceptable assertions");
            throw new SAMLException("Response does not contain any acceptable assertions");
        }

        final Assertion assertion = samlResponse.getAssertions().get(0);

        // Assertion must be signed correctly
        if (!assertion.isSigned()) {
            throw new SAMLException("Assertion must be signed");
        }

        // ------------------------------------
        // TODO: Verify signature
        // ------------------------------------
//        try {
//            final Signature sig = assertion.getSignature();
//            COT.getInstance().getIdP().getSignatureValidator().validate(sig);
//        } catch (ValidationException e) {
//            log.error("Signature not valid", e);
//            throw new SAMLException(e);
//        }
        // ------------------------------------
        final NameID nameId = assertion.getSubject().getNameID();
        if (nameId == null) {
            log.error("Name ID not present in subject");
            throw new SAMLException("Name ID not present in subject");
        }

        log.debug("SAML authenticated user " + nameId.getValue());
        verifyConditions(assertion.getConditions(), samlMessageContext);
    }

    private void verifyInResponseTo(final Response samlResponse) {
        final String key = samlResponse.getInResponseTo();

        if (!samlRequestStore.exists(key)) {
            log.error("Response does not match an authentication request");
            throw new RuntimeException("Response does not match an authentication request");
        }

        samlRequestStore.removeRequest(samlResponse.getInResponseTo());
    }

    private void verifyConditions(
            final Conditions conditions,
            final SAMLMessageContext<Response, SAMLObject, NameID> samlMessageContext)
            throws SAMLException {
        verifyExpirationConditions(conditions);
        verifyAudienceRestrictions(conditions.getAudienceRestrictions(), samlMessageContext);
    }

    private void verifyExpirationConditions(final Conditions conditions) throws SAMLException {
        log.debug("Verifying conditions");

        final DateTime currentTime = new DateTime(DateTimeZone.UTC);
        log.debug("Current time in UTC : " + currentTime);

        final DateTime notBefore = conditions.getNotBefore();
        log.debug("Not before condition : " + notBefore);

        if ((notBefore != null) && currentTime.isBefore(notBefore)) {
            throw new SAMLException("Assertion is not conformed with notBefore condition");
        }

        final DateTime notOnOrAfter = conditions.getNotOnOrAfter();
        log.debug("Not on or after condition : " + notOnOrAfter);

        if ((notOnOrAfter != null) && currentTime.isAfter(notOnOrAfter)) {
            throw new SAMLException("Assertion is not conformed with notOnOrAfter condition");
        }
    }

    private void verifyAudienceRestrictions(
            final List<AudienceRestriction> audienceRestrictions,
            final SAMLMessageContext<?, ?, ?> samlMessageContext)
            throws SAMLException {
        // TODO: Audience restrictions should be defined below
    }
}
