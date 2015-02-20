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
package net.tirasa.saml;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.tirasa.saml.context.COT;
import net.tirasa.saml.context.IdP;
import net.tirasa.saml.context.SP;
import net.tirasa.saml.util.Binding;
import net.tirasa.saml.util.Constants;
import net.tirasa.saml.util.SAMLUtils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLResponseSender {

    private static final Logger log = LoggerFactory.getLogger(SAMLResponseSender.class);

    public void sendLogoutResponse(
            final HttpServletRequest request,
            final HttpServletResponse servletResponse,
            final IdP idp,
            final String inResponseTo)
            throws Exception {

        final SP sp = COT.getInstance().getSp();

        final LogoutResponse logoutResponse = buildResponse(sp, idp, inResponseTo);

        final HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(
                servletResponse, request.isSecure());

        final String relayState = request.getParameter(Constants.RELAY);

        final BasicSAMLMessageContext<SAMLObject, LogoutResponse, SAMLObject> context = getMessageContext(
                idp, logoutResponse, COT.getInstance().getSp().getCredential(), relayState, responseAdapter);

        HTTPTransportUtils.addNoCacheHeaders(responseAdapter);
        HTTPTransportUtils.setUTF8Encoding(responseAdapter);

        try {
            new HTTPRedirectDeflateEncoder().encode(context);
//            new HTTPRedirectEncoder().encode(context);
        } catch (MessageEncodingException e) {
            log.error("Error encoding AuthN Request", e);
        }
    }

    public LogoutResponse buildResponse(final SP sp, final IdP idp, final String inResponseTo) throws ServletException {

        final String responseLocation = idp.getSLOLocation(Binding.POST).getResponseLocation();

        final IssuerBuilder issuerBuilder = new IssuerBuilder();
        final Issuer issuer = issuerBuilder.buildObject(
                Constants.ASSERTION,
                Constants.ISSUER,
                Constants.NS_PREFIX);

        issuer.setValue(sp.getEntityid());

        // Creation of AuthRequestObject
        final DateTime issueInstant = new DateTime();

        final LogoutResponseBuilder logoutResponseBuilder = new LogoutResponseBuilder();
        final LogoutResponse logoutResponse = logoutResponseBuilder.buildObject();
        logoutResponse.setIssuer(issuer);
        logoutResponse.setIssueInstant(issueInstant);
        logoutResponse.setInResponseTo(inResponseTo);
        logoutResponse.setID(sp.getEntityid());
        logoutResponse.setVersion(SAMLVersion.VERSION_20);
        logoutResponse.setStatus(generateStatus(StatusCode.SUCCESS_URI, "Logged out"));
        logoutResponse.setDestination(responseLocation);

        log.debug("SAML Respponse message : {} ", SAMLUtils.SAMLObjectToString(logoutResponse));

        return logoutResponse;
    }

    private BasicSAMLMessageContext<SAMLObject, LogoutResponse, SAMLObject> getMessageContext(
            final IdP idp,
            final LogoutResponse logoutResppnse,
            final Credential credential,
            final String relayState,
            final HttpServletResponseAdapter responseAdapter) {

        final BasicSAMLMessageContext<SAMLObject, LogoutResponse, SAMLObject> context = new BasicSAMLMessageContext<>();

        context.setPeerEntityEndpoint(idp.getSLOLocation(Binding.POST));
        context.setOutboundSAMLMessage(logoutResppnse);
        context.setOutboundMessageTransport(responseAdapter);
        context.setOutboundSAMLMessageSigningCredential(credential);
        context.setRelayState(relayState);

        return context;
    }

    private Status generateStatus(final String value, final String message) {
        final Status status = new StatusBuilder().buildObject(Status.DEFAULT_ELEMENT_NAME);
        final StatusCode statusCode = new StatusCodeBuilder().buildObject(StatusCode.DEFAULT_ELEMENT_NAME);

        statusCode.setValue(value);
        status.setStatusCode(statusCode);

        final StatusMessage statusMessage = new StatusMessageBuilder().buildObject(StatusMessage.DEFAULT_ELEMENT_NAME);
        statusMessage.setMessage(message);
        status.setStatusMessage(statusMessage);

        return status;
    }
}
