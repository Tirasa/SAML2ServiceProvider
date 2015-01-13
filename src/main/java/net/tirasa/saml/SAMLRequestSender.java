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
import net.tirasa.saml.store.SAMLRequestStore;
import net.tirasa.saml.util.Binding;
import net.tirasa.saml.util.Constants;
import net.tirasa.saml.util.SAMLUtils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLRequestSender {

    private static final Logger log = LoggerFactory.getLogger(SAMLRequestSender.class);

    public void sendSAMLAuthRequest(
            final HttpServletRequest request, final HttpServletResponse servletResponse, final IdP idp)
            throws Exception {
        final SP sp = COT.getInstance().getSp();

        final AuthnRequest authnRequest = buildRequest(sp, idp);

        final HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(
                servletResponse, request.isSecure());

        final String relayState = request.getParameter(Constants.RELAY);

        final BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = getMessageContext(
                authnRequest, COT.getInstance().getSp().getCredential(), relayState, responseAdapter);

        HTTPTransportUtils.addNoCacheHeaders(responseAdapter);
        HTTPTransportUtils.setUTF8Encoding(responseAdapter);

        try {
            new HTTPRedirectDeflateEncoder().encode(context);
        } catch (MessageEncodingException e) {
            log.error("Eror encoding AuthN Request", e);
        }
    }

    public AuthnRequest buildRequest(final SP sp, final IdP idp) throws ServletException {
        final IssuerBuilder issuerBuilder = new IssuerBuilder();
        final Issuer issuer = issuerBuilder.buildObject(
                Constants.ASSERTION,
                Constants.ISSUER,
                Constants.NS_PREFIX);

        issuer.setValue(sp.getEntityid());

        // Creation of AuthRequestObject
        final DateTime issueInstant = new DateTime();
        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();

        final AuthnRequest authRequest = authRequestBuilder.buildObject(
                SAMLConstants.SAML20P_NS,
                Constants.AUTHN_REQUEST,
                Constants.NS_PREFIX);

        // Store SAML 2.0 authentication request
        authRequest.setID(SAMLRequestStore.getInstance().storeRequest());
        authRequest.setForceAuthn(false);
        authRequest.setIssueInstant(issueInstant);
        authRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        authRequest.setAssertionConsumerServiceURL(sp.getAcs());
        authRequest.setIssuer(issuer);
        authRequest.setVersion(SAMLVersion.VERSION_20);

        /* NameIDPolicy */
        final NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
        nameIdPolicy.setFormat(Constants.NAMEID_FORMAT);
        nameIdPolicy.setSPNameQualifier(Constants.ISSUER);
        nameIdPolicy.setAllowCreate(true);
        authRequest.setNameIDPolicy(nameIdPolicy);

        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setDestination(idp.getSSOLocation(Binding.REDIRECT).getLocation());

        log.debug("SAML Authentication message : {} ", SAMLUtils.SAMLObjectToString(authRequest));

        return authRequest;
    }

    private BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> getMessageContext(
            final AuthnRequest authnRequest,
            final Credential credential,
            final String relayState,
            final HttpServletResponseAdapter responseAdapter) {

        final BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context
                = new BasicSAMLMessageContext<>();

        context.setPeerEntityEndpoint(COT.getInstance().getIdP().getSSOLocation(Binding.REDIRECT));
        context.setOutboundSAMLMessage(authnRequest);
        context.setOutboundMessageTransport(responseAdapter);
        context.setOutboundSAMLMessageSigningCredential(credential);
        context.setRelayState(relayState);

        return context;
    }
}
