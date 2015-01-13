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

package net.tirasa.saml.util;

import java.io.StringWriter;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.HTTPRule;
import org.opensaml.ws.security.provider.MandatoryIssuerRule;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class SAMLUtils {

    private static final long serialVersionUID = 1L;

    private static final Logger log = LoggerFactory.getLogger(SAMLUtils.class);

    public static SAMLMessageContext<Response, SAMLObject, NameID> decodeSamlMessage(
            final HttpServletRequest request, final HttpServletResponse response) throws Exception {

        final SAMLMessageContext<Response, SAMLObject, NameID> samlMessageContext = new BasicSAMLMessageContext<>();

        final HttpServletRequestAdapter httpServletRequestAdapter = new HttpServletRequestAdapter(request);
        samlMessageContext.setInboundMessageTransport(httpServletRequestAdapter);
        samlMessageContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        final HttpServletResponseAdapter httpServletResponseAdapter = new HttpServletResponseAdapter(response, request.
                isSecure());

        samlMessageContext.setOutboundMessageTransport(httpServletResponseAdapter);
        samlMessageContext.setPeerEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

        final SecurityPolicyResolver securityPolicyResolver = getSecurityPolicyResolver(request.isSecure());
        samlMessageContext.setSecurityPolicyResolver(securityPolicyResolver);

        new HTTPPostDecoder().decode(samlMessageContext);
        return samlMessageContext;
    }

    private static SecurityPolicyResolver getSecurityPolicyResolver(boolean isSecured) {
        final SecurityPolicy securityPolicy = new BasicSecurityPolicy();
        final HTTPRule httpRule = new HTTPRule(null, null, isSecured);
        final MandatoryIssuerRule mandatoryIssuerRule = new MandatoryIssuerRule();
        final List<SecurityPolicyRule> securityPolicyRules = securityPolicy.getPolicyRules();
        securityPolicyRules.add(httpRule);
        securityPolicyRules.add(mandatoryIssuerRule);
        return new StaticSecurityPolicyResolver(securityPolicy);
    }

    public static String SAMLObjectToString(final XMLObject samlObject) {
        try {
            return SAMLObjectToString(
                    Configuration.getMarshallerFactory().getMarshaller(samlObject).marshall(samlObject));
        } catch (Exception e) {
            log.error("Error serializing SAML Object", e);
            return null;
        }
    }

    public static String SAMLObjectToString(final Element node) {
        StringWriter rspWrt = new StringWriter();
        XMLHelper.writeNode(node, rspWrt);
        return rspWrt.toString();

    }
}
