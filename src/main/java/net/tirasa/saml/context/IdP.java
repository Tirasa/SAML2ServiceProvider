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
package net.tirasa.saml.context;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;
import net.tirasa.saml.util.Binding;
import net.tirasa.saml.util.Constants;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IdP {

    private final String id;

    private static final Logger log = LoggerFactory.getLogger(IdP.class);

    final String errorURL;

    private final Map<String, Endpoint> ssoBindings = new HashMap<>();

    private final Map<String, Endpoint> sloBindings = new HashMap<>();

    private final SignatureValidator signatureValidator;

    IdP(final EntityDescriptor ed) {
        this.id = ed.getEntityID();

        final BasicX509Credential signing = new BasicX509Credential();
        signing.setEntityId(id);

        final IDPSSODescriptor idpdescriptor = ed.getIDPSSODescriptor(Constants.PROTOCOL);

        errorURL = idpdescriptor.getErrorURL();

        for (SingleSignOnService sso : idpdescriptor.getSingleSignOnServices()) {
            log.debug("[{}] Add SSO binding {}({})", new Object[] { this.id, sso.getBinding(), sso.getLocation() });
            ssoBindings.put(sso.getBinding(), sso);
        }

        for (SingleLogoutService slo : idpdescriptor.getSingleLogoutServices()) {
            log.debug("[{}] Add SLO binding {}({})", new Object[] { this.id, slo.getBinding(), slo.getLocation() });
            sloBindings.put(slo.getBinding(), slo);
        }

        // TODO: check just for 1 certificate per type ....
        for (KeyDescriptor key : idpdescriptor.getKeyDescriptors()) {
            try {
                final X509Certificate cert = key.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);

                final byte[] decoded = Base64.decode(cert.getValue());
                final CertificateFactory cf = CertificateFactory.getInstance("X.509");
                final Certificate x509cert = cf.generateCertificate(new ByteArrayInputStream(decoded));
                final PublicKey publickKey = x509cert.getPublicKey();

                switch (key.getUse()) {
                    case ENCRYPTION:
                        log.debug("Found encryption certificate (not yet supported) ...\n{}", cert.getValue());
                        break;
                    case SIGNING:
                        log.debug("Found signing certificate ...\n{}", cert.getValue());
                        log.debug("PublicKey: {}", publickKey.toString());
                        signing.setPublicKey(publickKey);
                        break;
                    default:
                    //ignore
                }
            } catch (Exception e) {
                log.warn("Error retrieving X509Certificate from IdP metadata", e);
            }
        }

        signatureValidator = new SignatureValidator(signing);
    }

    public String getId() {
        return id;
    }

    public String getErrorURL() {
        return errorURL;
    }

    public Endpoint getSSOLocation(final Binding binding) {
        return ssoBindings.get(binding.getBinding());
    }

    public Endpoint getSLOLocation(final Binding binding) {
        return sloBindings.get(binding.getBinding());
    }

    public SignatureValidator getSignatureValidator() {
        return signatureValidator;
    }
}
