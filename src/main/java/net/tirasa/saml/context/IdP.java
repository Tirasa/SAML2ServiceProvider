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
package net.tirasa.saml.context;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import net.tirasa.saml.util.Binding;
import net.tirasa.saml.util.Constants;
import net.tirasa.saml.util.SignatureValidatorChain;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
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

    private final SignatureValidatorChain signatureValidatorChain;

    IdP(final EntityDescriptor ed) {
        this.id = ed.getEntityID();
        signatureValidatorChain = new SignatureValidatorChain(id);

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

        // Check just for 1 certificate per type ....
        for (KeyDescriptor key : idpdescriptor.getKeyDescriptors()) {
            try {

                final Collection<java.security.cert.X509Certificate> chain = new ArrayList<>();
                for (X509Certificate cert : key.getKeyInfo().getX509Datas().get(0).getX509Certificates()) {

                    final byte[] decoded = Base64.decode(cert.getValue());
                    final CertificateFactory cf = CertificateFactory.getInstance("X.509");

                    final ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
                    chain.add(java.security.cert.X509Certificate.class.cast(cf.generateCertificate(bais)));
                    bais.close();
                }

                switch (key.getUse()) {
                    case ENCRYPTION:
                        log.debug("Found encryption certificate (not yet supported) ...\n");
                        break;
                    case SIGNING:
                        log.debug("Instantiate signature validators chain");
                        signatureValidatorChain.setChain(chain);
                        break;
                    default:
                    //ignore
                }
            } catch (CertificateException | IOException e) {
                log.warn("Error retrieving X509Certificate from IdP metadata", e);
            }
        }
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

    public SignatureValidatorChain getSignatureValidatorChain() {
        return signatureValidatorChain;
    }
}
