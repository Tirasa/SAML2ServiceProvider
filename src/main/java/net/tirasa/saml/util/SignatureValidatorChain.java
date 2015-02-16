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

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureValidatorChain {

    private static final Logger log = LoggerFactory.getLogger(SignatureValidatorChain.class);

    private final String id;

    private final List<SignatureValidator> validators = new ArrayList<>();

    public SignatureValidatorChain(final String id) {
        this.id = id;
    }

    public void setChain(final Collection<X509Certificate> chain) {
        for (X509Certificate cert : chain) {
            try {
                cert.checkValidity();
                log.debug("Found valid certificate ...\n{}", cert.getPublicKey());

                final BasicX509Credential signing = new BasicX509Credential();
                signing.setEntityId(id);
                signing.setPublicKey(cert.getPublicKey());

                validators.add(new SignatureValidator(signing));
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                log.debug("Found not valid certificate ...\n{}", cert.getPublicKey());
            }
        }
    }

    public void validate(final Signature signature) throws ValidationException {
        for (SignatureValidator validator : validators) {
            try {
                validator.validate(signature);
                return;
            } catch (ValidationException ignore) {
                log.info("Validation faild with validator", ignore);
            }
        }
        throw new ValidationException("Signature cannot be validated");
    }
}
