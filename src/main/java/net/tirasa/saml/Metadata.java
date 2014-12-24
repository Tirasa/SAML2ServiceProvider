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
package net.tirasa.saml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import net.tirasa.saml.util.Constants;
import net.tirasa.saml.util.Properties;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

public class Metadata extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(Metadata.class);

    /**
     * Processes requests for both HTTP
     * <code>GET</code> and
     * <code>POST</code> methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("text/html;charset=UTF-8");

        final XMLObjectBuilderFactory bf = Configuration.getBuilderFactory();

        // Create the EntityDescriptor
        @SuppressWarnings("unchecked")
        final SAMLObjectBuilder<EntityDescriptor> entityDescriptorBuilder = (SAMLObjectBuilder<EntityDescriptor>) bf.
                getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);

        final EntityDescriptor spEntityDescriptor = entityDescriptorBuilder.buildObject();

        spEntityDescriptor.setEntityID(Properties.getString(Constants.ENTITYID, request.getRequestURL().toString()));

        @SuppressWarnings("unchecked")
        final SAMLObjectBuilder<SPSSODescriptor> spSSODescriptorBuilder = (SAMLObjectBuilder<SPSSODescriptor>) bf.
                getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        final SPSSODescriptor spSSODescriptor = spSSODescriptorBuilder.buildObject();

        spSSODescriptor.setWantAssertionsSigned(Properties.getBoolean(Constants.ASS_SIGN, false));
        spSSODescriptor.setAuthnRequestsSigned(Properties.getBoolean(Constants.AUTH_SIGN, false));

        final X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();

        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        try {

            final Credential credential = getCredential();

            if (spSSODescriptor.getWantAssertionsSigned()) {

                @SuppressWarnings("unchecked")
                final SAMLObjectBuilder<KeyDescriptor> keyDescriptorBuilder = (SAMLObjectBuilder<KeyDescriptor>) bf.
                        getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);

                KeyDescriptor encKeyDescriptor = keyDescriptorBuilder.buildObject();

                encKeyDescriptor.setUse(UsageType.ENCRYPTION);

                try {
                    encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));
                    spSSODescriptor.getKeyDescriptors().add(encKeyDescriptor);
                } catch (org.opensaml.xml.security.SecurityException e) {
                    log.error("Error generating credentials", e);
                }
            }

            if (spSSODescriptor.isAuthnRequestsSigned()) {

                @SuppressWarnings("unchecked")
                final SAMLObjectBuilder<KeyDescriptor> keyDescriptorBuilder = (SAMLObjectBuilder<KeyDescriptor>) bf.
                        getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);

                KeyDescriptor signKeyDescriptor = keyDescriptorBuilder.buildObject();

                signKeyDescriptor.setUse(UsageType.SIGNING);

                try {
                    signKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));
                    spSSODescriptor.getKeyDescriptors().add(signKeyDescriptor);
                } catch (org.opensaml.xml.security.SecurityException e) {
                    log.error("Error generating credentials", e);
                }
            }
        } catch (Exception e) {
            log.error("Error retrieving credentials", e);
        }

        @SuppressWarnings("unchecked")
        final SAMLObjectBuilder<NameIDFormat> nameIDFormatBuilder = (SAMLObjectBuilder<NameIDFormat>) bf.getBuilder(
                NameIDFormat.DEFAULT_ELEMENT_NAME);

        String[] formats = Properties.getStringArray(
                Constants.FORMATS, new String[] { "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" });

        for (String format : formats) {
            NameIDFormat nameIDFormat = nameIDFormatBuilder.buildObject();
            nameIDFormat.setFormat(format);
            spSSODescriptor.getNameIDFormats().add(nameIDFormat);
        }

        @SuppressWarnings("unchecked")
        final SAMLObjectBuilder<AssertionConsumerService> assertionConsumerServiceBuilder =
                (SAMLObjectBuilder<AssertionConsumerService>) bf.getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);

        AssertionConsumerService assertionConsumerService = assertionConsumerServiceBuilder.buildObject();
        assertionConsumerService.setIndex(0);
        assertionConsumerService.setBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

        // Setting address for our AssertionConsumerService
        assertionConsumerService.setLocation(
                Properties.getString(Constants.CONSUMER, request.getRequestURL().toString()));

        spSSODescriptor.getAssertionConsumerServices().add(assertionConsumerService);

        spSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        spEntityDescriptor.getRoleDescriptors().add(spSSODescriptor);

        try {
            DocumentBuilder builder;
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            builder = factory.newDocumentBuilder();
            Document document = builder.newDocument();
            Marshaller out = Configuration.getMarshallerFactory().getMarshaller(spEntityDescriptor);
            out.marshall(spEntityDescriptor, document);

            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            StringWriter stringWriter = new StringWriter();
            StreamResult streamResult = new StreamResult(stringWriter);
            DOMSource source = new DOMSource(document);
            transformer.transform(source, streamResult);
            stringWriter.close();
            String metadataXML = stringWriter.toString();

            try (PrintWriter writer = response.getWriter()) {
                writer.println(metadataXML);
            }
        } catch (ParserConfigurationException | MarshallingException | TransformerException | IOException e) {
            log.error("Errr generating metadata", e);
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP
     * <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP
     * <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

    private Credential getCredential() throws Exception {
        final KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        final String keystorePath = Properties.getString(Constants.KEYSTORE);

        log.debug("Loading {} kestore {}", keystore.getType(), keystorePath);

        try (final FileInputStream inputStream = new FileInputStream(keystorePath)) {
            keystore.load(inputStream, Properties.getString(Constants.STOREPASS, "changeit").toCharArray());
            log.debug("Loaded");
        }

        final String alias = Properties.getString(Constants.CERT_ALIAS, "test");

        log.debug("Loading certificate .... {}", alias);

        final Map<String, String> passwordMap = new HashMap<>();
        passwordMap.put(alias, Properties.getString(Constants.KEYPASS, "changeit"));

        final KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

        final Credential credential = resolver.resolveSingle(new CriteriaSet(new EntityIDCriteria(alias)));

        log.debug("Loaded");

        return credential;
    }
}
