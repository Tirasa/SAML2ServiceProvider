/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.tirasa.saml;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.w3c.dom.Document;

/**
 *
 * @author fabio
 */
public class Metadata extends HttpServlet {

    private static final long serialVersionUID = 1L;

    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException ex) {
            ex.printStackTrace();
        }
    }

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
        final SAMLObjectBuilder<EntityDescriptor> entityDescriptorBuilder = (SAMLObjectBuilder<EntityDescriptor>) bf.
                getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);

        final EntityDescriptor spEntityDescriptor = entityDescriptorBuilder.buildObject();

        spEntityDescriptor.setEntityID("http://localhost:9080/");
        final SAMLObjectBuilder<SPSSODescriptor> spSSODescriptorBuilder = (SAMLObjectBuilder<SPSSODescriptor>) bf.
                getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        SPSSODescriptor spSSODescriptor = spSSODescriptorBuilder.buildObject();

        spSSODescriptor.setWantAssertionsSigned(false);
        spSSODescriptor.setAuthnRequestsSigned(false);

        /*
         * X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
         *
         * keyInfoGeneratorFactory.setEmitEntityCertificate (
         *
         *
         * true);
         * KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
         *
         * KeyDescriptor encKeyDescriptor = SAMLUtil.buildSAMLObjectWithDefaultName(KeyDescriptor.class);
         *
         * encKeyDescriptor.setUse (UsageType.ENCRYPTION); //Set usage
         *
         * // Generating key info. The element will contain the public key. The key is used to by the IDP to encrypt
         * data
         *
         * try {
         * encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(X509Credential));
         * }
         *
         * catch (SecurityException e
         *
         *
         * ) {
         * log.error(e.getMessage(), e);
         * }
         *
         * spSSODescriptor.getKeyDescriptors ()
         *
         * .add(encKeyDescriptor);
         *
         * KeyDescriptor signKeyDescriptor = SAMLUtil.buildSAMLObjectWithDefaultName(KeyDescriptor.class);
         *
         * signKeyDescriptor.setUse (UsageType.SIGNING); //Set usage
         *
         * // Generating key info. The element will contain the public key. The key is used to by the IDP to verify
         * signatures
         *
         * try {
         * signKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(X509Credential));
         * }
         *
         * catch (SecurityException e
         *
         *
         * ) {
         * log.error(e.getMessage(), e);
         * }
         *
         * spSSODescriptor.getKeyDescriptors ()
         *
         * .add(signKeyDescriptor);
         */
        // Request transient pseudonym
        final SAMLObjectBuilder<NameIDFormat> nameIDFormatBuilder = (SAMLObjectBuilder<NameIDFormat>) bf.getBuilder(
                NameIDFormat.DEFAULT_ELEMENT_NAME);

        NameIDFormat nameIDFormat = nameIDFormatBuilder.buildObject();
        nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        spSSODescriptor.getNameIDFormats().add(nameIDFormat);

        final SAMLObjectBuilder<AssertionConsumerService> assertionConsumerServiceBuilder =
                (SAMLObjectBuilder<AssertionConsumerService>) bf.getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);

        AssertionConsumerService assertionConsumerService = assertionConsumerServiceBuilder.buildObject();
        assertionConsumerService.setIndex(0);
        assertionConsumerService.setBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

        // Setting address for our AssertionConsumerService
        assertionConsumerService.setLocation("http://localhost:9080/saml2sp/assertion-consumer-service");
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
        } catch (Exception e) {
            e.printStackTrace();
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
}
