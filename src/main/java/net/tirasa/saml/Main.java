/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.tirasa.saml;

import java.io.StringWriter;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.w3c.dom.Document;

/**
 *
 * @author fabio
 */
public class Main {

    private static SecureRandomIdentifierGenerator generator;

    /**
     * Any use of this class assures that OpenSAML is bootstrapped.
     * Also initializes an ID generator.
     */
    static {
        try {
            DefaultBootstrap.bootstrap();
            generator = new SecureRandomIdentifierGenerator();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {

        final XMLObjectBuilderFactory bf = Configuration.getBuilderFactory();

        // Create the EntityDescriptor
        final SAMLObjectBuilder<EntityDescriptor> entityDescriptorBuilder =
                (SAMLObjectBuilder<EntityDescriptor>) bf.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);

        final EntityDescriptor spEntityDescriptor = entityDescriptorBuilder.buildObject();

        spEntityDescriptor.setEntityID("http://macpro.irasa.net:9080/");
        final SAMLObjectBuilder<SPSSODescriptor> spSSODescriptorBuilder =
                (SAMLObjectBuilder<SPSSODescriptor>) bf.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        SPSSODescriptor spSSODescriptor = spSSODescriptorBuilder.buildObject();

        spSSODescriptor.setWantAssertionsSigned(true);
        spSSODescriptor.setAuthnRequestsSigned(true);

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
        final SAMLObjectBuilder<NameIDFormat> nameIDFormatBuilder =
                (SAMLObjectBuilder<NameIDFormat>) bf.getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);

        NameIDFormat nameIDFormat = nameIDFormatBuilder.buildObject();
        nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        spSSODescriptor.getNameIDFormats().add(nameIDFormat);


        final SAMLObjectBuilder<AssertionConsumerService> assertionConsumerServiceBuilder =
                (SAMLObjectBuilder<AssertionConsumerService>) bf.getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);

        AssertionConsumerService assertionConsumerService = assertionConsumerServiceBuilder.buildObject();
        assertionConsumerService.setIndex(0);
        assertionConsumerService.setBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

// Setting address for our AssertionConsumerService
        assertionConsumerService.setLocation("http://macpro.tirasa.net/assertion-consumer-service");
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

            System.out.println(metadataXML);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
