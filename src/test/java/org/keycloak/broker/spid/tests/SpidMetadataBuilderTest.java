package org.keycloak.broker.spid.tests;

import com.google.common.base.Charsets;
import org.apache.commons.io.IOUtils;
import org.jboss.logging.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.broker.spid.SpidIdentityProvider;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.broker.spid.metadata.contacttype.BillingContactInfo;
import org.keycloak.broker.spid.metadata.contacttype.MappingFunctions;
import org.keycloak.broker.spid.metadata.contacttype.OtherContactInfo;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.protocol.saml.SamlPrincipalType;
import org.keycloak.saml.SPMetadataDescriptor;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.XmlKeyInfoKeyNameTransformer;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static org.keycloak.broker.spid.metadata.SpidSpMetadataResourceProvider.customizeEntityDescriptor;

public class SpidMetadataBuilderTest {
    
    protected static final Logger logger = Logger.getLogger(SpidMetadataBuilderTest.class);
    
    List<Element> signingKeys = new LinkedList<>();
    List<Element> encryptionKeys = new LinkedList<>();
    
    URI loginBinding;
    URI logoutBinding;
    URI assertionEndpoint;
    URI logoutEndpoint;
    
    SpidIdentityProviderConfig configPA;
    SpidIdentityProviderConfig configPR;
    
    @Before
    public void init() throws URISyntaxException {
        
        loginBinding = new URI("http://localhost:8080/loginBind");
        logoutBinding = new URI("http://localhost:8080/logoutBind");
        assertionEndpoint = new URI("http://localhost:8080/assert");
        logoutEndpoint = new URI("http://localhost:8080/logout");
    
        configPA = new SpidIdentityProviderConfig();
        configPR = new SpidIdentityProviderConfig();
        
        applyCommonSettings(configPA);
        applyCommonSettings(configPR);
        
        applySettingsForPA(configPA);
        applySettingsForPrivate(configPR);
    }
    
    @Test
    public void testWriteMetadataForPublicSP() throws ProcessingException, ConfigurationException, ParserConfigurationException, SAXException, XPathExpressionException, IOException {
        final String xmlMetadata = writeXmlMetadata(configPA);
        Assert.assertEquals("display company info", evaluateXPath(xmlMetadata, "//*[local-name()='Organization']/*[local-name()='OrganizationDisplayName' and @lang = 'en']"));
        Assert.assertEquals("www.mycompany.it", evaluateXPath(xmlMetadata, "//*[local-name()='Organization']/*[local-name()='OrganizationURL' and @lang = 'it']"));
        Assert.assertEquals("IPACODE", evaluateXPath(xmlMetadata, "//*[local-name()='ContactPerson' and @contactType='other']/*[local-name()='Extensions']/*[local-name()='IPACode']"));
        Assert.assertEquals("", evaluateXPath(xmlMetadata, "//*[local-name()='ContactPerson' and @contactType='other']/*[local-name()='Extensions']/*[local-name()='Public']"));
    }
    
    @Test
    public void testWriteMetadataForPrivateSP() throws ProcessingException, ConfigurationException, SAXException, ParserConfigurationException, XPathExpressionException, IOException {
        final String xmlMetadata = writeXmlMetadata(configPR);
        Assert.assertEquals("display company info", evaluateXPath(xmlMetadata, "//*[local-name()='Organization']/*[local-name()='OrganizationDisplayName' and @lang = 'en']"));
        Assert.assertEquals("www.mycompany.it", evaluateXPath(xmlMetadata, "//*[local-name()='Organization']/*[local-name()='OrganizationURL' and @lang = 'it']"));
        Assert.assertEquals(null, evaluateXPath(xmlMetadata, "//*[local-name()='ContactPerson' and @contactType='other']/*[local-name()='Extensions']/*[local-name()='Public']"));
        Assert.assertEquals("", evaluateXPath(xmlMetadata, "//*[local-name()='ContactPerson' and @contactType='other']/*[local-name()='Extensions']/*[local-name()='Private']"));
        Assert.assertEquals("IT86334519757", evaluateXPath(xmlMetadata, "//*[local-name()='ContactPerson' and @contactType='other']/*[local-name()='Extensions']/*[local-name()='VATNumber']"));
        Assert.assertEquals("contact@email.it", evaluateXPath(xmlMetadata, "//*[local-name()='ContactPerson' and @contactType='other']/*[local-name()='EmailAddress']"));
        Assert.assertEquals("6334519757", evaluateXPath(xmlMetadata, "//*[local-name()='ContactPerson' and @contactType='billing']//Extensions//CessionarioCommittente//DatiAnagrafici/IdFiscaleIVA/IdCodice"));
        Assert.assertEquals("IT", evaluateXPath(xmlMetadata, "//*[local-name()='ContactPerson' and @contactType='billing']//Extensions//CessionarioCommittente//DatiAnagrafici/IdFiscaleIVA/IdPaese"));
        Assert.assertEquals("via Galileo Galilei", evaluateXPath(xmlMetadata, "//*[local-name()='ContactPerson' and @contactType='billing']//Extensions//CessionarioCommittente/Sede/Indirizzo"));
    }
    
    private void applyCommonSettings(SpidIdentityProviderConfig config){
        config.setAlias("SPID");
        config.setDisplayName("SPID");
        config.setEnabled(true);
        config.setTrustEmail(true);
        config.setFirstBrokerLoginFlowId("first broker login");
        config.setSyncMode(IdentityProviderSyncMode.IMPORT);
        config.setEntityId("ENTITYID");
    
        // SEZIONE SAML CONFIG (!!
        config.setSingleSignOnServiceUrl("https://localhost:8080/samlsso/login");
        config.setSingleLogoutServiceUrl("https://localhost:8080/samlsso/logout");
        config.setNameIDPolicyFormat("Transient");
        config.setPrincipalType(SamlPrincipalType.ATTRIBUTE);
        config.setPrincipalAttribute("familyName");
        config.setAllowCreated(true);
        config.setPostBindingResponse(true);
        config.setPostBindingAuthnRequest(true);
        config.setPostBindingLogout(true);
        config.setWantAssertionsSigned(true);
        config.setSignatureAlgorithm("RSA_SHA256");
        config.setXmlSigKeyInfoKeyNameTransformer(XmlKeyInfoKeyNameTransformer.KEY_ID);
        config.setValidateSignature(true);
        config.setAttributeConsumingServiceIndex(1);
        config.setAttributeConsumingServiceName("en|SpidLogin,it|SpidLogin");
        config.setOrganizationNames("en|Company name,it|Nome azienda");
        config.setOrganizationDisplayNames("en|display company info,it|descrizione azienda");
        config.setOrganizationUrls("en|www.mycompany.en,it|www.mycompany.it");
    }
    
    private void applySettingsForPA(SpidIdentityProviderConfig config){
        config.setSpPrivate(false);
        config.setIpaCode("IPACODE");
        
        config.setOtherContactCompany("Company name");
        config.setOtherContactPhone("041 456456456");
        config.setOtherContactEmail("emailserivizio@pubblico.it");
        config.setBillingContactCompany("Billing contact company");
        config.setBillingContactPhone("7897987");
        config.setBillingContactEmail("email-billing@email.it");
    }
    
    private void applySettingsForPrivate(SpidIdentityProviderConfig config){
        config.setSpPrivate(true);
        config.setOtherContactCompany("Company name");
        config.setOtherContactPhone("041 456456456");
        config.setOtherContactEmail("contact@email.it");
        config.setVatNumber("IT86334519757");
        
        config.setBillingContactCompany("Company name for billing");
        config.setBillingContactPhone("7897987");
        config.setBillingContactEmail("email-billing@email.it");
        config.setBillingContactRegistryName("Registro anagrafica");
        config.setBillingContactSiteAddress("via Galileo Galilei");
        config.setBillingContactSiteCity("MIRANO");
        config.setBillingContactSiteNumber("18A");
        config.setBillingContactSitePostalCode("30010");
        config.setBillingContactSiteProvince("VE");
        config.setBillingContactSiteCountry("IT");
    }
    
    public String writeXmlMetadata(SpidIdentityProviderConfig config) throws ProcessingException, ConfigurationException {
        
        boolean wantAuthnRequestsSigned = config.isWantAuthnRequestsSigned();
        boolean wantAssertionsSigned = config.isWantAssertionsSigned();
        boolean wantAssertionsEncrypted = config.isWantAssertionsEncrypted();
        String configEntityId = config.getEntityId();
        String nameIDPolicyFormat = config.getNameIDPolicyFormat();
        int attributeConsumingServiceIndex = config.getAttributeConsumingServiceIndex() != null ? config.getAttributeConsumingServiceIndex(): 1;
        String attributeConsumingServiceName = config.getAttributeConsumingServiceName();
        String[] attributeConsumingServiceNames = attributeConsumingServiceName != null ? attributeConsumingServiceName.split(","): null;
        
        // Additional EntityDescriptor customizations
        String strOrganizationNames = config.getOrganizationNames();
        String[] organizationNames = strOrganizationNames != null ? strOrganizationNames.split(","): null;
        
        String strOrganizationDisplayNames = config.getOrganizationDisplayNames();
        String[] organizationDisplayNames = strOrganizationDisplayNames != null ? strOrganizationDisplayNames.split(","): null;
        
        EntityDescriptorType entityDescriptor = SPMetadataDescriptor.buildSPdescriptor(
                loginBinding, logoutBinding, assertionEndpoint, logoutEndpoint,
                wantAuthnRequestsSigned, wantAssertionsSigned, wantAssertionsEncrypted,
                configEntityId, nameIDPolicyFormat, signingKeys, encryptionKeys);
        
        String strOrganizationUrls = config.getOrganizationUrls();
        String[] organizationUrls = strOrganizationUrls != null ? strOrganizationUrls.split(","): null;
    
        final Optional<OtherContactInfo> otherContactInfo = MappingFunctions.toOtherContact(config);
        final Optional<BillingContactInfo> billingContactInfo = MappingFunctions.toBillingContact(config);
    
        // Additional EntityDescriptor customizations
        customizeEntityDescriptor(entityDescriptor, organizationNames, organizationDisplayNames, organizationUrls, otherContactInfo, billingContactInfo);
        
        // Prepare the metadata descriptor model
        StringWriter sw = new StringWriter();
        XMLStreamWriter writer = StaxUtil.getXMLStreamWriter(sw);
        SAMLMetadataWriter metadataWriter = new SAMLMetadataWriter(writer);
        
        metadataWriter.writeEntityDescriptor(entityDescriptor);
        
        String descriptor = sw.toString();
        return descriptor;
    }
    
    static String evaluateXPath(String xml, String xpathExp)throws XPathExpressionException, IOException, SAXException, ParserConfigurationException {
        
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        final InputStream inputStream = IOUtils.toInputStream(xml, "utf-8");
        Document xmlDocument = builder.parse(inputStream);
        XPath xPath = XPathFactory.newInstance().newXPath();
//        xPath.setNamespaceContext(new NamespaceContext() {
//            @Override
//            ...
//        });
        
        
//        String expressionWithN = "//*[local-name()='Organization']/*[local-name()='OrganizationDisplayName']";
        final NodeList nodeList = (NodeList) xPath.compile(xpathExp).evaluate(xmlDocument, XPathConstants.NODESET);
        if (nodeList == null || nodeList.getLength()== 0) {
            return null;
        }
        // Return only the first element
        return nodeList.item(0) != null ? nodeList.item(0).getTextContent() : "";
    }
    
}
