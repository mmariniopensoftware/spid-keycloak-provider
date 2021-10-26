package org.keycloak.broker.spid.tests;

import org.junit.Before;
import org.junit.Test;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.broker.spid.metadata.BillingContactInfo;
import org.keycloak.broker.spid.metadata.OtherContactInfo;
import org.keycloak.broker.spid.metadata.Utils;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.saml.SamlPrincipalType;
import org.keycloak.saml.SPMetadataDescriptor;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.XmlKeyInfoKeyNameTransformer;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;
import org.w3c.dom.Element;

import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.stream.XMLStreamWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static org.keycloak.broker.spid.metadata.SpidSpMetadataResourceProvider.*;

public class SpidSAML2AuthnRequestBuilderTest {
    
    List<Element> signingKeys = new LinkedList<>();
    List<Element> encryptionKeys = new LinkedList<>();
    SpidIdentityProviderConfig config;
    
    @Before
    public void init(){
        config = new SpidIdentityProviderConfig();
        config.setAlias("SPID");
        config.setDisplayName("SPID");
        config.setEnabled(true);
        config.setTrustEmail(true);
        config.setFirstBrokerLoginFlowId("first broker login");
        config.setSyncMode(IdentityProviderSyncMode.IMPORT);
        config.setEntityId("ENTITYID"); //TODO ???
        
        // SEZIONE SAML CONFIG (!!
        config.setSingleSignOnServiceUrl("https://localhost:8080/demo/samlsso");
        config.setSingleLogoutServiceUrl("https://localhost:8080/demo/samlsso");
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
        config.setOrganizationNames("en|Online services,it|Servizi online");
        config.setOrganizationDisplayNames("en|Online services,it|Servizi online");
        config.setOrganizationUrls("en|www.opensoftware.it,it|www.opensoftware.it");
    }
    
    
    private void impostaSPAsPA(){
        config.setSpPrivate(false);
        config.setIpaCode("IPACODE");
        
        config.setOtherContactCompany("Company name");
        config.setOtherContactPhone("041 456456456");
        config.setOtherContactEmail("emailserivzio@pubblico.it");
        config.setBillingContactCompany("Company name for billing");
        config.setBillingContactPhone("7897987");
        config.setBillingContactEmail("email-billing@email.it");
    }
    
    private void impostaSPForPrivateCompany(){
        config.setSpPrivate(true);
        config.setOtherContactCompany("Company name");
        config.setOtherContactPhone("041 456456456");
        config.setOtherContactEmail("conatct@email.it");
        config.setVatNumber("IT86334519757");
        
        config.setBillingContactCompany("Company name for billing");
        config.setBillingContactPhone("7897987");
        config.setBillingContactEmail("email-billing@email.it");
        config.setBillingContactRegistryName("Registro anagrafica");
        config.setBillingContactSiteAddress("via Galileo Galilei");
        config.setBillingContactSiteCity("MIRANO");
        config.setBillingContactSiteNumber("15A");
        config.setBillingContactSitePostalCode("30020");
        config.setBillingContactSiteProvince("VE");
        config.setBillingContactSiteCountry("IT");
    }
    
    @Test
    public void testMetadataPublic() throws ProcessingException, ConfigurationException, URISyntaxException {
        impostaSPAsPA();
        writeXmlMetadata(config);
    }
    
    @Test
    public void testMetadataPrivateCompany() throws ProcessingException, ConfigurationException, URISyntaxException {
        impostaSPForPrivateCompany();
        writeXmlMetadata(config);
    }
    
    public String writeXmlMetadata(SpidIdentityProviderConfig conf) throws URISyntaxException, ProcessingException, ConfigurationException {
    
        final URI testUri = new URI("http://localhost:9080/testUrlBinding"); // PRESO DA CONFIG??
    
        boolean wantAuthnRequestsSigned = conf.isWantAuthnRequestsSigned();
        boolean wantAssertionsSigned = conf.isWantAssertionsSigned();
        boolean wantAssertionsEncrypted = conf.isWantAssertionsEncrypted();
        String configEntityId = conf.getEntityId();
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
                testUri, testUri, testUri, testUri,
                wantAuthnRequestsSigned, wantAssertionsSigned, wantAssertionsEncrypted,
                configEntityId, nameIDPolicyFormat, signingKeys, encryptionKeys);
    
        String strOrganizationUrls = config.getOrganizationUrls();
        String[] organizationUrls = strOrganizationUrls != null ? strOrganizationUrls.split(","): null;
    
        final Optional<BillingContactInfo> billingContact = Utils.mapToBillingContact.apply(config);
        final Optional<OtherContactInfo> otherContact = Utils.mapToOtherContact.apply(config);
        
        // Prepare the metadata descriptor model
        StringWriter sw = new StringWriter();
        XMLStreamWriter writer = StaxUtil.getXMLStreamWriter(sw);
        SAMLMetadataWriter metadataWriter = new SAMLMetadataWriter(writer);
    
        customizeEntityDescriptor(entityDescriptor, organizationNames, organizationDisplayNames, organizationUrls, otherContact, billingContact);
    
        metadataWriter.writeEntityDescriptor(entityDescriptor);
    
        String descriptor = sw.toString();
        System.out.println("OUT:\n" + descriptor);
        return descriptor;
    }
    
    private String getEntityId(String configEntityId, UriInfo uriInfo, RealmModel realm) {
        if (configEntityId == null || configEntityId.isEmpty())
            return UriBuilder.fromUri(uriInfo.getBaseUri()).path("realms").path(realm.getName()).build().toString();
        else
            return configEntityId;
    }
    
}
