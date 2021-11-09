package org.keycloak.broker.spid.metadata.contacttype;

import org.keycloak.dom.saml.v2.metadata.ContactType;
import org.keycloak.dom.saml.v2.metadata.ContactTypeType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.ExtensionsType;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.validation.constraints.NotNull;
import java.util.Optional;

import static org.keycloak.broker.spid.metadata.SpidSpMetadataResourceProvider.*;

public class ContactTypeMgr {
    
    public static void customizeEntityDescriptor(@NotNull EntityDescriptorType entityDescriptor, Optional<OtherContactInfo> otherContact, Optional<BillingContactInfo> billingContact) throws ConfigurationException {
        boolean isSpPrivate = otherContact.isPresent() && otherContact.get().isSpPrivate();
        
        if (isSpPrivate) {
            if (otherContact.isPresent()) {
                entityDescriptor.addContactPerson(createContactTypeOtherPrivate(otherContact.get()));
            }
            if (billingContact.isPresent()) {
                entityDescriptor.addContactPerson(createContactTypeBillingPrivate(billingContact.get()));
            }
            
        } else if (otherContact.isPresent()) {
            entityDescriptor.addContactPerson(createContactTypeOtherPA(otherContact.get()));
        }
    }
    
    private static ContactType createContactTypeOtherPrivate(OtherContactInfo otherContact) throws ConfigurationException {
        // Private SP Extensions
        ContactType otherContactPerson = new ContactType(ContactTypeType.OTHER);
        Document docOtherCt = DocumentUtil.createDocument();
        
        // Extensions
        if (otherContactPerson.getExtensions() == null)
            otherContactPerson.setExtensions(new ExtensionsType());
        
        if (!StringUtil.isNullOrEmpty(otherContact.getCompany()))
            otherContactPerson.setCompany(otherContact.getCompany());
        if (!StringUtil.isNullOrEmpty(otherContact.getEmail()))
            otherContactPerson.addEmailAddress(otherContact.getEmail());
        if (!StringUtil.isNullOrEmpty(otherContact.getPhone()))
            otherContactPerson.addTelephone(otherContact.getPhone());
        
        // VAT Number
        final Optional<Element> elVatNumber = createElementNS(docOtherCt, SPID_METADATA_EXTENSIONS_NS, "xmlns:spid", "spid:VATNumber", otherContact.getVatNumber());
        if (elVatNumber.isPresent()) {
            otherContactPerson.getExtensions().addExtension(elVatNumber.get());
        }
        
        // Fiscal Code
        final Optional<Element> elFiscalCode = createElementNS(docOtherCt, SPID_METADATA_EXTENSIONS_NS, "xmlns:spid", "spid:FiscalCode", otherContact.getFiscalCode());
        if (elFiscalCode.isPresent()) {
            otherContactPerson.getExtensions().addExtension(elFiscalCode.get());
        }
        
        // Private qualifier
        Element spTypeElement = docOtherCt.createElementNS(SPID_METADATA_EXTENSIONS_NS, "spid:Private");
        spTypeElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
        otherContactPerson.getExtensions().addExtension(spTypeElement);
        return otherContactPerson;
    }
    
    private static ContactType createContactTypeBillingPrivate(BillingContactInfo billContact) throws ConfigurationException {
        
        ContactType billingContactTag = new ContactType(ContactTypeType.BILLING);
        
        if (!StringUtil.isNullOrEmpty(billContact.getCompany())) {
            billingContactTag.setCompany(billContact.getCompany());
        }
        if (!StringUtil.isNullOrEmpty(billContact.getEmail())) {
            billingContactTag.addEmailAddress(billContact.getEmail());
        }
        
        if (!StringUtil.isNullOrEmpty(billContact.getPhone())) {
            billingContactTag.addTelephone(billContact.getPhone());
        }
        
        // Extensions
        if (billingContactTag.getExtensions() == null) {
            billingContactTag.setExtensions(new ExtensionsType());
        }
        
        Document docBillingCt = DocumentUtil.createDocument();
        final Optional<Element> elIdPaese = createElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:IdPaese", billContact.getVatCountryCode());
        final Optional<Element> elIdCodice = createElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:IdCodice", billContact.getVatNumber());
        
        final Element pIvaCodFiscaleElemt = createEmptyElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:IdFiscaleIVA");
        appendChild(pIvaCodFiscaleElemt, elIdCodice);
        appendChild(pIvaCodFiscaleElemt, elIdPaese);
        
        final Optional<Element> elDenominazione = createElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:Denominazione", billContact.getRegistryName());
        final Element elAnagrafica = createEmptyElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:Anagrafica");
        appendChild(elAnagrafica, elDenominazione);
        
        final Element elDatiAnagrafici = createEmptyElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:DatiAnagrafici");
        appendChild(elDatiAnagrafici, Optional.ofNullable(pIvaCodFiscaleElemt));
        appendChild(elDatiAnagrafici, Optional.ofNullable(elAnagrafica));
        
        Element elSede = null;
        if (billContact.getOffice() != null) {
            final OfficeInfo officeInfo = billContact.getOffice();
            final Optional<Element> elIndirizzo = createElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:Indirizzo", officeInfo.getAddress());
            final Optional<Element> elNumeroCivico = createElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:NumeroCivico", officeInfo.getNumber());
            final Optional<Element> elCap = createElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:CAP", officeInfo.getPostalCode());
            final Optional<Element> elComune = createElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:Comune", officeInfo.getCity());
            final Optional<Element> elProvincia = createElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:Provincia", officeInfo.getProvince());
            final Optional<Element> elNazione = createElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:Nazione", officeInfo.getCountryCode());
            elSede = createEmptyElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:Sede");
            appendChild(elSede, elIndirizzo);
            appendChild(elSede, elNumeroCivico);
            appendChild(elSede, elCap);
            appendChild(elSede, elComune);
            appendChild(elSede, elProvincia);
            appendChild(elSede, elNazione);
        }
        
        final Element elCessionarioCommittente = createEmptyElementNS(docBillingCt, SPID_METADATA_INVOICING_EXTENSIONS_NS, "xmlns:fpa", "fpa:CessionarioCommittente");
        elCessionarioCommittente.appendChild(elDatiAnagrafici);
        if (elSede != null) {
            elCessionarioCommittente.appendChild(elSede);
        }
        
        billingContactTag.getExtensions().addExtension(elCessionarioCommittente);
        return billingContactTag;
    }
    
    private static ContactType createContactTypeOtherPA(OtherContactInfo otherContact) throws ConfigurationException {
        ContactType otherContactTag = new ContactType(ContactTypeType.OTHER);
        if (!StringUtil.isNullOrEmpty(otherContact.getCompany()))
            otherContactTag.setCompany(otherContact.getCompany());
        if (!StringUtil.isNullOrEmpty(otherContact.getEmail()))
            otherContactTag.addEmailAddress(otherContact.getEmail());
        if (!StringUtil.isNullOrEmpty(otherContact.getPhone()))
            otherContactTag.addTelephone(otherContact.getPhone());
        
        // Extensions
        if (otherContactTag.getExtensions() == null)
            otherContactTag.setExtensions(new ExtensionsType());
        
        Document doc = DocumentUtil.createDocument();
        // Public SP Extensions
        
        // IPA Code
        if (!StringUtil.isNullOrEmpty(otherContact.getIpaCode())) {
            Element ipaCodeElement = doc.createElementNS(SPID_METADATA_EXTENSIONS_NS, "spid:IPACode");
            ipaCodeElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
            ipaCodeElement.setTextContent(otherContact.getIpaCode());
            otherContactTag.getExtensions().addExtension(ipaCodeElement);
        }
        
        // Public qualifier
        Element spTypeElement = doc.createElementNS(SPID_METADATA_EXTENSIONS_NS, "spid:Public");
        spTypeElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
        otherContactTag.getExtensions().addExtension(spTypeElement);
        
        return otherContactTag;
    }
    
    private static void appendChild(Element father, Optional<Element> child) {
        if (child.isPresent()) {
            father.appendChild(child.get());
        }
    }
    
    private static Element createEmptyElementNS(Document doc, String nsUri, String nsQualifiedName, String elementName) {
        Element vatNumberElement = doc.createElementNS(nsUri, elementName);
        vatNumberElement.setAttributeNS(XMLNS_NS, nsQualifiedName, nsUri);
        return vatNumberElement;
    }
    
    private static Optional<Element> createElementNS(Document doc, String nsUri, String nsQualifiedName, String elementName, String elementvalue) {
        if (StringUtil.isNullOrEmpty(elementvalue)) {
            return Optional.empty();
        }
        Element vatNumberElement = doc.createElementNS(nsUri, elementName);
        vatNumberElement.setAttributeNS(XMLNS_NS, nsQualifiedName, nsUri);
        vatNumberElement.setTextContent(elementvalue);
        return Optional.ofNullable(vatNumberElement);
    }
}
