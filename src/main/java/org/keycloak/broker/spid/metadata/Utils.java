package org.keycloak.broker.spid.metadata;

import org.jboss.logging.Logger;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.saml.common.util.StringUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.swing.text.html.Option;
import javax.validation.constraints.NotNull;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static org.keycloak.broker.spid.SpidIdentityProviderConfig.*;
import static org.keycloak.broker.spid.metadata.SpidSpMetadataResourceProvider.XMLNS_NS;

public class Utils {
    
    protected static final Logger logger = Logger.getLogger(Utils.class);
    
    final static Function<String, String> extractVatNumber = vat -> {
        if (StringUtil.isNullOrEmpty(vat) || vat.length() < 13) {
            logger.errorf("PIVA % non della lunghezza corretta", vat);
            return null;
        }
        return vat.substring(3, 13);
    };
    
    final static Function<String, String> extractVatCountryCode = vat -> {
        if (StringUtil.isNullOrEmpty(vat) || vat.length() < 13) {
            logger.errorf("PIVA % non della lunghezza corretta", vat);
            return null;
        }
        return vat.substring(0, 2);
    };
    
    public final static Function<SpidIdentityProviderConfig, Optional<OtherContactInfo>> mapToOtherContact = config -> {
        final List<String> fieldsNotNull = Arrays.asList(OTHER_CONTACT_SP_PRIVATE, OTHER_CONTACT_IPA_CODE, OTHER_CONTACT_VAT_NUMBER,
                OTHER_CONTACT_FISCAL_CODE,
                OTHER_CONTACT_COMPANY,
                OTHER_CONTACT_PHONE,
                OTHER_CONTACT_EMAIL);
        
        final boolean oneFieldNotNull = oneFieldNotNull(config.getConfig(), fieldsNotNull);
        final Optional<OtherContactInfo> otherContact;
        if (!oneFieldNotNull) {
            otherContact = Optional.empty();
        } else {
            otherContact = Optional.of(new OtherContactInfo());
            otherContact.get().setSpPrivate(config.isSpPrivate());
            otherContact.get().setIpaCode(config.getIpaCode());
            otherContact.get().setVatNumber(config.getVatNumber());
            otherContact.get().setFiscalCode(config.getFiscalCode());
            otherContact.get().setCompany(config.getOtherContactCompany());
            otherContact.get().setEmail(config.getOtherContactEmail());
            otherContact.get().setPhone(config.getOtherContactPhone());
        }
        return otherContact;
    };
    
    public final static Function<SpidIdentityProviderConfig, Optional<BillingContactInfo>> mapToBillingContact = config -> {
        final List<String> fieldsNotNull =
                Arrays.asList(
                        OTHER_CONTACT_COMPANY,
                        OTHER_CONTACT_PHONE,
                        OTHER_CONTACT_EMAIL);
        
        final boolean isPrivateAndFieldsNotNull = oneFieldNotNull(config.getConfig(), fieldsNotNull) && config.isSpPrivate();
        final Optional<BillingContactInfo> billContact;
        if (!isPrivateAndFieldsNotNull) {
            billContact = Optional.empty();
        } else {
            billContact = Optional.of(new BillingContactInfo());
            billContact.get().setCompany(config.getBillingContactCompany());
            billContact.get().setPhone(config.getBillingContactPhone());
            billContact.get().setEmail(config.getBillingContactEmail());
            billContact.get().setRegistryName(config.getBillingContactRegistryName());
            billContact.get().setVatNumber(extractVatNumber.apply(config.getVatNumber()));
            billContact.get().setVatCountryCode(extractVatCountryCode.apply(config.getVatNumber()));
            
            billContact.get().setSite(new SiteInfo());
            billContact.get().getSite().setAddress(config.getBillingContactSiteAddress());
            billContact.get().getSite().setNumber(config.getBillingContactSiteNumber());
            billContact.get().getSite().setCity(config.getBillingContactSiteCity());
            billContact.get().getSite().setPostalCode(config.getBillingContactSitePostalCode());
            billContact.get().getSite().setProvince(config.getBillingContactSiteProvince());
            billContact.get().getSite().setCountryCode(config.getBillingContactSiteCountry());
        }
        return billContact;
    };
    
    public static void appendChild(Element father, Optional<Element> child){
        if (child.isPresent()) {
            father.appendChild(child.get());
        }
    }
    
    public static Element createEmptyElementNS(Document doc, String nsUri, String nsQualifiedName, String elementName) {
        Element vatNumberElement = doc.createElementNS(nsUri, elementName);
        vatNumberElement.setAttributeNS(XMLNS_NS, nsQualifiedName, nsUri);
        return vatNumberElement;
    }
    
    public static Optional<Element> createElementNS(Document doc, String nsUri, String nsQualifiedName, String elementName, String elementvalue) {
        if (StringUtil.isNullOrEmpty(elementvalue)) {
            return Optional.empty();
        }
        Element vatNumberElement = doc.createElementNS(nsUri, elementName);
        vatNumberElement.setAttributeNS(XMLNS_NS, nsQualifiedName, nsUri);
        vatNumberElement.setTextContent(elementvalue);
        return Optional.ofNullable(vatNumberElement);
    }

//    public static boolean oneFieldNotNull(Object obj, @NotNull List<String> fieldsToCheck) {
//        final Optional<Field> firstFieldNotNull = Arrays.stream(obj.getClass().getDeclaredMethods())
//                .filter(method -> fieldsToCheck.contains(field))
//                .filter(field -> {
//                    try {
//                        final boolean isNotNull = field.get(obj) != null;
//                        if (isNotNull && field.get(obj) instanceof String) {
//                            return StringUtils.isNotEmpty(obj.toString());
//                        }
//                        return isNotNull;
//                    } catch (IllegalAccessException e) {
//                        logger.errorf("Error accessing field % of class %", field.getName(), obj.getClass());
//                        return false;
//                    }
//                })
//                .findFirst();
//        return firstFieldNotNull.isPresent();
//    }
    
    
    public static boolean oneFieldNotNull(Map<String, String> config, @NotNull List<String> fieldsToCheck) {
        
        final Optional<String> firstFieeldNotNull = config.keySet().stream()
                .filter(key -> fieldsToCheck.contains(key))
                .filter(key -> config.get(key) != null && !StringUtil.isNullOrEmpty(config.get(key))).findFirst();
        return firstFieeldNotNull.isPresent();
    }
//
//    public static boolean oneFieldNotNull(Object obj) {
//        final Optional<Field> firstFieldNotNull = Arrays.stream(obj.getClass().getDeclaredFields()).
//                filter(field -> {
//                    try {
//                        final boolean isNotNull = field.get(obj) != null;
//                        if (isNotNull && field.get(obj) instanceof String) {
//                            return StringUtils.isNotEmpty(obj.toString());
//                        }
//                        return isNotNull;
//                    } catch (IllegalAccessException e) {
//                        logger.errorf("Error accessing field % of class %", field.getName(), obj.getClass());
//                        return false;
//                    }
//                }).findFirst();
//        return firstFieldNotNull.isPresent();
//    }
//
//    public static boolean isGetter(Method method){
//        if(!method.getName().startsWith("get"))      return false;
//        if(method.getParameterTypes().length != 0)   return false;
//        if(void.class.equals(method.getReturnType()) return false;
//        return true;
//    }
    
}
