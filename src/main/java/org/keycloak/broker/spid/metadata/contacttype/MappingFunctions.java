package org.keycloak.broker.spid.metadata.contacttype;

import org.jboss.logging.Logger;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.saml.common.util.StringUtil;

import javax.validation.constraints.NotNull;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static org.keycloak.broker.spid.SpidIdentityProviderConfig.*;

public class MappingFunctions {
    
    protected static final Logger logger = Logger.getLogger(MappingFunctions.class);
    
    private static final Function<String, String> extractVatNumber = str -> {
        if (StringUtil.isNullOrEmpty(str) || str.length() < 13) {
            logger.errorf("PIVA % non della lunghezza corretta", str);
            throw new IllegalArgumentException(String.format("PIVA % non della lunghezza corretta", str));
        }
        return str.substring(3, 13);
    };
    private static final Function<String, String> extractVatCountryCode = str -> {
        if (StringUtil.isNullOrEmpty(str) || str.length() < 13) {
            logger.errorf("PIVA % non della lunghezza corretta", str);
            throw new IllegalArgumentException(String.format("PIVA % non della lunghezza corretta", str));
        }
        return str.substring(0, 2);
    };
    
    private static Function<SpidIdentityProviderConfig, BillingContactInfo> mapConfigToBillingContact = config -> {
        final BillingContactInfo target = new BillingContactInfo();
        target.setCompany(config.getBillingContactCompany());
        target.setPhone(config.getBillingContactPhone());
        target.setEmail(config.getBillingContactEmail());
        target.setRegistryName(config.getBillingContactRegistryName());
        target.setVatNumber(extractVatNumber.apply(config.getVatNumber()));
        target.setVatCountryCode(extractVatCountryCode.apply(config.getVatNumber()));
        target.setOffice(new OfficeInfo());
        target.getOffice().setAddress(config.getBillingContactSiteAddress());
        target.getOffice().setNumber(config.getBillingContactSiteNumber());
        target.getOffice().setCity(config.getBillingContactSiteCity());
        target.getOffice().setPostalCode(config.getBillingContactSitePostalCode());
        target.getOffice().setProvince(config.getBillingContactSiteProvince());
        target.getOffice().setCountryCode(config.getBillingContactSiteCountry());
        return target;
    };
    
    private static Function<SpidIdentityProviderConfig, OtherContactInfo> mapConfigToOtherContact = config -> {
        OtherContactInfo target = new OtherContactInfo();
        target.setSpPrivate(config.isSpPrivate());
        target.setIpaCode(config.getIpaCode());
        target.setVatNumber(config.getVatNumber());
        target.setFiscalCode(config.getFiscalCode());
        target.setCompany(config.getOtherContactCompany());
        target.setEmail(config.getOtherContactEmail());
        target.setPhone(config.getOtherContactPhone());
        return target;
    };
    
    public final static Optional<OtherContactInfo> toOtherContact(@NotNull SpidIdentityProviderConfig config) {
        final boolean oneFieldNotNull = oneFieldNotNull(config.getConfig(),
                Arrays.asList(OTHER_CONTACT_SP_PRIVATE, OTHER_CONTACT_IPA_CODE, OTHER_CONTACT_VAT_NUMBER,
                        OTHER_CONTACT_FISCAL_CODE,
                        OTHER_CONTACT_COMPANY,
                        OTHER_CONTACT_PHONE,
                        OTHER_CONTACT_EMAIL)
        );
        final Optional<OtherContactInfo> result;
        if (!oneFieldNotNull) {
            result = Optional.empty();
        } else {
            result = Optional.of(mapConfigToOtherContact.apply(config));
        }
        return result;
    }

    public final static Optional<BillingContactInfo> toBillingContact(@NotNull SpidIdentityProviderConfig config) {
        
        final boolean isPrivateAndFieldsNotNull = config.isSpPrivate() &&
                oneFieldNotNull(config.getConfig(),
                        Arrays.asList(
                                OTHER_CONTACT_COMPANY,
                                OTHER_CONTACT_PHONE,
                                OTHER_CONTACT_EMAIL));
        final Optional<BillingContactInfo> result;
        if (!isPrivateAndFieldsNotNull) {
            result = Optional.empty();
        } else {
            result = Optional.of(mapConfigToBillingContact.apply(config));
        }
        return result;
    }
    
    private static boolean oneFieldNotNull(Map<String, String> config, @NotNull List<String> fieldsToCheck) {
        
        final Optional<String> firstFieeldNotNull = config.keySet().stream()
                .filter(key -> fieldsToCheck.contains(key))
                .filter(key -> config.get(key) != null && !StringUtil.isNullOrEmpty(config.get(key))).findFirst();
        return firstFieeldNotNull.isPresent();
    }
}
