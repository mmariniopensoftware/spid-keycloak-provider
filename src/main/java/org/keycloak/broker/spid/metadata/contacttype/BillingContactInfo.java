package org.keycloak.broker.spid.metadata.contacttype;

/**
 * Properties for ContactPerson contactType="billing"
 */
public class BillingContactInfo {
    
    private String company;
    private String phone;
    private String email;
    private String registryName;
    private OfficeInfo office;
    private String vatNumber;
    private String vatCountryCode;
    
    public String getCompany() {
        return company;
    }
    
    public void setCompany(String company) {
        this.company = company;
    }
    
    public String getPhone() {
        return phone;
    }
    
    public void setPhone(String phone) {
        this.phone = phone;
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    public String getRegistryName() {
        return registryName;
    }
    
    public void setRegistryName(String registryName) {
        this.registryName = registryName;
    }
    
    public OfficeInfo getOffice() {
        return office;
    }
    
    public void setOffice(OfficeInfo office) {
        this.office = office;
    }
    
    public String getVatNumber() {
        return vatNumber;
    }
    
    public void setVatNumber(String vatNumber) {
        this.vatNumber = vatNumber;
    }
    
    public String getVatCountryCode() {
        return vatCountryCode;
    }
    
    public void setVatCountryCode(String vatCountryCode) {
        this.vatCountryCode = vatCountryCode;
    }
}
