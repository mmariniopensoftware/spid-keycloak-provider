package org.keycloak.broker.spid.metadata;

public class BillingContactInfo {
    
    private String company;
    private String phone;
    private String email;
    private String registryName;
    private SiteInfo site;
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
    
    public SiteInfo getSite() {
        return site;
    }
    
    public void setSite(SiteInfo site) {
        this.site = site;
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
