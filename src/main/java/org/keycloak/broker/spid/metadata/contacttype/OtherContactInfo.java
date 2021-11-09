package org.keycloak.broker.spid.metadata.contacttype;

/**
 * Properties for ContactPerson contactType="other"
 */
public class OtherContactInfo {
    
    private boolean isSpPrivate;
    private String ipaCode;
    private String vatNumber;
    private String fiscalCode;
    private String company;
    private String phone;
    private String email;
    
    public boolean isSpPrivate() {
        return isSpPrivate;
    }
    
    public void setSpPrivate(boolean spPrivate) {
        isSpPrivate = spPrivate;
    }
    
    public String getIpaCode() {
        return ipaCode;
    }
    
    public void setIpaCode(String ipaCode) {
        this.ipaCode = ipaCode;
    }
    
    public String getVatNumber() {
        return vatNumber;
    }
    
    public void setVatNumber(String vatNumber) {
        this.vatNumber = vatNumber;
    }
    
    public String getFiscalCode() {
        return fiscalCode;
    }
    
    public void setFiscalCode(String fiscalCode) {
        this.fiscalCode = fiscalCode;
    }
    
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
}
