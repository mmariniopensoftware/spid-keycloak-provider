package org.keycloak.broker.spid.metadata.contacttype;

/**
 * Properties for node Sede
 * @see  {@link https://spid.gov.it/invoicing-extensions}
 */
public class OfficeInfo {
    
    private String address;
    private String number;
    private String postalCode;
    private String province;
    private String city;
    private String countryCode;
    
    public String getAddress() {
        return address;
    }
    
    public void setAddress(String address) {
        this.address = address;
    }
    
    public String getNumber() {
        return number;
    }
    
    public void setNumber(String number) {
        this.number = number;
    }
    
    public String getPostalCode() {
        return postalCode;
    }
    
    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }
    
    public String getProvince() {
        return province;
    }
    
    public void setProvince(String province) {
        this.province = province;
    }
    
    public String getCountryCode() {
        return countryCode;
    }
    
    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }
    
    public String getCity() {
        return city;
    }
    
    public void setCity(String city) {
        this.city = city;
    }
}
