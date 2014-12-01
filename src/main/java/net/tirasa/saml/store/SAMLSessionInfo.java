/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.tirasa.saml.store;

import java.util.Date;
import java.util.Map;

public class SAMLSessionInfo {

    private String nameId;

    private Map<String, String> attributes;

    private Date validTo;

    public SAMLSessionInfo(String nameId, Map<String, String> attributes, Date validTo) {
        this.nameId = nameId;
        this.attributes = attributes;
        this.validTo = validTo;
    }

    public String getNameId() {
        return nameId;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public Date getValidTo() {
        return validTo;
    }
}
