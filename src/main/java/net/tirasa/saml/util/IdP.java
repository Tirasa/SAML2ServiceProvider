/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.tirasa.saml.util;

import java.util.Map;
import org.opensaml.saml2.metadata.EntityDescriptor;

public class IdP {

    private String id;

    private Map<String, String> bindings;

    public IdP(final EntityDescriptor ed) {
        this.id = ed.getID();
    }

    public String getId() {
        return id;
    }

    public Map<String, String> getBindings() {
        return bindings;
    }
}
