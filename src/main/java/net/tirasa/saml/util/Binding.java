/* 
 * Copyright 2014 Tirasa.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.saml.util;

public enum Binding {

    POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
    REDIRECT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
    SOAP("urn:oasis:names:tc:SAML:2.0:bindings:SOAP");

    private final String binding;

    private Binding(final String value) {
        this.binding = value;
    }

    public String getBinding() {
        return binding;
    }

}
