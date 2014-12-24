/* 
 * Copyright 2014 Expression project.organization is undefined on line 4, column 57 in unknown..
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

package net.tirasa.saml.store;

import java.util.HashSet;
import java.util.Set;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.impl.RandomIdentifierGenerator;

final public class SAMLRequestStore {

    private Set<String> samlRequestStorage = new HashSet<String>();

    private IdentifierGenerator identifierGenerator = new RandomIdentifierGenerator();

    private static SAMLRequestStore instance = new SAMLRequestStore();

    private SAMLRequestStore() {
    }

    public static SAMLRequestStore getInstance() {
        return instance;
    }

    public synchronized void storeRequest(String key) {
        if (samlRequestStorage.contains(key)) {
            throw new RuntimeException("SAML request storage has already contains key " + key);
        }

        samlRequestStorage.add(key);
    }

    public synchronized String storeRequest() {
        String key = null;
        while (true) {
            key = identifierGenerator.generateIdentifier(20);
            if (!samlRequestStorage.contains(key)) {
                storeRequest(key);
                break;
            }
        }
        return key;
    }

    public synchronized boolean exists(String key) {
        return samlRequestStorage.contains(key);
    }

    public synchronized void removeRequest(String key) {
        samlRequestStorage.remove(key);
    }
}
