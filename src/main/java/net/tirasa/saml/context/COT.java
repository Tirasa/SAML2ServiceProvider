/* 
 * Copyright 2015 Tirasa.
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

package net.tirasa.saml.context;

import java.util.HashMap;
import java.util.Map;

public class COT {

    private static final String ts = "Thead Safe Access";

    private final Map<String, IdP> IDPs;

    private SP sp;

    private static COT cot;

    private COT() {
        this.IDPs = new HashMap<>();
    }

    public static COT getInstance() {
        synchronized (ts) {
            if (cot == null) {
                cot = new COT();
            }

            return cot;
        }
    }

    /**
     * Gets IdP with the given entity ID.
     *
     * @param entityID IdP ID.
     * @return IdP.
     */
    public IdP getIdP(final String entityID) {
        return entityID == null ? getIdP() : IDPs.get(entityID);
    }

    /**
     * Gets random IdP.
     *
     * @return IdP.
     */
    public IdP getIdP() {
        return IDPs.isEmpty() ? null : IDPs.values().iterator().next();
    }

    /**
     * Adds IdP to the COT.
     *
     * @param entityID IdP ID.
     * @param idp IdP.
     * @return IdP.
     */
    IdP addIdP(final String entityID, final IdP idp) {
        return IDPs.put(entityID, idp);
    }

    /**
     * Gets local SP.
     *
     * @return SP.
     */
    public SP getSp() {
        return sp;
    }

    /**
     * Sets local SP.
     *
     * @param sp SP.
     */
    void setSp(SP sp) {
        this.sp = sp;
    }

}
