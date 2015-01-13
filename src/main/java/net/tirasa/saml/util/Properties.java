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

package net.tirasa.saml.util;

import java.io.IOException;
import org.slf4j.LoggerFactory;

public class Properties {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(Properties.class);

    private static final java.util.Properties prop = new java.util.Properties();

    static {
        try {
            prop.load(Properties.class.getResourceAsStream("/services.properties"));
        } catch (IOException e) {
            log.warn("Error loading global properties", e);
        }
    }

    public static String getString(final String key) {
        return prop.getProperty(key);
    }

    public static String getString(final String key, final String def) {
        return prop.getProperty(key, def);
    }

    public static boolean getBoolean(final String key, final boolean def) {
        final String res = prop.getProperty(key);
        return res == null ? def : Boolean.parseBoolean(res);
    }

    public static String[] getStringArray(final String key, final String[] def) {
        final String res = prop.getProperty(key);
        return res == null ? def : res.split(" ");
    }
}
