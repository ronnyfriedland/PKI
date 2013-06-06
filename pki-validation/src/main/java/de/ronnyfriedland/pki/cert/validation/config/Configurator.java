package de.ronnyfriedland.pki.cert.validation.config;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;

/**
 * Application configuration
 * 
 * @author ronnyfriedland
 */
public final class Configurator {

    public final static CompositeConfiguration CONFIG = new CompositeConfiguration();
    static {
        try {
            CONFIG.addConfiguration(new PropertiesConfiguration(Thread.currentThread().getContextClassLoader()
                    .getResource("cert.properties")));
            CONFIG.setListDelimiter(',');
        } catch (ConfigurationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /**
     * Konfigurationsparameter
     */
    public enum ConfiguratorKeys {
        KEYUSAGES("keyusages"), EXTENDEDKEYUSAGES("extendedkeyusages"), ALGORITHM("algorithm");

        private final String key;

        private ConfiguratorKeys(final String aKey) {
            this.key = aKey;
        }

        /**
         * Liefert den Schlüssel des Konfigurationsparameters
         * 
         * @return Konfigurationsparameter
         */
        public String getKey() {
            return key;
        }
    }

    private Configurator() {
        // empty
    }
}
