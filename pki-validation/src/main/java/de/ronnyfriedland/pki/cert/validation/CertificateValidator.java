package de.ronnyfriedland.pki.cert.validation;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import de.ronnyfriedland.pki.cert.validation.config.Configurator;
import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;

/**
 * Validates a given certificate with the configured validators.
 * 
 * @author ronnyfriedland
 */
public class CertificateValidator {

    private static final Set<Validator> validators = new HashSet<Validator>();
    static {
        validators.add(new DateRangeValidator());
        validators.add(new KeyUsageValidator(Configurator.CONFIG.getStringArray(Configurator.ConfiguratorKeys.KEYUSAGES
                .getKey())));
        validators.add(new ExtendedKeyUsageValidator(Configurator.CONFIG
                .getStringArray(Configurator.ConfiguratorKeys.EXTENDEDKEYUSAGES.getKey())));
        validators.add(new SignatureAlgorithmValidator(Configurator.CONFIG
                .getStringArray(Configurator.ConfiguratorKeys.ALGORITHM.getKey())));
    }

    public static void validateCertificate(X509Certificate cert) throws CertificateValidationException {
        if (null == cert) {
            throw new IllegalArgumentException("parameter cert not set");
        }
        for (Validator validator : validators) {
            validator.validate(cert);
        }
    }
}
