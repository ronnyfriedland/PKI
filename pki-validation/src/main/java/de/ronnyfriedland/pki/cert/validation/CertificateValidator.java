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
        validators.add(new CrlValidator());
    }

    /**
     * Validates the certificate using the configured {@link Validator} implementations within {@link #validators}
     * 
     * @param cert the certificate to validate
     * @throws CertificateValidationException if validation failed (cret invalid)
     */
    public static void validateCertificate(final X509Certificate cert) throws CertificateValidationException {
        if (null == cert) {
            throw new IllegalArgumentException("parameter cert not set");
        }
        for (Validator validator : validators) {
            validator.validate(cert);
        }
    }

    /**
     * Validates the certificate using a custom list of {@link Validator}
     * 
     * @param cert the certificate to validate
     * @param validators custom validators
     * @throws CertificateValidationException if validation failed (cret invalid)
     */
    public static void validateCertificate(final X509Certificate cert, final Validator... validators)
            throws CertificateValidationException {
        if (null == cert) {
            throw new IllegalArgumentException("parameter cert not set");
        }
        if ((null == validators) || (0 >= validators.length)) {
            throw new IllegalArgumentException("parameter validators not set");
        }
        for (Validator validator : validators) {
            validator.validate(cert);
        }
    }

}
