package de.ronnyfriedland.pki.cert.validation;

import java.security.cert.X509Certificate;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;

/**
 * @author ronnyfriedland
 */
public interface Validator {

    /**
     * Validates the given {@link X509Certificate} with the custom validator implementation.
     * 
     * @param cert the certificate to validate
     * @throws CertificateValidationException exception if validation failed
     */
    void validate(final X509Certificate cert) throws CertificateValidationException;

}
