package de.ronnyfriedland.pki.cert.validation;

import java.security.cert.X509Certificate;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;

/**
 * @author ronnyfriedland
 */
public interface Validator {

    public void validate(final X509Certificate cert) throws CertificateValidationException;

}
