package de.ronnyfriedland.pki.cert.validation;

import java.security.cert.X509Certificate;
import java.util.Calendar;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;
import de.ronnyfriedland.pki.cert.validation.ex.ValidationError;

/**
 * Validates the date range of the certificate.
 * 
 * @author ronnyfriedland
 */
public class DateRangeValidator implements Validator {

    /**
     * {@inheritDoc}
     * 
     * @see de.ronnyfriedland.pki.cert.validation.Validator#validate(java.security.cert.X509Certificate)
     */
    public void validate(X509Certificate cert) throws CertificateValidationException {
        Calendar now = Calendar.getInstance();
        if (now.getTime().before(cert.getNotBefore()) || now.getTime().after(cert.getNotAfter())) {
            throw new CertificateValidationException(ValidationError.DATE_RANGE, "date range of certificate not valid");
        }
        now.add(Calendar.DAY_OF_MONTH, -1);
        if (now.getTime().after(cert.getNotAfter())) {
            throw new CertificateValidationException(ValidationError.DATE_RANGE,
                    "certificate will expire withing the next 24 hours");
        }
    }

}
