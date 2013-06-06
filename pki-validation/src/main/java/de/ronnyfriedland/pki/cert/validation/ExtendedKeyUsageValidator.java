package de.ronnyfriedland.pki.cert.validation;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.StringUtils;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;
import de.ronnyfriedland.pki.cert.validation.ex.ValidationError;

public class ExtendedKeyUsageValidator implements Validator {

    private final Set<String> allowedExtendedKeyUsages = new HashSet<String>();

    /**
     * Creates an new instance of {@link ExtendedKeyUsageValidator}.
     * 
     * @param allowedExtendedKeyUsages
     *            list of allowed extended key usages
     */
    public ExtendedKeyUsageValidator(String... allowedExtendedKeyUsages) {
        if (null != allowedExtendedKeyUsages && 0 < allowedExtendedKeyUsages.length) {
            for (String allowedKeyUsage : allowedExtendedKeyUsages) {
                if (StringUtils.isNotBlank(allowedKeyUsage)) {
                    this.allowedExtendedKeyUsages.add(allowedKeyUsage);
                }
            }
        }
    }

    /**
     * {@inheritDoc}
     * 
     * @see de.ronnyfriedland.pki.cert.validation.Validator#validate(java.security.cert.X509Certificate)
     */
    public void validate(X509Certificate cert) throws CertificateValidationException {
        try {
            List<String> keyUsages = cert.getExtendedKeyUsage();
            if (null != keyUsages) {
                for (String keyUsage : keyUsages) {
                    if (!this.allowedExtendedKeyUsages.contains(keyUsage)) {
                        throw new CertificateValidationException(ValidationError.EXTENDED_KEYUSAGE, String.format(
                                "certificate contains invalid extended key usage / allowed: %s.",
                                this.allowedExtendedKeyUsages));
                    }
                }
            } else {
                if (0 < this.allowedExtendedKeyUsages.size()) {
                    throw new CertificateValidationException(ValidationError.EXTENDED_KEYUSAGE, String.format(
                            "certificate contains no extended key usage / allowed: %s.", this.allowedExtendedKeyUsages));
                }
            }
        } catch (CertificateParsingException e) {
            throw new CertificateValidationException(ValidationError.INVALID, e);
        }
    }

}
