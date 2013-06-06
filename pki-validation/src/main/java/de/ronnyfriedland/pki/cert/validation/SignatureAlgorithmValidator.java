package de.ronnyfriedland.pki.cert.validation;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import org.apache.commons.lang.StringUtils;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;
import de.ronnyfriedland.pki.cert.validation.ex.ValidationError;

/**
 * Validates the used algorithm of the certificate
 * 
 * @author ronnyfriedland
 */
public class SignatureAlgorithmValidator implements Validator {

    private final Set<String> allowedAlgorithms = new HashSet<String>();

    /**
     * Creates an new instance of {@link KeyUsageValidator}.
     * 
     * @param allowedAlgorithms
     *            list of allowed algorithms
     */
    public SignatureAlgorithmValidator(String... allowedAlgorithms) {
        if (null != allowedAlgorithms && 0 < allowedAlgorithms.length) {
            for (String allowedAlgorithm : allowedAlgorithms) {
                if (StringUtils.isNotBlank(allowedAlgorithm)) {
                    this.allowedAlgorithms.add(allowedAlgorithm.toLowerCase(Locale.getDefault()));
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
        String sigAlg = cert.getSigAlgName().toLowerCase(Locale.getDefault());
        if (!this.allowedAlgorithms.isEmpty() && !this.allowedAlgorithms.contains(sigAlg)) {
            throw new CertificateValidationException(ValidationError.ALGORITHM, String.format(
                    "invalid signature algorithm %s / allowed: %s", sigAlg, this.allowedAlgorithms));
        }
    }
}
