package de.ronnyfriedland.pki.cert.validation;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.StringUtils;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;
import de.ronnyfriedland.pki.cert.validation.ex.ValidationError;

public class KeyUsageValidator implements Validator {

    private final Set<String> allowedKeyUsages = new HashSet<String>();

    private final List<String> KEY_USAGES = new ArrayList<String>();
    {
        KEY_USAGES.add("digitalSignature");
        KEY_USAGES.add("nonRepudiation");
        KEY_USAGES.add("keyEncipherment");
        KEY_USAGES.add("dataEncipherment");
        KEY_USAGES.add("keyAgreement");
        KEY_USAGES.add("keyCertSign");
        KEY_USAGES.add("cRLSign");
        KEY_USAGES.add("encipherOnly");
        KEY_USAGES.add("decipherOnly");
    }

    /**
     * Creates an new instance of {@link KeyUsageValidator}.
     * 
     * @param allowedKeyUsage
     *            list of allowed key usages
     */
    public KeyUsageValidator(String... allowedKeyUsages) {
        if (null != allowedKeyUsages && 0 < allowedKeyUsages.length) {
            for (String allowedKeyUsage : allowedKeyUsages) {
                if (StringUtils.isNotBlank(allowedKeyUsage)) {
                    this.allowedKeyUsages.add(allowedKeyUsage);
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
        boolean[] keyUsages = cert.getKeyUsage();
        if (null != keyUsages) {
            for (int i = 0; i < 9; i++) {
                if (keyUsages[i] && !this.allowedKeyUsages.contains(this.KEY_USAGES.get(i))) {
                    throw new CertificateValidationException(ValidationError.KEYUSAGE, String.format(
                            "certificate contains invalid key usage: %s", this.KEY_USAGES.get(i)));
                }
            }
        } else {
            if (0 < this.allowedKeyUsages.size()) {
                throw new CertificateValidationException(ValidationError.KEYUSAGE, String.format(
                        "certificate contains no key usage / allowed: %s.", this.allowedKeyUsages));
            }
        }
    }

}
