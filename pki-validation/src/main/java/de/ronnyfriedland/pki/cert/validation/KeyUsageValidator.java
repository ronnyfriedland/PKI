package de.ronnyfriedland.pki.cert.validation;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x509.KeyUsage;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;
import de.ronnyfriedland.pki.cert.validation.ex.ValidationError;

public class KeyUsageValidator implements Validator {

    private final Set<Integer> allowedKeyUsages = new HashSet<Integer>();

    private enum KeyUsageEnum {

        digitalSignature(KeyUsage.digitalSignature), nonRepudiation(KeyUsage.nonRepudiation), keyEncipherment(
                KeyUsage.keyEncipherment), dataEncipherment(KeyUsage.dataEncipherment), keyAgreement(
                KeyUsage.keyAgreement), keyCertSign(KeyUsage.keyCertSign), cRLSign(KeyUsage.cRLSign), encipherOnly(
                KeyUsage.encipherOnly), decipherOnly(KeyUsage.decipherOnly);

        private Integer usage;

        private KeyUsageEnum(final Integer usage) {
            this.usage = usage;
        }

        public static Integer intValue(final String usage) {
            Integer result;
            try {
                result = KeyUsageEnum.valueOf(usage).usage;
            } catch (IllegalArgumentException e) {
                result = -1;
            }
            return result;
        }
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
                    this.allowedKeyUsages.add(KeyUsageEnum.intValue(allowedKeyUsage));
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
            for (int i = 0; i < KeyUsageEnum.values().length; i++) {
                if (keyUsages[i] && !allowedKeyUsages.contains(i)) {
                    throw new CertificateValidationException(ValidationError.KEYUSAGE, String.format(
                            "certificate contains invalid key usage: %s", keyUsages[i]));
                }
            }
        } else {
            if (0 < this.allowedKeyUsages.size()) {
                throw new CertificateValidationException(ValidationError.KEYUSAGE, String.format(
                        "certificate contains no key usage / required: %s.", this.allowedKeyUsages));
            }
        }
    }
}
