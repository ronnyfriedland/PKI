package de.ronnyfriedland.pki.cert.validation.ex;

public class CertificateValidationException extends Exception {

    private static final long serialVersionUID = -686252088301546826L;

    private final ValidationError validationError;

    public CertificateValidationException(final ValidationError error, final Throwable cause) {
        super(cause);
        this.validationError = error;
    }

    public CertificateValidationException(final ValidationError error, final String message) {
        super(message);
        this.validationError = error;
    }

    /**
     * {@inheritDoc}
     * 
     * @see java.lang.Throwable#toString()
     */
    @Override
    public String toString() {
        StringBuilder sbuild = new StringBuilder(super.toString());
        sbuild.append("[error: ").append(validationError).append("]");
        return sbuild.toString();
    }
}
