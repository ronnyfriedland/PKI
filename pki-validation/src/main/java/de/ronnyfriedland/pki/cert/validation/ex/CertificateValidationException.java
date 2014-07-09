package de.ronnyfriedland.pki.cert.validation.ex;

/**
 * Exception whic his thrown if certificate is invalid.
 * 
 * @author ronnyfriedland
 */
public class CertificateValidationException extends Exception {

    /** The serialVersionUID */
    private static final long serialVersionUID = -686252088301546826L;

    /** The validation error */
    private transient final ValidationError validationError;

    /**
     * Creates a new CertificateValidationException instance.
     * 
     * @param error the validation error
     * @param cause the cause
     */
    public CertificateValidationException(final ValidationError error, final Throwable cause) {
        super(cause);
        this.validationError = error;
    }

    /**
     * Creates a new CertificateValidationException instance.
     * 
     * @param error the validation error
     * @param message the error description
     */
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
        final StringBuilder sbuild = new StringBuilder(super.toString());
        sbuild.append("[error: ").append(validationError).append(']');
        return sbuild.toString();
    }
}
