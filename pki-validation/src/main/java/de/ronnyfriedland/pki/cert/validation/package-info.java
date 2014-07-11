/**
 * Contains all checker classes for certificate validation. All validation classes implement the 
 * {@link de.ronnyfriedland.pki.cert.validation.Validator} interface which provides a method 
 * {@link de.ronnyfriedland.pki.cert.validation.Validator#validate(java.security.cert.X509Certificate)} to implement 
 * the custom validation method.
 * 
 * There are several pre-defined validation classes available:
 * <ul>
 * <li>{@link de.ronnyfriedland.pki.cert.validation.CrlValidator}</li>
 * <li>{@link de.ronnyfriedland.pki.cert.validation.DateRangeValidator}</li>
 * <li>{@link de.ronnyfriedland.pki.cert.validation.ExtendedKeyUsageValidator}</li>
 * <li>{@link de.ronnyfriedland.pki.cert.validation.KeyUsageValidator}</li>
 * <li>{@link de.ronnyfriedland.pki.cert.validation.SignatureAlgorithmValidator}</li>
 * </ul>
 * 
 * If you need all of the validation classes mentioned above you can use the 
 * {@link de.ronnyfriedland.pki.cert.validation.CertificateValidator#validateCertificate(java.security.cert.X509Certificate)} 
 * to validate your {@link java.security.cert.X509Certificate} against all validators.
 * <br/><br/>
 * You you need to implement your own {@link de.ronnyfriedland.pki.cert.validation.Validator} or you do not need all of 
 * the validators, it is possible to define your collection of validators and pass it to the 
 * {@link de.ronnyfriedland.pki.cert.validation.CertificateValidator#validateCertificate(java.security.cert.X509Certificate, Validator...)}.
 * 
 * @author ronnyfriedland
 */
package de.ronnyfriedland.pki.cert.validation;