package de.ronnyfriedland.pki.cert.validation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;

public class CertificateValidatorTest {

    private X509Certificate validCert;
    private X509Certificate invalidCert;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setUp() throws Exception {
        Date startDate = new Date(0);
        Date expiryDate = new Date(Long.MAX_VALUE);

        validCert = generateTestCertificate(startDate, expiryDate);
        invalidCert = generateTestCertificate(startDate, startDate);
    }

    private X509Certificate generateTestCertificate(Date startDate, Date expiryDate) throws NoSuchAlgorithmException,
            CertificateEncodingException, NoSuchProviderException, SignatureException, InvalidKeyException {
        BigInteger serialNumber = new BigInteger("1");
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal dnName = new X500Principal("CN=Test CA Certificate");

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(dnName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(dnName); // note: same as issuer
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA1withRSA");

        return certGen.generate(keyPair.getPrivate(), "BC");
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testValidateDateRange() throws Exception {
        try {
            CertificateValidator.validateCertificate(invalidCert);
            Assert.fail("exception expected !");
        } catch (CertificateValidationException e) {
            // ok
        }
        try {
            CertificateValidator.validateCertificate(validCert);
        } catch (CertificateValidationException e) {
            throw e;
        }
    }
}
