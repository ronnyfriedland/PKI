package de.ronnyfriedland.pki.cert.validation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;
import de.ronnyfriedland.pki.cert.validation.ex.ValidationError;

/**
 * Check if certificate is revoked (against crl)
 * 
 * @author ronnyfriedland
 */
public class CrlValidator implements Validator {

    /**
     * {@inheritDoc}
     * 
     * @see de.ronnyfriedland.pki.cert.validation.Validator#validate(java.security.cert.X509Certificate)
     */
    @Override
    public void validate(final X509Certificate cert) throws CertificateValidationException {
        try {
            final List<String> urls = getCrlUrls(cert);
            for (final String url : urls) {
                final URL crlUrl = new URL(url);
                final InputStream crlStream = crlUrl.openStream();
                try {
                    final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    X509CRL crl = (X509CRL) certFactory.generateCRL(crlStream);
                    if (crl.isRevoked(cert)) {
                        throw new CertificateValidationException(ValidationError.REVOKED, "certificate is revoked");
                    }
                } finally {
                    IOUtils.closeQuietly(crlStream);
                }
            }
        } catch (IOException | CertificateException | CRLException e) {
            throw new CertificateValidationException(ValidationError.INVALID, e);
        }
    }

    private List<String> getCrlUrls(final X509Certificate cert) throws IOException {
        List<String> resultList = new ArrayList<String>();
        byte[] crlDistributionPoints = cert.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        if (null != crlDistributionPoints) {
            DERObject derCrlDP = readCrlDP(new ByteArrayInputStream(crlDistributionPoints));
            DEROctetString dosCrlDP = (DEROctetString) derCrlDP;
            derCrlDP = readCrlDP(dosCrlDP.getOctetStream());
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derCrlDP);
            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (null != dpn) {
                    if (dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                        for (GeneralName genName : genNames) {
                            if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                String url = DERIA5String.getInstance(genName.getName()).getString();
                                resultList.add(url);
                            }
                        }
                    }
                }
            }
        }
        return resultList;
    }

    private DERObject readCrlDP(final InputStream inStream) throws IOException {
        ASN1InputStream oAsnInStream = null;
        DERObject derCrlDP = null;
        try {
            oAsnInStream = new ASN1InputStream(inStream);
            derCrlDP = oAsnInStream.readObject();
        } finally {
            IOUtils.closeQuietly(oAsnInStream);
        }
        return derCrlDP;
    }
}
