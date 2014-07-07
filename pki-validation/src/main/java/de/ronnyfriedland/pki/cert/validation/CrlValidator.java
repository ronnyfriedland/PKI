package de.ronnyfriedland.pki.cert.validation;

import de.ronnyfriedland.pki.cert.validation.ex.CertificateValidationException;
import de.ronnyfriedland.pki.cert.validation.ex.ValidationError;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by ronnyfriedland on 06.07.14.
 */
public class CrlValidator implements Validator {

    /**
     * {@inheritDoc}
     *
     * @see de.ronnyfriedland.pki.cert.validation.Validator#validate(java.security.cert.X509Certificate)
     */
    @Override
    public void validate(X509Certificate cert) throws CertificateValidationException {
        try {
            List<String> urls = getCrlUrls(cert);
            for (String url : urls) {
                URL crlUrl = new URL(url);
                InputStream crlStream = crlUrl.openStream();
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
                    if (crl.isRevoked(cert)) {
                        throw new CertificateValidationException(ValidationError.REVOKED, "certificate is revoked");
                    }
                } finally {
                    crlStream.close();
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private List<String> getCrlUrls(X509Certificate cert) throws IOException {
        List<String> resultList = new ArrayList<String>();
        byte[] crlDistributionPoints = cert.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        if (null != crlDistributionPoints) {
            ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crlDistributionPoints));
            DERObject derObjCrlDP = oAsnInStream.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(dosCrlDP.getOctetStream());
            DERObject derObj2 = oAsnInStream2.readObject();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (null != dpn) {
                    if (dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                        for(GeneralName genName : genNames) {
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
}
