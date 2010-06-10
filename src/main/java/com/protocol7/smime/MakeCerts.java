package com.protocol7.smime;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class MakeCerts {
    static int serialNo = 1;

    static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey pub) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(pub.getEncoded());
        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(bIn).readObject());

        return new AuthorityKeyIdentifier(info);
    }

    static SubjectKeyIdentifier createSubjectKeyId(PublicKey pub) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(pub.getEncoded());

        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(bIn).readObject());

        return new SubjectKeyIdentifier(info);
    }

    /**
     * create a basic X509 certificate from the given keys
     */
    static X509Certificate makeCertificate(KeyPair subKP, String subDN, KeyPair issKP, String issDN)
            throws GeneralSecurityException, IOException {
        PublicKey subPub = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey issPub = issKP.getPublic();

        X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();

        v3CertGen.setSerialNumber(BigInteger.valueOf(serialNo++));
        v3CertGen.setIssuerDN(new X509Name(issDN));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis()));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)));
        v3CertGen.setSubjectDN(new X509Name(subDN));
        v3CertGen.setPublicKey(subPub);
        v3CertGen.setSignatureAlgorithm("MD5WithRSAEncryption");

        v3CertGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, createSubjectKeyId(subPub));

        v3CertGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, createAuthorityKeyId(issPub));

        return v3CertGen.generate(issPriv);
    }

    public static void main(String args[]) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(1024, new SecureRandom());

        String signDN = "O=Callista, C=SE";
        KeyPair signKP = kpg.generateKeyPair();
        X509Certificate signCert = makeCertificate(signKP, signDN, signKP, signDN);

        
        String origDN = "CN=Niklas Gustavsson, O=Callista, C=SE";
        KeyPair origKP = kpg.generateKeyPair();
        X509Certificate origCert = makeCertificate(origKP, origDN, signKP, signDN);
        
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("sign", signKP.getPrivate(), "password".toCharArray(), new Certificate[]{origCert, signCert});
        ks.store(new FileOutputStream("keystore"), "password".toCharArray());
    }
}
