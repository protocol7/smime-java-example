package com.protocol7.smime;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;

public class Sign {
    public static void main(String args[]) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("keystore"), "password".toCharArray());
        
        List<Certificate> certList = new ArrayList<Certificate>();

        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = ks.getCertificate(alias);
            if(cert != null) {
                certList.add(cert);
            }
        }
        
        PrivateKey key = (PrivateKey) ks.getKey("sign", "password".toCharArray());
        X509Certificate signCert = (X509Certificate) ks.getCertificate("sign");
        
        // create a CertStore containing the certificates we want carried
        // in the signature
        CertStore certsAndcrls = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");

        // create the generator for creating an smime/signed message
        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        // add a signer to the generator - this specifies we are using SHA1 and
        // adding the smime attributes above to the signed attributes that
        // will be generated as part of the signature. The encryption algorithm
        // used is taken from the key - in this RSA with PKCS1Padding
        gen.addSigner(key, signCert, SMIMESignedGenerator.DIGEST_SHA1);

        // add our pool of certs and cerls (if any) to go with the signature
        gen.addCertificatesAndCRLs(certsAndcrls);

        MimeBodyPart msg = new MimeBodyPart();
        msg.setContent("<somexml />", "application/xml");

        // sign
        MimeMultipart mm = gen.generate(msg, "BC");

        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        MimeMessage body = new MimeMessage(session);
        body.setContent(mm, mm.getContentType());
        body.saveChanges();

        body.writeTo(System.out);
        body.writeTo(new FileOutputStream("signed.message"));
    }
}
