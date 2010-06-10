package com.protocol7.smime;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMESigned;

public class Verify {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Properties props = System.getProperties();

        Session session = Session.getDefaultInstance(props, null);

        MimeMessage msg = new MimeMessage(session, new FileInputStream("signed.message"));

        SMIMESigned signedMessage;
        
        // make sure this was a multipart/signed message - there should be
        // two parts as we have one part for the content that was signed and
        // one part for the actual signature.
        if (msg.isMimeType("multipart/signed")) {
            signedMessage = new SMIMESigned((MimeMultipart) msg.getContent());
        } else if (msg.isMimeType("application/pkcs7-mime") || msg.isMimeType("application/x-pkcs7-mime")) {
            // in this case the content is wrapped in the signature block.
            signedMessage = new SMIMESigned(msg);
        } else {
            throw new IllegalArgumentException("Not a signed message!");
        }

        MimeBodyPart content = signedMessage.getContent();

        Object cont = content.getContent();

        System.out.println("Content: " + extractContent(cont));

        verify(signedMessage);
    }

    /**
     * verify the signature (assuming the cert is contained in the message)
     */
    @SuppressWarnings("unchecked")
    private static void verify(SMIMESigned signedMessage) throws Exception {
        CertStore certs = signedMessage.getCertificatesAndCRLs("Collection", "BC");

        SignerInformationStore signers = signedMessage.getSignerInfos();

        for(Object signerObj : signers.getSigners()) {
            SignerInformation signer = (SignerInformation) signerObj;
            Collection certCollection = certs.getCertificates(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate) certIt.next();

            System.out.println("Signed by: " + cert);
            
            // verify that the sig is correct and that it was generated
            // when the certificate was current
            if (signer.verify(cert, "BC")) {
                System.out.println("signature verified");
            } else {
                System.out.println("signature failed!");
            }
        }
    }

    private static String extractSingleContext(Object cont) throws IOException {
        if (cont instanceof String) {
            return (String) cont;
        } else if(cont instanceof InputStream) {
            BufferedReader reader = new BufferedReader(new InputStreamReader((InputStream) cont));
            
            StringBuffer sb = new StringBuffer();
            String line = reader.readLine();
            while(line != null) {
                sb.append(line);
                sb.append('\n');
                line = reader.readLine();
            }
            
            return sb.toString();
        } else {
            throw new IllegalArgumentException("Unknown content object " + cont.getClass());
        }
    }
    
    private static List<String> extractContent(Object cont) throws MessagingException, IOException {
        List<String> result = new ArrayList<String>();
        if (cont instanceof Multipart) {
            Multipart mp = (Multipart) cont;
            int count = mp.getCount();
            for (int i = 0; i < count; i++) {
                BodyPart m = mp.getBodyPart(i);
                Object part = m.getContent();

                result.add(extractSingleContext(part));
            }
        } else {
            result.add(extractSingleContext(cont));
        }
        
        return result;
    }
    

}
