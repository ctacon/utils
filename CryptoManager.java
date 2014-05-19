

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

/**
 *
 * @author ctacon
 */
public class CryptoManager {

    public static Document sign(String request, PrivateKey privateKey,
            Certificate publicCertificate) throws Exception {
        DocumentBuilderFactory dbf
                = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document document = builder.parse(new ByteArrayInputStream(request.getBytes()));
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        DOMSignContext dsc = new DOMSignContext(privateKey, document.getDocumentElement());
        Reference manifestRef = fac.newReference("#mainData",
                fac.newDigestMethod(DigestMethod.SHA1, null),
                Collections.singletonList(fac.newTransform(Transform.ENVELOPED,
                (TransformParameterSpec) null)), null, null);
        Manifest manifest = fac.newManifest(Collections.singletonList(manifestRef), "metaData");

        Reference ref = fac.newReference("#metaData", fac.newDigestMethod(DigestMethod.SHA1, null),
                Collections.singletonList(fac.newTransform(Transform.ENVELOPED,
                (TransformParameterSpec) null)), null, null);
//        Reference ref1 = fac.newReference("#Obj1",
//                fac.newDigestMethod(DigestMethod.SHA1, null),
//                Collections.singletonList(fac.newTransform(Transform.ENVELOPED,
//                (TransformParameterSpec) null)), null, null);

        List<Reference> referenceList = new LinkedList<Reference>();
        referenceList.add(ref);
//        referenceList.add(ref1);
        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(
                CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                referenceList);

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<Object> dataList = new LinkedList<Object>();
        dataList.add(publicCertificate);
        X509Data x509Data = kif.newX509Data(dataList);
        javax.xml.crypto.dsig.keyinfo.KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data),
                null);

        XMLSignature signature = fac.newXMLSignature(si, ki, null, "Sig1", null);
        signature.sign(dsc);
        return document;
    }

    public static Pair<PrivateKey, Certificate> loadKeys(String keystorePath, String keystorePassword) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
        String al = null;
        while (ks.aliases().hasMoreElements()) {
            al = ks.aliases().nextElement();
            if (ks.isKeyEntry(al)) {
                break;
            }
        }
        if (al != null) {
            return new Pair<PrivateKey, Certificate>(
                    (PrivateKey) ks.getKey(al, keystorePassword.toCharArray()),
                    ks.getCertificate(al));
        } else {
            return null;
        }
    }
}
