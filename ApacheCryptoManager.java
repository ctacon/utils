

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *
 * @author ctacon
 */
public class ApacheCryptoManager {

    public static String CHARSET = "utf-8";

    public static String sign(String request, PrivateKey privateKey,
            Certificate publicCertificate) throws Exception {
        String digestAlgo = Constants.ALGO_ID_DIGEST_SHA1;
        String signAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;

        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(request.getBytes(CHARSET)));
        XMLSignature sig = new org.apache.xml.security.signature.XMLSignature(
                doc, "", signAlgo);
        Element root = doc.createElementNS("", "Document");
        root.setAttribute("stan", String.valueOf(System.currentTimeMillis()));
        root.appendChild(sig.getElement());
        ObjectContainer obj = new ObjectContainer(doc);
        obj.appendChild(doc.getDocumentElement());
        String Id = "Res0";
        obj.setId(Id);
        sig.appendObject(obj);
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("#" + Id, transforms, digestAlgo, null,
                Reference.OBJECT_URI);
        sig.addKeyInfo((X509Certificate) publicCertificate);
        sig.sign(privateKey);
        return print(root,CHARSET);
    }

    public static String print(Node xml, String encoding)
            throws Exception {
        Transformer transformer = TransformerFactory.newInstance()
                .newTransformer();
        StreamResult result = new StreamResult(new StringWriter());
        DOMSource source = new DOMSource(xml, encoding);
        transformer.transform(source, result);
        String xmlString = result.getWriter().toString();
        return xmlString;
    }
}
