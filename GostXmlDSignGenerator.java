
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Iterator;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.io.DOMReader;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import java.io.File;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.dom.DOMResult;
import org.bouncycastle.openssl.PEMReader;
import org.dom4j.io.DocumentSource;
import org.w3c.dom.Element;

/**
 * Формирует подпись по стандарту 1.5 XMLDSig. Алгоритм GOST Требуются либы :
 * XMLDSigRI.jar,xmlsec-1.5.0.jar Должен быть настроен criptoPro Ссылки:
 * http://www.java2s.com/Code/JavaAPI/javax.xml.crypto.dsig/XMLSignatureFactorynewXMLSignatureSignedInfosiKeyInfoki.htm
 * http://docs.oracle.com/javase/6/docs/api/javax/xml/crypto/dsig/XMLSignatureFactory.html
 * http://docs.oracle.com/cd/E17802_01/webservices/webservices/docs/1.6/tutorial/doc/XMLDigitalSignatureAPI8.html
 * http://www.java.net/node/672119 *
 * http://cryptopro.ru/forum2/Default.aspx?g=posts&t=4988
 * https://gist.github.com/3742724
 * http://cryptopro.ru/forum2/default.aspx?g=posts&m=25360
 * http://docs.oracle.com/javase/7/docs/technotes/guides/security/xmldsig/XMLDigitalSignature.html
 *
 * @author ctacon
 */
public class GostXmlDSignGenerator {

    private Logger logger;

    public GostXmlDSignGenerator(Logger logger) {
	this.logger = logger;
    }

    public Document generateSig(Document d, String requestType, String privateKeyPath, String publicCertPath) {
	try {
	    if (d == null) {
		throw new Exception("Отсутcвует документ для подписи!");
	    }
	    logger.debug("получил xml : " + d.asXML());
	    // Загрузка провайдера.
	    Provider xmlDSigProvider = new ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI();
	    logger.debug("xmlDSigProvider: " + xmlDSigProvider);
//	    org.w3c.dom.Document document = stringToDom(d.asXML(), requestType);
	    org.w3c.dom.Document document = copy(d, requestType);
	    KeyStore hdImageStore = KeyStore.getInstance("HDImageStore");
	    hdImageStore.load(null, null);
	    PrivateKey privateKey = (PrivateKey) hdImageStore.getKey(privateKeyPath, null);
	    logger.info("private-key-alg = " + privateKey.getAlgorithm());

	    PEMReader publicCertreader = new PEMReader(new FileReader(new File(publicCertPath)), null);
	    X509Certificate publicCert = (X509Certificate) publicCertreader.readObject();

	    XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance("DOM", xmlDSigProvider);

	    DOMSignContext dsc = new DOMSignContext(privateKey, document.getDocumentElement());

	    //Преобразования над узлом ds:SignedInfo:
	    List<Transform> transformList = new ArrayList<Transform>();
	    Transform transformC14N = sigFactory.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", (TransformParameterSpec) null);
	    transformList.add(transformC14N);

	    // Ссылка на подписываемые данные с алгоритмом хеширования ГОСТ 34.11.
	    logger.info("elementbyID = " + document.getElementById("#DocData"));
	    logger.info("elementbyID = " + document.getElementById("DocData"));
	    // logger.debug("node = " + printNode(document.getElementById("DocData")));
	    Reference ref = sigFactory.newReference("#DocData",
		    sigFactory.newDigestMethod("http://www.w3.org/2001/04/xmldsig-more#gostr3411", null),
		    transformList,
		    null,
		    null);
	    //Задаем алгоритм подписи:
	    SignedInfo signedInfo = sigFactory.newSignedInfo(
		    sigFactory.newCanonicalizationMethod(
		    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
		    (C14NMethodParameterSpec) null),
		    sigFactory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", null),
		    Collections.singletonList(ref));

	    KeyInfoFactory kif = sigFactory.getKeyInfoFactory();
	    X509Data x509Data = kif.newX509Data(Collections.singletonList(publicCert));
	    KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data), "KeyInfo");

	    javax.xml.crypto.dsig.XMLSignature xmlSig = sigFactory.newXMLSignature(signedInfo, ki);
	    dsc.setDefaultNamespacePrefix("ds");
	    xmlSig.sign(dsc);

	    return domToDom4j(document);
	} catch (Throwable ex) {
	    logger.error(ex, ex);
	    return null;
	}
    }

    private String printDocument(org.w3c.dom.Document doc) throws IOException, TransformerException {

	TransformerFactory tf = TransformerFactory.newInstance();
	Transformer transformer = tf.newTransformer();
	transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
	transformer.setOutputProperty(OutputKeys.METHOD, "xml");
	transformer.setOutputProperty(OutputKeys.INDENT, "yes");
	transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
	transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
	StringWriter sw = new StringWriter();
	transformer.transform(new DOMSource(doc),
		new StreamResult(sw));
	sw.flush();
	return sw.toString();
    }

    private String printNode(Element el) throws TransformerConfigurationException, TransformerException {
	TransformerFactory transfac = TransformerFactory.newInstance();
	Transformer trans = transfac.newTransformer();
	trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
	trans.setOutputProperty(OutputKeys.INDENT, "yes");
	StringWriter sw = new StringWriter();
	StreamResult result = new StreamResult(sw);
	DOMSource source = new DOMSource(el);
	trans.transform(source, result);
	return sw.toString();
    }

    /**
     * Проверка подписи. 
     *
     * @param d
     * @param validatioKeyPath
     * @return
     */
    public boolean verifySign(Document d, String validatioKeyPath) {
	try {
	    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    dbf.setNamespaceAware(true);
	    DocumentBuilder builder = dbf.newDocumentBuilder();

	    org.w3c.dom.Document doc = builder.parse(new ByteArrayInputStream(d.asXML().getBytes()));

	    PEMReader validationCertreader = new PEMReader(new FileReader(new File(validatioKeyPath)), null);
	    X509Certificate validationCert = (X509Certificate) validationCertreader.readObject();
	    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
	    if (nl.getLength() == 0) {
		logger.error("Не могу найти подпись!");
		return false;
	    }
	    DOMValidateContext valContext = new DOMValidateContext(validationCert.getPublicKey(), nl.item(0));
	    XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
	    XMLSignature signature = factory.unmarshalXMLSignature(valContext);
	    boolean coreValidity = signature.validate(valContext);
	    if (coreValidity == false) {
		logger.error("Подпись не прошла проверку. Ищу причину!");
		boolean sv = signature.getSignatureValue().validate(valContext);
		logger.info("signature validation status: " + sv);
		Iterator i = signature.getSignedInfo().getReferences().iterator();
		for (int j = 0; i.hasNext(); j++) {
		    boolean refValid = ((Reference) i.next()).validate(valContext);
		    logger.info("ref[" + j + "] validity status: " + refValid);
		}
	    }
	    return coreValidity;
	} catch (Exception ex) {
	    logger.error(ex, ex);
	    return false;
	}
    }

    private org.w3c.dom.Document stringToDom(String xmlSource, String tagName)
	    throws SAXException, ParserConfigurationException, IOException {
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	factory.setNamespaceAware(true);
	DocumentBuilder builder = factory.newDocumentBuilder();
	org.w3c.dom.Document doc = builder.parse(new InputSource(new StringReader(xmlSource)));
	if (tagName != null && !tagName.isEmpty()) {
	    //обход багов org.w3c.dom.Document
	    Element el = (Element) doc.getElementsByTagName(tagName).item(0);
	    el.setIdAttribute("Id", true);
	}
	return doc;
    }

    private org.dom4j.Document domToDom4j(org.w3c.dom.Document input) {
	org.dom4j.io.DOMReader reader = new DOMReader();
	org.dom4j.Document document = reader.read(input);
//	document.setXMLEncoding("windows-1251");
	return document;
    }

    static org.w3c.dom.Document copy(org.dom4j.Document orig, String tagName) {
	try {
	    TransformerFactory tf = TransformerFactory.newInstance();
	    Transformer t = tf.newTransformer();
	    DOMResult result = new DOMResult();
	    t.transform(new DocumentSource(orig), result);
	    org.w3c.dom.Document document = (org.w3c.dom.Document) result.getNode();
	    if (tagName != null && !tagName.isEmpty()) {
		Element el = (Element) document.getElementsByTagName(tagName).item(0);
		el.setIdAttribute("Id", true);
	    }
	    return document;
	} catch (Exception e) {
	    throw new RuntimeException(e);
	}
    }
}
