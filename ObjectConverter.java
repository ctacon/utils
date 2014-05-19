

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 *
 * @author ctacon
 */
public class ObjectConverter {

    public static String getXmlFromObject(Object request, String xsdPath) throws JAXBException, UnsupportedEncodingException, SAXException, Exception {
        Schema schema = null;
        if (xsdPath != null) {
            schema = javax.xml.validation.SchemaFactory
                    .newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                    .newSchema(new File(xsdPath));
        }
        JAXBContext context = JAXBContext.newInstance(request.getClass());
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        marshaller.setProperty(Marshaller.JAXB_ENCODING, "utf-8");
        marshaller.setSchema(schema);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        marshaller.marshal(request, baos);
        String bodyXml = baos.toString();
        return bodyXml;
    }

    public static String getXmlFromObject(Object request, String xsdPath, String rootElement) throws XMLStreamException, SAXException, JAXBException, UnsupportedEncodingException {
        Schema schema = null;
        if (xsdPath != null) {
            schema = javax.xml.validation.SchemaFactory
                    .newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                    .newSchema(new File(xsdPath));
        }
        XMLOutputFactory xof = XMLOutputFactory.newFactory();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xsw = xof.createXMLStreamWriter(baos);
        if (rootElement != null) {
            xsw.writeStartDocument();
            xsw.writeStartElement(rootElement);
        }
        JAXBContext context = JAXBContext.newInstance(request.getClass());
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
        marshaller.setSchema(schema);
        marshaller.marshal(request, xsw);
        if (rootElement != null) {
            xsw.writeEndElement();
            xsw.writeEndDocument();
            xsw.close();
        }
        return baos.toString();
    }

    public static Object getObjectFromBody(Class someClass, String xml) throws DocumentException, JAXBException {
        Document document = DocumentHelper.parseText(xml);
        Dom4jUtil.removeAllNamespaces(document);
        String res = document.asXML();
        JAXBContext jc = JAXBContext.newInstance(someClass);
        Unmarshaller u = jc.createUnmarshaller();
        return u.unmarshal(new StringReader(res));
    }

    public static Object getObjectFromBody(Class someClass, String xpath, String xml) throws DocumentException, JAXBException {
        Document document = DocumentHelper.parseText(xml);
        Dom4jUtil.removeAllNamespaces(document);
        String res = document.valueOf(xpath);
        JAXBContext jc = JAXBContext.newInstance(someClass);
        Unmarshaller u = jc.createUnmarshaller();
        return u.unmarshal(new StringReader(res));
    }

    public static String printNode(Element el) throws TransformerConfigurationException, TransformerException {
        TransformerFactory transfac = TransformerFactory.newInstance();
        Transformer trans = transfac.newTransformer();
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
        trans.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        StringWriter sw = new StringWriter();
        StreamResult result = new StreamResult(sw);
        DOMSource source = new DOMSource(el);
        trans.transform(source, result);
        return sw.toString();
    }

}
