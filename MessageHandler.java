

import java.io.StringWriter;
import java.util.Collections;
import java.util.Set;
import javax.xml.namespace.QName;
import javax.xml.soap.Node;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import org.apache.log4j.Logger;

public class MessageHandler
	implements SOAPHandler<SOAPMessageContext> {

    private Logger log;

    public MessageHandler(Logger log) {
	this.log = log;
	this.log.setAdditivity(false);
    }

    public boolean handleMessage(SOAPMessageContext messageContext) {
	boolean outbound = ((Boolean) messageContext.get("javax.xml.ws.handler.message.outbound")).booleanValue();
	SOAPMessage msg = messageContext.getMessage();
	if (outbound) {
	    return processOutputMessage(msg);
	}
	return processInputMessage(msg);
    }

    private boolean processOutputMessage(SOAPMessage msg) {
	this.log.info("Request: " + nodeToString(msg.getSOAPPart()));
	return true;
    }

    private boolean processInputMessage(SOAPMessage msg) {
	this.log.info("Response: " + nodeToString(msg.getSOAPPart()));
	return true;
    }

    public Set<QName> getHeaders() {
	return Collections.EMPTY_SET;
    }

    public boolean handleFault(SOAPMessageContext messageContext) {
	this.log.info("Fault: " + nodeToString(messageContext.getMessage().getSOAPPart()));
	return true;
    }

    public void close(MessageContext context) {
    }

    public String nodeToString(Node node) {
	try {
	    TransformerFactory tfactory = TransformerFactory.newInstance();
	    Transformer trans = null;
	    trans = tfactory.newTransformer();
	    trans.setOutputProperty("indent", "no");

	    DOMSource source = new DOMSource(node);
	    StringWriter writer = new StringWriter();
	    StreamResult res = new StreamResult(writer);
	    trans.transform(source, res);

	    return writer.toString();
	} catch (TransformerException ex) {
	}
	return "";
    }
}
