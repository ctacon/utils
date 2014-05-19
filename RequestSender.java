
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.log4j.Logger;

/**
 *
 * @author ctacon
 */
public class RequestSender {

    public static String send(Logger logger, String host, String port,String request) {
        try {
//            logger.debug("request = " + request);
            SSLContext sslContext = SSLContext.getInstance("GostTLS");
            KeyManager[] keyManagers = null;
            TrustManager[] trustManagers = null;
            trustManagers = new TrustManager[1];
            trustManagers[0] = new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] chain,
                        String authType) throws CertificateException {
                }

                public void checkClientTrusted(X509Certificate[] chain,
                        String authType) throws CertificateException {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            };

            sslContext.init(keyManagers, trustManagers, new SecureRandom());
            SSLSocket socket = (SSLSocket) sslContext.getSocketFactory()
                    .createSocket(host, Integer.parseInt(port));
            SocketFactory.getDefault().createSocket(host, Integer.parseInt(port));
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);
            zos.putNextEntry(new ZipEntry("test"));
            zos.write(request.getBytes());
            zos.closeEntry();
            zos.flush();

            byte[] data = baos.toByteArray();

            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            dos.writeInt(data.length);
            dos.write(data);
            dos.flush();

            byte[] tmp;
            DataInputStream input = new DataInputStream(socket.getInputStream());
            tmp = new byte[input.readInt()];
            input.readFully(tmp);
            input.close();
            ByteArrayInputStream ba_is = new ByteArrayInputStream(tmp);
            ZipInputStream source_is = new ZipInputStream(ba_is);
            ZipEntry entry = source_is.getNextEntry();
            baos = new ByteArrayOutputStream();
            int ch;
            while ((ch = source_is.read()) != -1) {
                baos.write(ch);

            }
            String response = baos.toString("UTF-8");
            ba_is.close();
            source_is.close();
            baos.close();

            logger.info("response = " + response);
            return response;
        } catch (Exception ex) {
            logger.error(ex, ex);
            return null;
        }

    }

}
