
import java.io.File;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import org.apache.log4j.Logger;
import org.bouncycastle.openssl.PEMReader;

import CMS_samples.CMStools;
import com.objsys.asn1j.runtime.*;
import java.security.Security;
import java.util.Arrays;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Level;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.tools.Array;

/**
 *
 * @author ctacon
 */
public class CryptoManager {

    private PrivateKey privateKey;
    private X509Certificate publicCert;
    Logger logger;

    public CryptoManager(String privateKeyPath, String privateKeyPassword, String publicCertPath, Logger logger) throws Exception {
	this.logger = logger;
	try {
	    KeyStore hdImageStore = KeyStore.getInstance("HDImageStore");
	    hdImageStore.load(null, null);
	    privateKey = (PrivateKey) hdImageStore.getKey(
		    privateKeyPath,
		    privateKeyPassword == null || privateKeyPassword.isEmpty()
		    ? null
		    : privateKeyPassword.toCharArray());
	    PEMReader publicCertreader = new PEMReader(new FileReader(new File(publicCertPath)), null);
	    publicCert = (X509Certificate) publicCertreader.readObject();
	} catch (Exception ex) {
	    logger.error(ex, ex);
	    throw ex;
	}
    }

    public byte[] sign(String message) throws Exception {
	try {
	    logger.info("private-key-alg = " + privateKey.getAlgorithm());
	    Signature sig = Signature.getInstance(JCP.GOST_EL_SIGN_NAME);
	    logger.info("sign algorithm = " + sig.getAlgorithm());

	    sig.initSign(privateKey);
	    sig.update(message.getBytes("cp1251"));
	    byte[] s = sig.sign();
	    return s;
//	    return Base64.encodeBytes(s, 0, s.length, Base64.DONT_BREAK_LINES);
	} catch (Exception ex) {
	    logger.error(ex, ex);
	    throw new Exception(ex);
	}
    }

    /**
     * Функция формирования простой отсоединенной подписи формата PKCS#7 по хешу
     * сообщения.
     *
     * @param message
     * @param data Данные для подписи.
     * @param privateKey Закрытый ключ для создания ЭЦП.
     * @param certificate Сертификат подписи.
     * @return ЭЦП.
     * @throws Exception
     */
    public byte[] createPKCS7(String message) throws Exception {
	try {
	    byte[] data = message.getBytes("cp1251");

	    // Получаем бинарную подпись длиной 64 байта.

	    final Signature signature = Signature.getInstance(JCP.GOST_EL_SIGN_NAME);
	    signature.initSign(privateKey);
	    signature.update(data);

	    final byte[] sign = signature.sign();

	    // Формируем контекст подписи формата PKCS7.

	    final ContentInfo all = new ContentInfo();
	    all.contentType = new Asn1ObjectIdentifier(
		    new OID(CMStools.STR_CMS_OID_SIGNED).value);

	    final SignedData cms = new SignedData();
	    all.content = cms;
	    cms.version = new CMSVersion(1);

	    // Идентификатор алгоритма хеширования.

	    cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
	    final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(
		    new OID(CMStools.DIGEST_OID).value);
	    a.parameters = new Asn1Null();
	    cms.digestAlgorithms.elements[0] = a;

	    // Т.к. подпись отсоединенная, то содержимое отсутствует.

	    cms.encapContentInfo = new EncapsulatedContentInfo(
		    new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_DATA).value), null);

	    // Добавляем сертификат подписи.

	    cms.certificates = new CertificateSet(1);
	    final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate asnCertificate =
		    new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();

	    final Asn1BerDecodeBuffer decodeBuffer =
		    new Asn1BerDecodeBuffer(publicCert.getEncoded());
	    asnCertificate.decode(decodeBuffer);

	    cms.certificates.elements = new CertificateChoices[1];
	    cms.certificates.elements[0] = new CertificateChoices();
	    cms.certificates.elements[0].set_certificate(asnCertificate);

	    // Добавялем информацию о подписанте.

	    cms.signerInfos = new SignerInfos(1);
	    cms.signerInfos.elements[0] = new SignerInfo();
	    cms.signerInfos.elements[0].version = new CMSVersion(1);
	    cms.signerInfos.elements[0].sid = new SignerIdentifier();

	    final byte[] encodedName = publicCert.getIssuerX500Principal().getEncoded();
	    final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
	    final Name name = new Name();
	    name.decode(nameBuf);

	    final CertificateSerialNumber num = new CertificateSerialNumber(
		    publicCert.getSerialNumber());

	    cms.signerInfos.elements[0].sid.set_issuerAndSerialNumber(
		    new IssuerAndSerialNumber(name, num));
	    cms.signerInfos.elements[0].digestAlgorithm =
		    new DigestAlgorithmIdentifier(new OID(CMStools.DIGEST_OID).value);
	    cms.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
	    cms.signerInfos.elements[0].signatureAlgorithm =
		    new SignatureAlgorithmIdentifier(new OID(CMStools.SIGN_OID).value);
	    cms.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();
	    cms.signerInfos.elements[0].signature = new SignatureValue(sign);

	    // Получаем закодированную подпись.

	    final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
	    all.encode(asnBuf, true);

	    return asnBuf.getMsgCopy();

	} catch (Exception ex) {
	    logger.error(ex, ex);
	    return null;
	}
    }

    /**
     * Функция декодирования подписи формата PKCS7. Пример подписи взят из {@link CMS_samples.CMS#CMSVerify(byte[],
     * Certificate, byte[])}.
     *
     * @param pkcs7Signature ЭЦП формата PKCS7.
     * @param data Подписанные данные.
     * @param certificate Сертификат для проверки подписи.
     * @return True, если подпись корректна.
     * @throws Exception
     */
    public boolean verifyPKCS7(byte[] pkcs7Signature, String message) throws Exception {
	byte[] data = message.getBytes("cp1251");
	// Декодирование подписи формата PKCS7.

	int i = -1;
	final Asn1BerDecodeBuffer asnBuf = new Asn1BerDecodeBuffer(pkcs7Signature);
	final ContentInfo all = new ContentInfo();
	all.decode(asnBuf);

	// Проверка формата подписи.

	boolean supportedType =
		new OID(CMStools.STR_CMS_OID_SIGNED).eq(all.contentType.value);
	if (!supportedType) {
	    throw new Exception("Not supported");
	}

	final SignedData cms = (SignedData) all.content;
	if (cms.version.value != 1) {
	    throw new Exception("Incorrect version");
	}

	boolean supportedData = new OID(CMStools.STR_CMS_OID_DATA).eq(
		cms.encapContentInfo.eContentType.value);
	if (!supportedData) {
	    throw new Exception("Nested not supported");
	}

	byte[] text = null;
	if (data != null) {
	    text = data;
	} else if (cms.encapContentInfo.eContent != null) {
	    text = cms.encapContentInfo.eContent.value;
	}

	if (text == null) {
	    throw new Exception("No content");
	}

	// Получение идентификатора алгоритма хеширования.

	OID digestOid = null;
	DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(
		new OID(CMStools.DIGEST_OID).value);

	for (i = 0; i < cms.digestAlgorithms.elements.length; i++) {

	    if (cms.digestAlgorithms.elements[i].algorithm.equals(a.algorithm)) {
		digestOid = new OID(cms.digestAlgorithms.elements[i].algorithm.value);
		break;
	    } // if

	} // for

	if (digestOid == null) {
	    throw new Exception("Unknown digest");
	}

	// Поиск сертификат подписи.

	int pos = -1;
	for (i = 0; i < cms.certificates.elements.length; i++) {

	    final Asn1BerEncodeBuffer encBuf = new Asn1BerEncodeBuffer();
	    cms.certificates.elements[i].encode(encBuf);

	    final byte[] in = encBuf.getMsgCopy();
	    if (Arrays.equals(in, publicCert.getEncoded())) {
		System.out.println("Selected certificate: " + publicCert.getSubjectDN());
		pos = i;
		break;
	    } // if

	} // for

	if (pos == -1) {
	    throw new Exception("Not signed on certificate");
	}

	// Декодирование подписанта.

	final SignerInfo info = cms.signerInfos.elements[pos];
	if (info.version.value != 1) {
	    throw new Exception("Incorrect version");
	}

	if (!digestOid.equals(new OID(info.digestAlgorithm.algorithm.value))) {
	    throw new Exception("Not signed on certificate");
	}

	final byte[] sign = info.signature.value;

	// Проверка подписи.

	final Signature signature = Signature.getInstance(JCP.GOST_EL_SIGN_NAME);
	signature.initVerify(publicCert);
	signature.update(text);

	return signature.verify(sign);
    }

    public static void main(String[] args) throws Exception {
	Security.addProvider(new BouncyCastleProvider());
	Security.addProvider(new ru.CryptoPro.JCP.JCP());
	Security.addProvider(new ru.CryptoPro.ssl.Provider());
	Security.addProvider(new ru.CryptoPro.reprov.RevCheck());

	Logger logger = Logger.getRootLogger();
	logger.setAdditivity(true);
	logger.setLevel(Level.DEBUG);
	CryptoManager cr = new CryptoManager("le-a4150d50-f686-48d5-97d1-8bc18c72848b", "", "/home/ctacon/NetBeansProjects/migom-new-new/DEMO_GOST.cer", logger);
	// Формирование подписи PKCS7.
	String textToSing = FileUtils.readFileToString(new File("/home/ctacon/NetBeansProjects/simple_iniversal_gate_configs/src/configs/test.xml"), "cp1251");
	FileUtils.writeByteArrayToFile(new File("/tmp/sign-test/encodding.test"), textToSing.getBytes("cp1251"));

	byte[] pkcs7Sign = cr.createPKCS7(textToSing);

	// Локальная проверка подписи PKCS7.

	boolean checkResult = cr.verifyPKCS7(pkcs7Sign, textToSing);

	if (checkResult) {
	    System.out.println("Valid signature");
	} else {
	    System.err.println("Invalid signature.");
	    return;
	}

	// Сохранение данных и подписи в файлы.

	Array.writeFile("/tmp/sign-test/texttoSign", textToSing.getBytes());
	Array.writeFile("/tmp/sign-test/pkcs7", pkcs7Sign);


    }


}
