package andy;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

/**
 * It's not working, so far.
 * 
 * java.security.SignatureException: error decoding signature bytes.
 * 
 */
public class ApplePaySignatureVerifier {
	static {
		Security.addProvider(new BouncyCastleProvider());  
	}
	public static void main(String[] args) throws Exception {
		String authResponse = IOUtils.toString(ClassLoader.getSystemResourceAsStream("payment_auth_response.txt"), "UTF-8");
		InputStream applePayPem = new FileInputStream("D:\\AMS_GIT\\merchant-service\\info\\ApplePay\\test\\payment_cert\\apple_pay.pem");
		
		System.out.println(verify(applePayPem, authResponse));
	}
	
	public static boolean verify(InputStream pem, String authResponse) throws Exception {
		DocumentContext cxt = JsonPath.parse(authResponse);
		String paymentDataEphemeralPublicKey = cxt.read("token.paymentData.header.ephemeralPublicKey");
		String paymentDataData = cxt.read("token.paymentData.data");
		String paymentDataSignature = cxt.read("token.paymentData.signature");
		String paymentDataTransactionId = cxt.read("token.paymentData.header.transactionId");
		
		byte[] sign = Base64.getDecoder().decode(paymentDataSignature);
		byte[] data = Base64.getDecoder().decode(paymentDataData);
		byte[] ephemeralPublicKey = Base64.getDecoder().decode(paymentDataEphemeralPublicKey);
		byte[] transactionId = Hex.decode(paymentDataTransactionId);

		Certificate cert = loadCertificate(pem);

		Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
		signature.initVerify(cert.getPublicKey());
		signature.update(concat(ephemeralPublicKey, data, transactionId));
		return signature.verify(sign);
	}

	private static byte[] concat(byte[]... data) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		for (byte[] d : data) {
			bos.write(d);
		}
		return bos.toByteArray();
	}
	
	private static Certificate loadCertificate(InputStream pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(pem);
        return cert;
	}
}
