package andy;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyStore;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.apache.commons.io.IOUtils;

public class ApplePayStartSession {

	public static void main(String[] args) throws Exception {
		InputStream keystore = new FileInputStream("D:\\AMS_GIT\\merchant-service\\info\\ApplePay\\test\\merchant.p12");
		String url = "https://apple-pay-gateway-cert.apple.com/paymentservices/startSession";
		
		String jsonResponse= start(keystore, "000000", url, "merchant.ams", "mstest.active.com", "AndyTest");
		
		//{"epochTimestamp":1515380826099,"expiresAt":1515388026099,"merchantSessionIdentifier":"xxx","nonce":"d329c625","merchantIdentifier":"xxx","domainName":"mstest.active.com","displayName":"AndyTest","signature":"XXX"}
		System.out.println(jsonResponse);
	}
	
	public static String start(InputStream p12Keystore, String keystorePwd, String applePayURL,
			String merchantId, String domainName, String displayName) throws Exception {
		URL url = new URL(applePayURL);
		HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		conn.setDoOutput(true);
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(p12Keystore, keystorePwd .toCharArray());
		KeyManagerFactory keyFact = KeyManagerFactory.getInstance("SunX509");
		keyFact.init(keyStore, keystorePwd.toCharArray());
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(keyFact.getKeyManagers(), null, null);
		conn.setSSLSocketFactory(ctx.getSocketFactory());
		OutputStream os = conn.getOutputStream();
		
		String req = "{'merchantIdentifier':'" + merchantId+ "', "
				+ "'domainName':'" + domainName + "', "
				+ "'displayName':'" + displayName + "'}";
		os.write(req .getBytes());
		try {
			return IOUtils.toString(conn.getInputStream(), "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
			return IOUtils.toString(conn.getErrorStream(), "UTF-8");
		}
	}

}
