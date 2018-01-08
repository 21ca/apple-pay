package andy;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

public class ApplePayDecoder{
	static {
		if (Security.getProvider("BC") == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}
	
	public static void main(String[] args) throws Exception {
		String authResponse = IOUtils.toString(ClassLoader.getSystemResourceAsStream("payment_auth_response.txt"), "UTF-8");
		InputStream keyStore = new FileInputStream("D:\\AMS_GIT\\merchant-service\\info\\ApplePay\\payment_cert\\payment.p12");
		
		byte[] data = decryptAuthResponse(keyStore, "000000", "merchant.ams", authResponse);
		
		//{"applicationPrimaryAccountNumber":"4817000000000000","applicationExpirationDate":"251130","currencyCode":"840","transactionAmount":899,"deviceManufacturerIdentifier":"040010030273","paymentDataType":"3DSecure","paymentData":{"onlinePaymentCryptogram":"AozYCeUAEa7N1uyLxFMLMAACAAA=","eciIndicator":"7"}}
		System.out.println(new String(data));
	}
	
	public static byte[] decryptAuthResponse(InputStream keyStore, String keStorePwd, 
			String merchantId, String authResponse) throws Exception {
		PrivateKey priKey = getPrivateKey(keyStore, keStorePwd);
		DocumentContext cxt = JsonPath.parse(authResponse);
		String ephemeralPublicKey = cxt.read("token.paymentData.header.ephemeralPublicKey");
		String paymentData = cxt.read("token.paymentData.data");

		byte[] ephemeral = Base64.getDecoder().decode(ephemeralPublicKey);
		byte[] data = Base64.getDecoder().decode(paymentData);
		byte[] secret = deriveSecret(priKey, ephemeral);
		byte[] symmetricKey = deriveSymmetricKey(secret, merchantId);

		return decrypt(symmetricKey, data);
	}
	
	private static PrivateKey getPrivateKey(InputStream keyStoreData, String keyStorePwd) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(keyStoreData, keyStorePwd.toCharArray());
		Enumeration<String> aliasEnum = keyStore.aliases();
		while (aliasEnum.hasMoreElements()) {
			String alias = aliasEnum.nextElement();
			if (keyStore.isKeyEntry(alias)) {
				return (PrivateKey) keyStore.getKey(alias, keyStorePwd.toCharArray());
			}
		}
		return null;
	}
	
	private static byte[] deriveSymmetricKey(byte[] secret, String merchantId) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		bos.write(new byte[] { 0x00, 0x00, 0x00, 0x01 });
		bos.write(secret);
		byte[] alg = "id-aes256-GCM".getBytes();
		bos.write(alg.length);
		bos.write(alg);
		bos.write("Apple".getBytes());
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		byte[] v = messageDigest.digest(merchantId.getBytes());
		bos.write(v);

		return messageDigest.digest(bos.toByteArray());
	}
	
	private static byte[] decrypt(byte[] bkey, byte[] data) throws Exception {
		SecretKeySpec key = new SecretKeySpec(bkey, "AES");
		Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
		c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
		return c.doFinal(data);
	}
	
	private static byte[] deriveSecret(PrivateKey priKey, byte[] ephemeral) throws Exception {
		KeyFactory keyFac = KeyFactory.getInstance("EC");
		PublicKey pub = keyFac.generatePublic(new X509EncodedKeySpec(ephemeral));

		KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
		keyAgree.init(priKey);
		keyAgree.doPhase(pub, true);
		return keyAgree.generateSecret();
	}

}
