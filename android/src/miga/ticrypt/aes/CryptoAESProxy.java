package miga.ticrypt.aes;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import miga.ticrypt.TiCryptModule;
import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;

@Kroll.proxy(creatableInModule = TiCryptModule.class)
public class CryptoAESProxy extends KrollProxy
{

	public CryptoAESProxy()
	{
		super();
	}

	@Kroll.method
	public String generateKey()
	{

		String key;
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			SecureRandom secureRandom = new SecureRandom();
			keyGen.init(secureRandom);
			SecretKey secretKey = keyGen.generateKey();
			key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		} catch (Exception ex) {
			key = ex.getMessage();
		}
		return key;
	}

	@Kroll.method
	public String crypt(String key, String value)
	{
		String cryptedData;
		try {
			SecretKey skeySpec = new SecretKeySpec(key.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			byte[] encrypted = cipher.doFinal(value.getBytes("UTF-8"));
			cryptedData = Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception ex) {
			cryptedData = ex.getMessage();
		}
		return cryptedData;
	}

	@Kroll.method
	public String decrypt(String key, String encrypted)
	{
		String cryptedData;
		try {
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted.getBytes()));
			cryptedData = new String(decrypted, "UTF-8");

		} catch (Exception ex) {
			cryptedData = ex.getMessage();
		}

		return cryptedData;
	}
}