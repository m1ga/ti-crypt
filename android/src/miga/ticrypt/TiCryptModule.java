package miga.ticrypt;

import android.util.Base64;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import javax.crypto.Cipher;
import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.KrollModule;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.kroll.common.Log;

@Kroll.module(name = "Ticrypt", id = "miga.ticrypt")
public class TiCryptModule extends KrollModule
{
	static final String TAG = "TiCrypt";
	Key publicKey = null;
	Key privateKey = null;

	public TiCryptModule()
	{
		super();
	}

	@Kroll.method
	public KrollDict generateKeyPair()
	{
		// generate key pair
		//
		KrollDict arg = new KrollDict();

		try {
			//SecureRandom secureRandom = new SecureRandom();
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			KeyPair kp = kpg.genKeyPair();
			publicKey = kp.getPublic();
			privateKey = kp.getPrivate();

			arg.put("privateKey", Base64.encodeToString(privateKey.getEncoded(), Base64.NO_WRAP));
			arg.put("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP));

		} catch (Exception e) {
			Log.e(TAG, "RSA key pair error");
		}

		return arg;
	}

	@Kroll.method
	public String decode(HashMap args)
	{
		// decode string back to plain text
		//
		KrollDict arg = new KrollDict(args);
		String txt = arg.getString("cipherText");
		byte[] bytesEncoded = Base64.decode(txt, 0);
		String keyString = arg.getString("privateKey");
		PrivateKey key;

		try {
			byte[] encodedKey = Base64.decode(keyString, 0);
			PKCS8EncodedKeySpec x509KeySpec = new PKCS8EncodedKeySpec(encodedKey);
			KeyFactory keyFact = KeyFactory.getInstance("RSA");
			key = keyFact.generatePrivate(x509KeySpec);
		} catch (Exception e) {
			return "error key";
		}

		byte[] decodedBytes = null;

		try {
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.DECRYPT_MODE, key);
			decodedBytes = c.doFinal(bytesEncoded);
		} catch (Exception e) {
			Log.e(TAG, "RSA decryption error " + e.toString());
			return "error";
		}
		return new String(decodedBytes);
	}

	@Kroll.method
	public String encode(HashMap args)
	{
		// encode text to cipher text
		//
		KrollDict arg = new KrollDict(args);
		String txt = arg.getString("plainText");
		String keyString = arg.getString("publicKey");
		byte[] encodedBytes = null;
		Key key;

		try {
			byte[] encodedKey = Base64.decode(keyString, 0);
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(encodedKey);
			KeyFactory keyFact = KeyFactory.getInstance("RSA");
			key = keyFact.generatePublic(x509KeySpec);
		} catch (Exception e) {
			return "error key";
		}

		try {
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.ENCRYPT_MODE, key);
			encodedBytes = c.doFinal(txt.getBytes());
		} catch (Exception e) {
			Log.e(TAG, "RSA encryption error " + e.toString());
		}

		return Base64.encodeToString(encodedBytes, Base64.NO_WRAP);
	}
}
