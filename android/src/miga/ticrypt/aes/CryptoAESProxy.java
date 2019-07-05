package miga.ticrypt.aes;

import miga.ticrypt.TiCryptModule;
import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

@Kroll.proxy(creatableInModule=TiCryptModule.class)
public class CryptoAESProxy extends KrollProxy{

    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private final static String HEX = "0123456789ABCDEF";
    private int size = 32;

    public CryptoAESProxy(){
        super();
    }

    @Kroll.method
    public String generateKey() {
    
        StringBuilder builder = new StringBuilder();
        while (size-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    @Kroll.method
    public String crypt(String key, String value){
        String cryptedData;
        SecretKey skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            byte[] encrypted = cipher.doFinal(value.getBytes());
            cryptedData = toHex(encrypted);
        }catch (Exception ex){
            cryptedData = ex.getMessage();
        }
        return cryptedData;
    }

    @Kroll.method
    public String decrypt(String key, String encrypted) {
        String cryptedData;
        SecretKey skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] decrypted = cipher.doFinal(encrypted.getBytes());
            cryptedData = new String(decrypted);
        }catch (Exception ex){
            cryptedData = ex.getMessage();
        }

        return cryptedData;
    }

    private static String toHex(byte[] buf) {
        if (buf == null)
            return "";
        StringBuilder result = new StringBuilder(2 * buf.length);
        for (byte aBuf : buf) {
            result.append(HEX.charAt((aBuf >> 4) & 0x0f)).append(HEX.charAt(aBuf & 0x0f));
        }
        return result.toString();
    }

}