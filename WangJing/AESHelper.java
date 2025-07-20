package WangJing;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESHelper {
    public static String encrypt(String key, String msg) throws Exception {
        SecretKeySpec sk = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sk);
        return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes()));
    }

    public static String decrypt(String key, String cipherText) throws Exception {
        SecretKeySpec sk = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sk);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }
}

