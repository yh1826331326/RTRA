package Wang;

import it.unisa.dia.gas.jpbc.Element;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


class Receiver {
    // AES 解密
    public static String decryptWithGK(String encryptedBase64, byte[] GK) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(GK, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // 验证签名并解密
    public static String receiveAndVerify(BroadcastMessage msg, byte[] GK) throws Exception {
        long now = System.currentTimeMillis();
        if (Math.abs(now - msg.timestamp) > 10000) throw new RuntimeException("Broadcast message expired");

        if (!msg.cert.verifyCA()) throw new RuntimeException("Certificate verification failed");

        String M3 = msg.pseudo + msg.encryptedMsg + msg.timestamp;
        Element hM3 = SystemSetup.HtoG1(M3);

        Element left = SystemSetup.pairing.pairing(msg.signature, SystemSetup.P);
        Element right = SystemSetup.pairing.pairing(hM3, msg.cert.pubKey);
        if (!left.isEqual(right)) throw new RuntimeException("Signature verification failed");

        return decryptWithGK(msg.encryptedMsg, GK);
    }

}

