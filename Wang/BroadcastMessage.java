package Wang;

import it.unisa.dia.gas.jpbc.Element;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

class BroadcastMessage {
    public String pseudo;
    public String encryptedMsg;

    public long timestamp;
    public Element signature;
    public Cert cert;

    public BroadcastMessage(String pseudo, String encryptedMsg, long timestamp, Element signature, Cert cert) {
        this.pseudo = pseudo;
        this.encryptedMsg = encryptedMsg;
        this.timestamp = timestamp;
        this.signature = signature;
        this.cert = cert;
    }
}

class Broadcaster {
    // 用群组密钥加密（AES）
    public static String encryptWithGK(String msg, byte[] GK) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(GK, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 车辆广播消息
    public static BroadcastMessage generateBroadcast(Vehicle vehicle, String pseudo, String msg, byte[] GK) throws Exception {
        long timestamp = System.currentTimeMillis();
        String content = msg + "|" + timestamp;
        String cipherText = encryptWithGK(content, GK);

        String M3 = pseudo + cipherText + timestamp;
        Element hM3 = SystemSetup.HtoG1(M3);
        Element sig = hM3.duplicate().mulZn(vehicle.x).getImmutable();

        return new BroadcastMessage(pseudo, cipherText, timestamp, sig, vehicle.cert);
    }
}
