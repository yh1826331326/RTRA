package WangJing;

import it.unisa.dia.gas.jpbc.Element;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

class MessageEncryptor {
    public static String encryptMessages(List<String> messages, List<Element> gammas, Element sessionKey) throws Exception {
        List<String> bundle = new ArrayList<>();
        for (int i = 0; i < messages.size(); i++) {
            String m = messages.get(i);
            Element gamma = gammas.get(i);
            byte[] mBytes = m.getBytes(StandardCharsets.UTF_8);
            byte[] gBytes = gamma.toBytes();
            byte[] xor = xorBytes(mBytes, gBytes);
            String tag = Base64.getEncoder().encodeToString(SystemSetup.HtoZr(9, gamma.toString()).toBytes());
            String encoded = tag + ":" + Base64.getEncoder().encodeToString(xor);
            bundle.add(encoded);
        }
        return aesEncrypt(String.join("|", bundle), sessionKey.toString().substring(0, 16));
    }

    public static List<String> decryptMessages(String ciphertext, Element gamma_i_prime, Element sessionKey) throws Exception {
        String plain = aesDecrypt(ciphertext, sessionKey.toString().substring(0, 16));
        String[] parts = plain.split("\\|");
        String targetTag = Base64.getEncoder().encodeToString(SystemSetup.HtoZr(9, gamma_i_prime.toString()).toBytes());
        for (String p : parts) {
            String[] pair = p.split(":");
            if (pair[0].equals(targetTag)) {
                byte[] cBytes = Base64.getDecoder().decode(pair[1]);
                byte[] gBytes = gamma_i_prime.toBytes();
                byte[] mBytes = xorBytes(cBytes, gBytes);
                return List.of(new String(mBytes));
            }
        }
        return List.of();
    }

    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i % b.length]);
        }
        return out;
    }

    private static String aesEncrypt(String msg, String key) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
    }

    private static String aesDecrypt(String encrypted, String key) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encrypted)), StandardCharsets.UTF_8);
    }
}