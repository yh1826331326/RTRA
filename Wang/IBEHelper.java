package Wang;

import it.unisa.dia.gas.jpbc.Element;


import java.security.MessageDigest;
import java.util.Arrays;

public class IBEHelper {
    // H_2: ID → G1（用于IBE）
    public static Element H2(String id) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(id.getBytes());
        return SystemSetup.G1.newElement().setFromHash(hash, 0, hash.length).getImmutable();
    }

    // H_3/H_4: GT → byte[]
    public static byte[] H_GT(Element e, int length) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(e.toBytes());
        return Arrays.copyOf(hash, length); // AES 16字节
    }
}
