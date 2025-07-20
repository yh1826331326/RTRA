package WangJing;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class SystemSetup {
    public static Pairing pairing;
    public static Field G1;
    public static Field Zr;
    public static Element P, Ppub, s;
    public static MessageDigest[] hashFunctions = new MessageDigest[10];

    public static void setup(String curveParams) throws Exception {
        pairing = PairingFactory.getPairing(curveParams);
        PairingFactory.getInstance().setUsePBCWhenPossible(true);

        G1 = pairing.getG1();
        Zr = pairing.getZr();

        P = G1.newRandomElement().getImmutable();
        s = Zr.newRandomElement().getImmutable();
        Ppub = P.duplicate().mulZn(s).getImmutable();

        for (int i = 0; i < 10; i++) {
            hashFunctions[i] = MessageDigest.getInstance("SHA-256");
        }
    }

    public static Element HtoZr(int index, String... values) {
        try {
            MessageDigest hash = hashFunctions[index];
            hash.reset();
            for (String v : values)
                hash.update(v.getBytes(StandardCharsets.UTF_8));
            return Zr.newElementFromHash(hash.digest(), 0, hash.digest().length).getImmutable();
        } catch (Exception e) {
            throw new RuntimeException("Hash failed: " + e.getMessage());
        }
    }

    public static Element HtoG1(int index, String... values) {
        return G1.newElement().set(HtoZr(index, values)).mul(P).getImmutable();
    }
}
