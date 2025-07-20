package Wang;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
//import it.unisa.dia.gas.jpbc.PairingParametersGeneratorFactory;
import it.unisa.dia.gas.jpbc.Element;

import java.security.MessageDigest;
import java.util.Base64;

public class SystemSetup {
    public static Pairing pairing;
    public static Element P, Ppub;
    public static Field G1, GT, Zq;
    public static Element s; // master private key

    // 初始化系统参数
    public static void initialize() {
        pairing = PairingFactory.getPairing("a.properties"); // 配置文件路径
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        G1 = pairing.getG1();
        GT = pairing.getGT();
        Zq = pairing.getZr();

        P = G1.newRandomElement().getImmutable();
        s = Zq.newRandomElement().getImmutable();
        Ppub = P.duplicate().mulZn(s).getImmutable();

        System.out.println("System Initialized:");
        System.out.println("P: " + P);
        System.out.println("s (Master Key): " + s);
        System.out.println("Ppub: " + Ppub);
        System.out.println();
    }

    // Hash: {0,1}* -> G1
    public static Element HtoG1(String msg) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(msg.getBytes());
        return G1.newElement().setFromHash(hash, 0, hash.length).getImmutable();
    }

    // Hash: GT -> Zq
    public static Element H1(Element gtElem) throws Exception {
        byte[] gtBytes = gtElem.toBytes();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(gtBytes);
        return Zq.newElementFromHash(hash, 0, hash.length).getImmutable();
    }
}

