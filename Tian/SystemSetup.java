package Tian;

import it.unisa.dia.gas.jpbc.*;

import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SystemSetup {
    public static Pairing pairing;
    public static Field G1, Zr;
    public static Element P, s, Ppub;

    // 初始化系统参数
    public static void initialize(String paramFilePath) {
        // 加载pairing参数（a.properties文件）
        PairingParameters params = PairingFactory.getPairingParameters(paramFilePath);
        pairing = PairingFactory.getPairing(params);

        // 群初始化
        G1 = pairing.getG1();
        Zr = pairing.getZr();

        // 系统生成元 P
        P = G1.newRandomElement().getImmutable();

        // 主密钥 s ∈ Z_p^*
        s = Zr.newRandomElement().getImmutable();

        // 主公钥 Ppub = s · P
        Ppub = P.duplicate().mulZn(s).getImmutable();

        System.out.println("✅ The system initialization is complete");
    }

    // 哈希函数：H : String → Zr
    public static Element hashToZr(String input) {
        return Zr.newElement().setFromHash(input.getBytes(), 0, input.length()).getImmutable();
    }
}

