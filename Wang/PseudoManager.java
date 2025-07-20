package Wang;

import it.unisa.dia.gas.jpbc.Element;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

class PseudoRequest {
    public Element U;
    public byte[] V;
    public byte[] r3;

    public PseudoRequest(Element U, byte[] V, byte[] r3) {
        this.U = U;
        this.V = V;
        this.r3 = r3;
    }
}

public class PseudoManager {

    // 车辆向服务器发起 IBE 请求
    public static PseudoRequest requestNewPseudos(String vehicleID, String serverID) throws Exception {
        byte[] r3 = new byte[16];
        new SecureRandom().nextBytes(r3);
        String msg = vehicleID + "|" + Base64.getEncoder().encodeToString(r3);

        // IBE 加密
        Element Qserver = IBEHelper.H2(serverID);
        Element r = SystemSetup.Zq.newRandomElement().getImmutable();

        Element U = SystemSetup.P.duplicate().mulZn(r).getImmutable();
    //    Element pairing = SystemSetup.pairing.pairing(Qserver, SystemSetup.Ppub).powZn(r).getImmutable();
        Element pairingGT = SystemSetup.pairing.pairing(Qserver, SystemSetup.Ppub).powZn(r).getImmutable();
        if (!pairingGT.getField().equals(SystemSetup.GT)) {
            throw new RuntimeException("pairingGT 不属于 GT，实际是: " + pairingGT.getField().toString());
        }
        byte[] key = IBEHelper.H_GT(pairingGT, 16);



        byte[] V = xorBytes(msg.getBytes(StandardCharsets.UTF_8), key);

        return new PseudoRequest(U, V, r3);
    }

    public static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte)(a[i] ^ b[i % b.length]);
        }
        return out;
    }
}

