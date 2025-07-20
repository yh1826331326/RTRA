package Wang;

import it.unisa.dia.gas.jpbc.Element;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

class PseudoResponse {
    public Element C1;
    public byte[] C2;
}

public class Server {
    public static PseudoResponse respondNewPseudos(PseudoRequest req, String serverID, Element vehiclePubKey) throws Exception {
        // IBE 解密
        Element Qserver = IBEHelper.H2(serverID);
        Element d_server =Qserver.duplicate().mulZn(SystemSetup.s).getImmutable();
        Element pairing = SystemSetup.pairing.pairing(d_server, req.U).getImmutable();
        byte[] key = IBEHelper.H_GT(pairing, 16);

        String decrypted = new String(PseudoManager.xorBytes(req.V, key), StandardCharsets.UTF_8);
        String[] parts = decrypted.split("\\|");
        String vehicleID = parts[0];
        byte[] r3 = Base64.getDecoder().decode(parts[1]);

        // 构造新的伪名响应
        String[] pseudos = new String[]{"P1X", "P2Y", "P3Z"};
        String msg = String.join(",", pseudos) + "|" + Base64.getEncoder().encodeToString(r3);

        // ElGamal 加密
        Element k = SystemSetup.Zq.newRandomElement().getImmutable();
        Element C1 = SystemSetup.P.duplicate().mulZn(k).getImmutable();
        Element sharedGT = SystemSetup.pairing.pairing(vehiclePubKey, SystemSetup.P).powZn(k).getImmutable();
        byte[] key2 = IBEHelper.H_GT(sharedGT, 16);

        byte[] C2 = PseudoManager.xorBytes(msg.getBytes(StandardCharsets.UTF_8), key2);

        PseudoResponse pr = new PseudoResponse();
        pr.C1 = C1;
        pr.C2 = C2;
        return pr;
    }
}

