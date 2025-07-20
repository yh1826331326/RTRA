package Wang;

import it.unisa.dia.gas.jpbc.Element;

import java.nio.charset.StandardCharsets;

public class VehicleReceiver {

    public static String[] decryptResponse(PseudoResponse resp, Element x) throws Exception {
        Element shared = resp.C1.duplicate().mulZn(x).getImmutable();
        byte[] key = IBEHelper.H_GT(shared, 16);
        String msg = new String(PseudoManager.xorBytes(resp.C2, key), StandardCharsets.UTF_8);

        String[] parts = msg.split("\\|");
        String pseuStr = parts[0];
        String[] pseudos = pseuStr.split(",");
        return pseudos;
    }
}

