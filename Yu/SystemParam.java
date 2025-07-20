package Yu;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SystemParam {
    public Pairing pairing;
    public Field G1;
    public Field Zr;
    public Element P;         // 椭圆曲线基点
    public Element Ppub;      // 系统公钥
    public Element s;         // 系统主私钥

    public SystemParam() {
        PairingParameters params = PairingFactory.getPairingParameters("a.properties");
        pairing = PairingFactory.getPairing(params);
        PairingFactory.getInstance().setUsePBCWhenPossible(true);

        G1 = pairing.getG1();
        Zr = pairing.getZr();

        P = G1.newRandomElement().getImmutable();
        s = Zr.newRandomElement().getImmutable();
        Ppub = P.duplicate().mulZn(s).getImmutable();
    }
}
