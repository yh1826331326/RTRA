package Yu;

import it.unisa.dia.gas.jpbc.Element;

public class RSU {
    private final SystemParam params;
    public String RID;
    public Element r;   // 私钥
    public Element R;   // 公钥

    public RSU(SystemParam params, String RID) {
        this.params = params;
        this.RID = RID;
        this.r = params.Zr.newRandomElement().getImmutable();
        this.R = params.P.duplicate().mulZn(r).getImmutable();
    }

    public Element getPublicKey() {
        return R;
    }

    public Element getPrivateKey() {
        return r;
    }
    private Element hashToZr(String input) {
        return params.Zr.newElement().setFromHash(input.getBytes(), 0, input.length()).getImmutable();
    }

    public boolean verifyRSUSignature(TA.RSURecord record) {
        Element left = params.P.duplicate().mulZn(record.sigmaR).getImmutable();
        Element right = params.Ppub.duplicate().mulZn(hashToZr(
                record.RID + record.R + record.A )).add(record.A).getImmutable();
        return left.isEqual(right);
    }

}
