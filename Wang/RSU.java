package Wang;
import it.unisa.dia.gas.jpbc.Element;
public class RSU {
    public String ID;
    public Element sk, PK;
    public Cert cert;

    public RSU(String id) {
        this.ID = id;
        this.sk = SystemSetup.Zq.newRandomElement().getImmutable();
        this.PK = SystemSetup.P.duplicate().mulZn(sk).getImmutable();
    }

    // RSU向CA提交注册请求
    public Cert requestCertificate() throws Exception {
        Element hash = SystemSetup.HtoG1(ID + PK.toString() + "2026-01-01");
        Element signature = hash.duplicate().mulZn(SystemSetup.s).getImmutable();
        this.cert = new Cert(ID, PK, "2026-01-01", signature);
        return this.cert;
    }
}

class Cert {
    public String ID;
    public Element pubKey;
    public String validUntil;
    public Element signature;

    public Cert(String ID, Element pubKey, String validUntil, Element signature) {
        this.ID = ID;
        this.pubKey = pubKey;
        this.validUntil = validUntil;
        this.signature = signature;
    }

    public boolean verifyCA() throws Exception {
        Element h = SystemSetup.HtoG1(ID + pubKey.toString() + validUntil);
        Element left = SystemSetup.pairing.pairing(signature, SystemSetup.P);
        Element right = SystemSetup.pairing.pairing(h, SystemSetup.Ppub);
        return left.isEqual(right);
    }
}

