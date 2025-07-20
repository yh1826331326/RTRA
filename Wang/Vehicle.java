package Wang;

import it.unisa.dia.gas.jpbc.Element;

public class Vehicle {
    public String ID;
    public Element x, Y; // 私钥与公钥
    public Cert cert;
    public String[] pseudos;

    public Vehicle(String id) {
        this.ID = id;
        this.x = SystemSetup.Zq.newRandomElement().getImmutable();
        this.Y = SystemSetup.P.duplicate().mulZn(x).getImmutable();
    }

    // 请求证书
    public Cert requestCertificate() throws Exception {
        Element hash = SystemSetup.HtoG1(ID + Y.toString() + "2026-01-01");
        Element signature = hash.duplicate().mulZn(SystemSetup.s).getImmutable();
        this.cert = new Cert(ID, Y, "2026-01-01", signature);
        return cert;
    }

    // 发起认证请求
    public AuthRequest generateAuthRequest(String pseudo) throws Exception {
        Element a = SystemSetup.Zq.newRandomElement().getImmutable();
        Element A = SystemSetup.P.duplicate().mulZn(a).getImmutable();
        long timestamp = System.currentTimeMillis();

        String M1 = pseudo + A.toString() + timestamp;
        Element hM1 = SystemSetup.HtoG1(M1);
        Element sigma1 = hM1.duplicate().mulZn(x.duplicate()).getImmutable();

        return new AuthRequest(pseudo, A, timestamp, sigma1, this.cert, a);
    }
}

class AuthRequest {
    public String pseudo;
    public Element A;
    public long timestamp;
    public Element sigma1;
    public Cert cert;
    public Element a; // 临时保存车辆随机数，用于会话密钥计算

    public AuthRequest(String pseudo, Element A, long timestamp, Element sigma1, Cert cert, Element a) {
        this.pseudo = pseudo;
        this.A = A;
        this.timestamp = timestamp;
        this.sigma1 = sigma1;
        this.cert = cert;
        this.a = a;
    }
}
