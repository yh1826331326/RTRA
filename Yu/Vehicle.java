package Yu;

import it.unisa.dia.gas.jpbc.Element;

public class Vehicle {

    public String VID;

    public String PID;
    public Element v;      // 私钥
    public Element V;      // 公钥

    public Element U;

    public Element u;
    public Element xi;

    public Element Bi;

    public Element SK;

    public String ar;

    public Vehicle(SystemParam params, String VID) {
        this.VID = VID;
        this.v = params.Zr.newRandomElement().getImmutable();
        this.V = params.P.duplicate().mulZn(v).getImmutable();
    }

    public Element getPrivateKey() {
        return v;
    }

    public Element getPublicKey() {
        return V;
    }

    public String getVID() {
        return VID;
    }

    public String hashToStr(String input, SystemParam params) {
        return hashToZr(input,params).toString(); // 简化为字符串输出
    }

    public Element hashToZr(String input,SystemParam params) {
        return params.Zr.newElement().setFromHash(input.getBytes(), 0, input.getBytes().length).getImmutable();
    }

    private String xor(String a, String b) {
        char[] r = new char[a.length()];
        for (int i = 0; i < a.length(); i++) {
            r[i] = (char) (a.charAt(i) ^ b.charAt(i % b.length()));
        }
        return new String(r);
    }

    public boolean verifyRegistration(TA.VehicleRecord record, SystemParam params) {
        // Step 1: 计算 PID 并验证
        Element vPpub = params.Ppub.duplicate().mulZn(this.getPrivateKey());  // v_i * P_pub   params.Ppub
        String PID = xor(this.getVID(),hashToStr(record.Bi.toString() + vPpub,params));

        if (!PID.equals(record.PID)) {
            System.out.println("[Vehicle] Verification PID is inconsistent!");
            return false;
        }

        // Step 2: 验证签名 σ_V
        Element h = hashToZr(record.PID + V + record.Bi , params);
        Element left = params.P.duplicate().mulZn(record.sigmaV);
        Element right = params.Ppub.duplicate().mulZn(h).add(record.Bi);

        if (!left.isEqual(right)) {
            System.out.println("[Vehicle] Signature verification failed!");
            return false;
        }
        this.xi= record.sigmaV;
        this.Bi= record.Bi;
        this.PID= record.PID;

        System.out.println("[Vehicle] Registration verification successful, PID = " + record.PID);
        return true;
    }
}
