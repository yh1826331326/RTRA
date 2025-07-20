package Tian;

import it.unisa.dia.gas.jpbc.Element;

import java.awt.*;

public class CrossDomainV2V {

    public static class InterDomainMessage {
        public String PVID_i;
        public Element E_i, Z_i, sigma_vi;
        public String M_enc;
        public String Rec, Fro;
        public long T5;

        public InterDomainMessage(String PVID_i, Element E_i, Element Z_i, Element sigma_vi,
                                  String M_enc, String Rec, String Fro, long T5) {
            this.PVID_i = PVID_i;
            this.E_i = E_i.getImmutable();
            this.Z_i = Z_i.getImmutable();
            this.sigma_vi = sigma_vi.getImmutable();
            this.M_enc = M_enc;
            this.Rec = Rec;
            this.Fro = Fro;
            this.T5 = T5;
        }
    }

    // 第一步：发送方车辆 Vi 构造跨域消息
    public static InterDomainMessage sendInterDomainMessage(String ID_Vi,
                                                            Element x_i,
                                                            Element M_vi,
                                                            String RSU_i,
                                                            String RSU_j,
                                                            String PID_j,
                                                            Element X_Vi,
                                                            Element Pub_v2v) {
        long time=System.currentTimeMillis();

        Element e_i = SystemSetup.Zr.newRandomElement().getImmutable();
        Element E_i = SystemSetup.P.duplicate().mulZn(e_i).getImmutable();

        // 构造伪身份
        Element temp = SystemSetup.Ppub.duplicate().mulZn(e_i);
        String PVID_i = xorStrings(ID_Vi, SystemSetup.hashToZr(temp.toString()).toString());

        // 签名 σ_vi = e_i + x_i · h(PVID_i || E_i || M)
        String h_input = PVID_i + E_i.toString() + M_vi.toString();
        Element h = SystemSetup.hashToZr(h_input);
        Element sigma_vi = e_i.duplicate().add(x_i.duplicate().mul(h)).getImmutable();

        // 模拟对称加密消息
        Element shared = SystemSetup.Ppub.duplicate().mulZn(e_i);  // 模拟会话密钥
        String M_enc = xorStrings(M_vi.toString(), SystemSetup.hashToZr(shared.toString()).toString());

        // 元信息：来源与目标
        String Fro = RSU_i + "|" + PVID_i;
        String Rec = RSU_j + "|" + PID_j;
        long T5 = System.currentTimeMillis();

        // 自动构造 Z_i = X_i - Pub_v2v · h(ID_RSU_i)
        Element h_rsu = SystemSetup.hashToZr(RSU_i);
        Element Z_i = X_Vi.duplicate().sub(Pub_v2v.duplicate().mulZn(h_rsu)).getImmutable();
        System.out.println("The time for generating signatures within the domain: "+(System.currentTimeMillis()-time)+" ms");

        return new InterDomainMessage(PVID_i, E_i, Z_i, sigma_vi, M_enc, Rec, Fro, T5);
    }


    // 字符串异或模拟
    public static String xorStrings(String a, String b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(a.length(), b.length()); i++) {
            sb.append((char)(a.charAt(i) ^ b.charAt(i)));
        }
        return sb.toString();
    }

    public static class ForwardedMessage {
        public String ID_RSU_i;
        public Element R_3, sigma_rsu;
        public String M_i;
        public long T6;

        public ForwardedMessage(String ID, Element R_3, Element sigma, String M_i, long T6) {
            this.ID_RSU_i = ID;
            this.R_3 = R_3.getImmutable();
            this.sigma_rsu = sigma.getImmutable();
            this.M_i = M_i;
            this.T6 = T6;
        }
    }

    // 第二步：RSU_i 解密并转发到 RSU_j
    public static ForwardedMessage forwardToTargetRSU(InterDomainMessage msg,
                                                      Element d_RSU_i,
                                                      String ID_RSU_i,
                                                      Element X_RSU_j,
                                                      Element Y_RSU_j) {
        // 验证时间戳 T5
        long now = System.currentTimeMillis();
        if (Math.abs(now - msg.T5) > 30000) {
            System.out.println("⛔ T5 timeout, discard cross-domain messages!");
            return null;
        }

        // 解密 M = M_enc XOR h(e_i · Ppub) （用 E_i·d_RSU_i ≈ e_i·Ppub）
        Element shared = msg.E_i.duplicate().mulZn(d_RSU_i); // e_i · Ppub
        String M_i = xorStrings(msg.M_enc, SystemSetup.hashToZr(shared.toString()).toString());

        // 构造 R3 = r3 · P
        Element r3 = SystemSetup.Zr.newRandomElement().getImmutable();
        Element R_3 = SystemSetup.P.duplicate().mulZn(r3).getImmutable();

        // 构造 D_RSUj = X + Y + Ppub · h(ID || X || Y)
        String h_input = ID_RSU_i + X_RSU_j.toString() + Y_RSU_j.toString();
        Element D_RSUj = X_RSU_j.duplicate().add(Y_RSU_j).add(SystemSetup.Ppub.duplicate().mulZn(SystemSetup.hashToZr(h_input)));

        // 构造签名 σ = r3 + d_RSUi * h(...)
        long T6 = System.currentTimeMillis();
        String sigInput = ID_RSU_i + R_3.toString() + M_i + T6;
        Element h = SystemSetup.hashToZr(sigInput);
        Element sigma = r3.duplicate().add(d_RSU_i.duplicate().mul(h)).getImmutable();

        System.out.println("RSU forwarding time: "+(System.currentTimeMillis()-now)+" ms");
        return new ForwardedMessage(ID_RSU_i, R_3, sigma, M_i, T6);
    }

    public static class RSUResponseToVehicle {
        public String M_j;
        public long T7;

        public RSUResponseToVehicle(String M_j, long T7) {
            this.M_j = M_j;
            this.T7 = T7;
        }
    }

    // 第三步：目标 RSU_j 接收并验证源 RSU_i 消息
    public static RSUResponseToVehicle receiveCrossDomainMessageByRSU(ForwardedMessage msg,
                                                                      String ID_RSU_i,
                                                                      Element X_RSU_i,
                                                                      Element Y_RSU_i,
                                                                      Element d_RSU_j) {
        // 1. 验证时间戳 T6
        long now = System.currentTimeMillis();
        if (Math.abs(now - msg.T6) > 30000) {
            System.out.println("⛔ T6 timeout, discard message!");
            return null;
        }

        // 2. 构造 D_RSU_i = X + Y + Ppub·h(...)
        String h_input = ID_RSU_i + X_RSU_i.toString() + Y_RSU_i.toString();
        Element D_RSUi = X_RSU_i.duplicate().add(Y_RSU_i).add(
                SystemSetup.Ppub.duplicate().mulZn(SystemSetup.hashToZr(h_input)));

        // 3. 验证签名
        String sigInput = ID_RSU_i + msg.R_3.toString() + msg.M_i + msg.T6;
        Element h = SystemSetup.hashToZr(sigInput);

        Element left = SystemSetup.P.duplicate().mulZn(msg.sigma_rsu);
        Element right = msg.R_3.duplicate().add(D_RSUi.duplicate().mulZn(h));
        System.out.println("跨域RSU验证时间："+(System.currentTimeMillis()-now)+" ms");

        if (!left.isEqual(right)) {
          //  System.out.println("❌ RSU_j 验证源 RSU_i 签名失败！");
            return null;
        }

        // 4. 解密 M_v = M_i XOR h(R_3 * d_RSU_j)
        Element shared = msg.R_3.duplicate().mulZn(d_RSU_j);
        String M_plain = xorStrings(msg.M_i, SystemSetup.hashToZr(shared.toString()).toString());

        // 5. 模拟构造密文返回给 Vj
        long T7 = System.currentTimeMillis();
        String M_j = xorStrings(M_plain, SystemSetup.hashToZr("session-key").toString()); // 模拟对称加密

        return new RSUResponseToVehicle(M_j, T7);
    }

    // 第四步：Vj 最终验签并解密原文
    public static boolean finalVerifyByVehicle(RSUResponseToVehicle msgFromRSU,
                                               InterDomainMessage originalMsg,
                                               Element Pub_v2v,
                                               String ID_RSU_i) {
        // 1. 验证时间戳 T7
        long now = System.currentTimeMillis();
        if (Math.abs(now - msgFromRSU.T7) > 30000) {
            System.out.println("⛔ T7 timeout, message expired!！");
            return false;
        }

        // 2. 解密 M_v = M_j XOR h(session-key) （模拟）
        String M_plain = xorStrings(msgFromRSU.M_j, SystemSetup.hashToZr("session-key").toString());

        // 3. 恢复 X_Vi = Z_i + Pub_v2v · h(ID_RSU_i)
        Element h = SystemSetup.hashToZr(ID_RSU_i);
        Element X_Vi = originalMsg.Z_i.duplicate().add(Pub_v2v.duplicate().mulZn(h)).getImmutable();

        // 4. 验证 Vi 的签名
        String sigInput = originalMsg.PVID_i + originalMsg.E_i.toString() + M_plain;
        Element sigH = SystemSetup.hashToZr(sigInput);

        Element left = SystemSetup.P.duplicate().mulZn(originalMsg.sigma_vi);
        Element right = originalMsg.E_i.duplicate().add(X_Vi.duplicate().mulZn(sigH));
        System.out.println("Cross-domain vehicle verification time: "+(System.currentTimeMillis()-now)+" ms");

        if (!left.isEqual(right)) {
            System.out.println("❌ The Vj failed to verify the signature of Vi!");
            return false;
        }

        System.out.println("✅ Vj successfully verified the signature of Vi!");
        System.out.println("📨 The final received message is in plain text: " + M_plain);
        return true;
    }



}

