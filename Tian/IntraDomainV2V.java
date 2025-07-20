package Tian;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class IntraDomainV2V {

    public static class V2VMessage {
        public String PVID_i;
        public Element Y_i, Z_i, sigma;
        public String M_enc;
        public long T3;

        public Element hD_input;

        public V2VMessage(String PVID_i, Element Y_i, Element Z_i, Element sigma, String M_enc, long T3,Element hD_input) {
            this.PVID_i = PVID_i;
            this.Y_i = Y_i.getImmutable();
            this.Z_i = Z_i.getImmutable();
            this.sigma = sigma.getImmutable();
            this.M_enc = M_enc;
            this.T3 = T3;
            this.hD_input=hD_input;
        }
    }

    // 发送方生成域内V2V消息
    public static V2VMessage send(String ID_Vi, Element x_i, Element Pub_v2v, Element M_vi,
                                  Element X_Vi, Element Y_Vj, String ID_RSUj) {

        Element y_i = SystemSetup.Zr.newRandomElement().getImmutable();
      //  System.out.println("y_i: "+y_i);
        Element Y_i = SystemSetup.P.duplicate().mulZn(y_i).getImmutable();
        //System.out.println("Y_i: "+Y_i);

        // 构造伪身份
        Element temp = Pub_v2v.duplicate().mulZn(y_i);
        Element pid_hash = SystemSetup.hashToZr(temp.toString());
        String PVID_i = xorStrings(ID_Vi, pid_hash.toString());
      //  System.out.println("PVID_i: "+PVID_i);

        // 构造认证信息 D_Vj = X_Vi + Y_Vj + Ppub * h(X || Y)
        String hD_input = X_Vi.toString() + Y_Vj.toString();
        Element D_Vj = X_Vi.duplicate().add(Y_Vj).add(SystemSetup.Ppub.duplicate().mulZn(SystemSetup.hashToZr(hD_input)));
     //   System.out.println("D_Vj: "+D_Vj);

        // 加密消息 M = M_vi XOR h(y_i * D_Vj)
        Element shared = D_Vj.duplicate().mulZn(y_i);
        String hShared = SystemSetup.hashToZr(shared.toString()).toString();
        String M_enc = xorStrings(M_vi.toString(), hShared);
     //   System.out.println("M_enc: "+M_enc);

        // 构造 Z_i = X_Vi - Pub_v2v * h(ID_RSUj)
        Element h_rsu = SystemSetup.hashToZr(ID_RSUj);
      //  System.out.println("X_Vi: "+X_Vi);
        Element Z_i = X_Vi.duplicate().sub(Pub_v2v.duplicate().mulZn(h_rsu)).getImmutable();
       // System.out.println(SystemSetup.P.duplicate().mulZn(x_i).isEqual(X_Vi));

        // 构造签名 σ = y_i + x_i * h(ID_RSUj || M_enc || T3)
        long T3 = System.currentTimeMillis();
        String sig_input = ID_RSUj + M_enc + T3;
        Element h = SystemSetup.hashToZr(sig_input);
     //   System.out.println("h "+h);
        Element sigma = y_i.duplicate().add(x_i.duplicate().mul(h)).getImmutable();
   //     System.out.println("sigma: "+sigma);

        return new V2VMessage(PVID_i, Y_i, Z_i, sigma, M_enc, T3,SystemSetup.hashToZr(hD_input));
    }

    // 接收方验证域内V2V消息
    public static boolean receive(V2VMessage msg, Element d_Vj, Element Pub_v2v, String ID_RSUj) {
        long now = System.currentTimeMillis();
        if (Math.abs(now - msg.T3) > 30000) {
            System.out.println("⚠️ The timestamp is illegal!");
            return false;
        }

        // 恢复 X_Vi = Z_i + Pub_v2v * h(ID_RSUj)
        Element h_rsu = SystemSetup.hashToZr(ID_RSUj);
        Element X_Vi = msg.Z_i.duplicate().add(Pub_v2v.duplicate().mulZn(h_rsu)).getImmutable();
    //    System.out.println("X_Vi: "+X_Vi);

        // 验证签名 σ·P =? Y_i + X_Vi·h
        String sig_input = ID_RSUj + msg.M_enc + msg.T3;
        Element h = SystemSetup.hashToZr(sig_input);
    //    System.out.println("h: "+h);
        Element left = SystemSetup.P.duplicate().mulZn(msg.sigma);
        Element right = msg.Y_i.duplicate().add( X_Vi.add(SystemSetup.Ppub.mulZn(msg.hD_input)).duplicate().mulZn(h));


        if (!left.isEqual(right)) {
            System.out.println("❌ Signature verification failed!");
            System.out.println("left: " + left);
            System.out.println("right: " + right);
            return false;
        }

        // 解密消息 M_vi = M_enc XOR h(Y_i * d_Vj)
        Element shared = msg.Y_i.duplicate().mulZn(d_Vj);
        String hShared = SystemSetup.hashToZr(shared.toString()).toString();
        String mPlain = xorStrings(msg.M_enc, hShared);

        System.out.println("✅ Received the message successfully! \"Plaintext: " + mPlain);
        return true;
    }

    public static String xorStrings(String a, String b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(a.length(), b.length()); i++) {
            sb.append((char)(a.charAt(i) ^ b.charAt(i)));
        }
        return sb.toString();
    }

    // 批量验证函数
    public static boolean batchVerify(List<V2VMessage> msgs, Element Pub_v2v, String ID_RSUj) {
        Element sumLeft = SystemSetup.G1.newZeroElement().getImmutable();
        Element sumY = SystemSetup.G1.newZeroElement().getImmutable();
        Element sumX = SystemSetup.G1.newZeroElement().getImmutable();

        Element h_rsu = SystemSetup.hashToZr(ID_RSUj);
        Element sumP = SystemSetup.Zr.newZeroElement().getImmutable();
        for (V2VMessage msg : msgs) {
            // H_0_i = h(PVID_i || M || T3)
            String H_input =ID_RSUj + msg.M_enc + msg.T3;
            Element H0 = SystemSetup.hashToZr(H_input);

            // sum(σ_i · P)
            sumLeft = sumLeft.duplicate().add(SystemSetup.P.duplicate().mulZn(msg.sigma)).getImmutable();

            // sum(Y_i)
            sumY = sumY.duplicate().add(msg.Y_i).getImmutable();

            Element X_Vi = msg.Z_i.duplicate().add(Pub_v2v.duplicate().mulZn(h_rsu)).getImmutable();

            // sum(Z_i · H0)
            sumX = sumX.duplicate().add(X_Vi.duplicate().mulZn(H0)).getImmutable();

            // sum(H0)
            sumP = sumP.duplicate().add(msg.hD_input.duplicate().mul(H0)).getImmutable();

        }

        // Pub_v2v · h(ID_RSUj) · sum(H0)
        Element right3 = SystemSetup.Ppub.duplicate().mulZn(sumP).getImmutable();

        // 右边：Y + Z·H + Pub_v2v · h_rsu · sum(H)
        Element sumRight = sumY.duplicate().add(sumX).add(right3).getImmutable();

        if (sumLeft.isEqual(sumRight)) {
            System.out.println("✅ Batch verification passed, co-verification " + msgs.size() + " messages！");
            return true;
        } else {
            System.out.println("❌ Batch verification failed！");
            System.out.println("sumLeft  = " + sumLeft);
            System.out.println("sumRight = " + sumRight);
            return false;
        }
    }

}
