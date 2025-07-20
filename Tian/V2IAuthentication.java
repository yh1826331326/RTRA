package Tian;

import it.unisa.dia.gas.jpbc.Element;

public class V2IAuthentication {

    // 步骤 1：车辆 Vi 发起认证请求
    public static class AuthRequest {
        public String PID_i;
        public Element R1, V_v;
        public long T1;

        public AuthRequest(String PID_i, Element R1, Element V_v, long T1) {
            this.PID_i = PID_i;
            this.R1 = R1.getImmutable();
            this.V_v = V_v.getImmutable();
            this.T1 = T1;
        }
    }

    // 步骤 2：RSU 响应认证请求
    public static class AuthResponse {
        public String ID_RSUj;
        public Element R2, H, Z_i, V_r;
        public long T2;

        public AuthResponse(String ID, Element R2, Element H, Element Z_i, Element V_r, long T2) {
            this.ID_RSUj = ID;
            this.R2 = R2.getImmutable();
            this.H = H.getImmutable();
            this.Z_i = Z_i.getImmutable();
            this.V_r = V_r.getImmutable();
            this.T2 = T2;
        }
    }

    // 第一步：Vi → RSU
    public static AuthRequest vehicleInitiate(String ID_Vi, Element d_Vi, Element X_RSU, Element Y_RSU, String ID_RSU) {

        Element r1 = SystemSetup.Zr.newRandomElement().getImmutable();
        Element R1 = SystemSetup.P.duplicate().mulZn(r1).getImmutable();

        // D_r = X + Y + Ppub * h(ID_RSU || X || Y)
        String hashR = ID_RSU + X_RSU.toString() + Y_RSU.toString();
        Element D_r = X_RSU.duplicate().add(Y_RSU).add(SystemSetup.Ppub.duplicate().mulZn(SystemSetup.hashToZr(hashR))).getImmutable();

        String PID_i = xorStrings(ID_Vi, SystemSetup.hashToZr(D_r.duplicate().mulZn(r1).toString()).toString());

        long T1 = System.currentTimeMillis();
        String hashVv = R1.toString() + PID_i + T1;
        Element V_v = r1.duplicate().add(d_Vi.duplicate().mulZn(SystemSetup.hashToZr(hashVv))).getImmutable();


        return new AuthRequest(PID_i, R1, V_v, T1);
    }

    // 第二步：RSU → Vi
//    public static AuthResponse rsuRespond(AuthRequest request, Element d_RSUj, String ID_RSUj, Element X_Vi, Element Y_Vi, Element m_j, String ID_Vi_original) {
//        long Tc = System.currentTimeMillis();
//        if (Math.abs(request.T1 - Tc) >= 30000) {  // 30秒超时
//            System.out.println("⛔ 消息过期！");
//            return null;
//        }
//
//        // 恢复 ID
//        Element D_rsu = d_RSUj;
//        String ID_Vi_recovered = xorStrings(request.PID_i, SystemSetup.hashToZr(request.R1.duplicate().mulZn(D_rsu).toString()).toString());
//
//        // 计算 D_v
//        String hashDv = X_Vi.toString() + Y_Vi.toString();
//        Element D_v = X_Vi.duplicate().add(Y_Vi).add(SystemSetup.Ppub.duplicate().mulZn(SystemSetup.hashToZr(hashDv)));
//
//        // 验证签名
//        String hV = request.R1.toString() + request.PID_i + request.T1;
//        Element left = SystemSetup.P.duplicate().mulZn(request.V_v);
//        Element right = request.R1.duplicate().add(D_v.duplicate().mulZn(SystemSetup.hashToZr(hV)));
//        if (!left.isEqual(right)) {
//            System.out.println("❌ 验证 V_v 失败！");
//            return null;
//        }
//        System.out.println("RSU验证签名时间： "+(System.currentTimeMillis()-Tc)+" ms");
//
//        long time=System.currentTimeMillis();
//
//        // 认证通过，生成响应参数
//        Element r2 = SystemSetup.Zr.newRandomElement().getImmutable();
//        Element z_i = SystemSetup.Zr.newRandomElement().getImmutable();
//        Element R2 = SystemSetup.P.duplicate().mulZn(r2).getImmutable();
//
//        Element Z_i = SystemSetup.P.duplicate().mulZn(z_i).getImmutable();
//
//        Element x_i = z_i.duplicate().add(m_j.duplicate().mul(SystemSetup.hashToZr(ID_RSUj))).getImmutable();
//
//        Element H = xorElements(SystemSetup.hashToZr(D_v.duplicate().mulZn(r2).toString()), SystemSetup.hashToZr(ID_Vi_original + x_i.toString() + Z_i.toString()));
//
//        long T2 = System.currentTimeMillis();
//        String hVr = R2.toString() + Z_i.toString() + H.toString() + T2;
//        Element V_r = r2.duplicate().add(d_RSUj.duplicate().mul(SystemSetup.hashToZr(hVr))).getImmutable();
//        System.out.println("RSU生成签名时间 "+(System.currentTimeMillis()-time)+" ms");
//
//        long time1=System.currentTimeMillis();
//        Element R_ij = request.R1.duplicate().mulZn(r2).getImmutable();
//        Element SK_ij = SystemSetup.hashToZr(R_ij.toString() + ID_Vi_recovered + ID_RSUj);
//        System.out.println("协商密钥计算时间： "+(System.currentTimeMillis()-time1)+" ms");
//        System.out.println("协商密钥为："+SK_ij);
//
//        return new AuthResponse(ID_RSUj, R2, H, Z_i, V_r, T2);
//    }
//
//    // 第三步：Vi验证响应并完成密钥协商
//    public static boolean vehicleVerify(AuthResponse resp, Element d_Vi, Element D_r, String PID_i, String ID_Vi, String ID_RSU) {
//        long Tc = System.currentTimeMillis();
//        if (Math.abs(resp.T2 - Tc) >= 30000) {
//            System.out.println("⛔ 响应已过期！");
//            return false;
//        }
//
//        String hVr = resp.R2.toString() + resp.Z_i.toString() + resp.H.toString() + resp.T2;
//        Element left = SystemSetup.P.duplicate().mulZn(resp.V_r);
//        Element right = resp.R2.duplicate().add(D_r.duplicate().mulZn(SystemSetup.hashToZr(hVr)));
//        if (!left.isEqual(right)) {
//            System.out.println("❌ V_r 验证失败！");
//            return false;
//        }
//
//
//        long time1=System.currentTimeMillis();
//        Element R_ij = resp.R2.duplicate().mulZn(SystemSetup.hashToZr(PID_i));  // or use r1 · R2
//        Element SK_ij = SystemSetup.hashToZr(R_ij.toString() + ID_Vi + ID_RSU);
//        System.out.println("协商密钥计算时间： "+(System.currentTimeMillis()-time1)+" ms");
//
//        Element h = SystemSetup.hashToZr(resp.R2.duplicate().mulZn(d_Vi).toString());
//        String H_content = xorStrings(resp.H.toString(), h.toString());
//
//        System.out.println("✅ 双向认证完成，SK_ij: " + SK_ij);
//        System.out.println("解密出的 H 内容：" + H_content);
//        return true;
//    }

    public static AuthResponse rsuRespond(AuthRequest request, Element d_RSUj, String ID_RSUj, Element X_Vi, Element Y_Vi, Element m_j, String ID_Vi_original) {
        long Tc = System.currentTimeMillis();
        if (Math.abs(request.T1 - Tc) >= 30000) {  // 30 seconds timeout
            System.out.println("⛔ Message expired!");
            return null;
        }

        // Recover ID
        Element D_rsu = d_RSUj;
        String ID_Vi_recovered = xorStrings(request.PID_i, SystemSetup.hashToZr(request.R1.duplicate().mulZn(D_rsu).toString()).toString());

        // Calculate D_v
        String hashDv = X_Vi.toString() + Y_Vi.toString();
        Element D_v = X_Vi.duplicate().add(Y_Vi).add(SystemSetup.Ppub.duplicate().mulZn(SystemSetup.hashToZr(hashDv)));

        // Verify signature
        String hV = request.R1.toString() + request.PID_i + request.T1;
        Element left = SystemSetup.P.duplicate().mulZn(request.V_v);
        Element right = request.R1.duplicate().add(D_v.duplicate().mulZn(SystemSetup.hashToZr(hV)));
        if (!left.isEqual(right)) {
            System.out.println("❌ Verification of V_v failed!");
            return null;
        }
        System.out.println("RSU signature verification time: " + (System.currentTimeMillis() - Tc) + " ms");

        long time = System.currentTimeMillis();

        // Authentication successful, generate response parameters
        Element r2 = SystemSetup.Zr.newRandomElement().getImmutable();
        Element z_i = SystemSetup.Zr.newRandomElement().getImmutable();
        Element R2 = SystemSetup.P.duplicate().mulZn(r2).getImmutable();

        Element Z_i = SystemSetup.P.duplicate().mulZn(z_i).getImmutable();

        Element x_i = z_i.duplicate().add(m_j.duplicate().mul(SystemSetup.hashToZr(ID_RSUj))).getImmutable();

        Element H = xorElements(SystemSetup.hashToZr(D_v.duplicate().mulZn(r2).toString()), SystemSetup.hashToZr(ID_Vi_original + x_i.toString() + Z_i.toString()));

        long T2 = System.currentTimeMillis();
        String hVr = R2.toString() + Z_i.toString() + H.toString() + T2;
        Element V_r = r2.duplicate().add(d_RSUj.duplicate().mul(SystemSetup.hashToZr(hVr))).getImmutable();
        System.out.println("RSU signature generation time: " + (System.currentTimeMillis() - time) + " ms");

        long time1 = System.currentTimeMillis();
        Element R_ij = request.R1.duplicate().mulZn(r2).getImmutable();
        Element SK_ij = SystemSetup.hashToZr(R_ij.toString() + ID_Vi_recovered + ID_RSUj);
        System.out.println("Key agreement calculation time: " + (System.currentTimeMillis() - time1) + " ms");
        System.out.println("The agreed key is: " + SK_ij);

        return new AuthResponse(ID_RSUj, R2, H, Z_i, V_r, T2);
    }

    // Step 3: Vi verifies the response and completes the key agreement
    public static boolean vehicleVerify(AuthResponse resp, Element d_Vi, Element D_r, String PID_i, String ID_Vi, String ID_RSU) {
        long Tc = System.currentTimeMillis();
        if (Math.abs(resp.T2 - Tc) >= 30000) {
            System.out.println("⛔ Response expired!");
            return false;
        }

        String hVr = resp.R2.toString() + resp.Z_i.toString() + resp.H.toString() + resp.T2;
        Element left = SystemSetup.P.duplicate().mulZn(resp.V_r);
        Element right = resp.R2.duplicate().add(D_r.duplicate().mulZn(SystemSetup.hashToZr(hVr)));
        if (!left.isEqual(right)) {
            System.out.println("❌ Verification of V_r failed!");
            return false;
        }

        long time1 = System.currentTimeMillis();
        Element R_ij = resp.R2.duplicate().mulZn(SystemSetup.hashToZr(PID_i));  // or use r1 · R2
        Element SK_ij = SystemSetup.hashToZr(R_ij.toString() + ID_Vi + ID_RSU);
        System.out.println("Key agreement calculation time: " + (System.currentTimeMillis() - time1) + " ms");

        Element h = SystemSetup.hashToZr(resp.R2.duplicate().mulZn(d_Vi).toString());
        String H_content = xorStrings(resp.H.toString(), h.toString());

        System.out.println("✅ Bi-directional authentication completed, SK_ij: " + SK_ij);
        System.out.println("Decrypted H content: " + H_content);
        return true;
    }


    // 字符串异或（模拟PID隐藏/还原）
    public static String xorStrings(String a, String b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(a.length(), b.length()); i++) {
            sb.append((char) (a.charAt(i) ^ b.charAt(i)));
        }
        return sb.toString();
    }

    // Element 异或（用于模拟H加密）
    public static Element xorElements(Element a, Element b) {
        byte[] aBytes = a.toBytes();
        byte[] bBytes = b.toBytes();
        byte[] res = new byte[Math.min(aBytes.length, bBytes.length)];
        for (int i = 0; i < res.length; i++) {
            res[i] = (byte) (aBytes[i] ^ bBytes[i]);
        }
        return SystemSetup.Zr.newElementFromBytes(res).getImmutable();
    }
}

