package Tian;

import it.unisa.dia.gas.jpbc.Element;

public class VehicleRegistration {

    // 注册请求消息：车辆 ID 和 Y_Vi
    public static class RegistrationRequest {
        public String ID_Vi;
        public Element Y_Vi;

        public RegistrationRequest(String ID_Vi, Element Y_Vi) {
            this.ID_Vi = ID_Vi;
            this.Y_Vi = Y_Vi.getImmutable();
        }
    }

    // 注册响应消息：x_Vi, X_Vi
    public static class RegistrationResponse {
        public Element x_Vi, X_Vi;

        public RegistrationResponse(Element x_Vi, Element X_Vi) {
            this.x_Vi = x_Vi.getImmutable();
            this.X_Vi = X_Vi.getImmutable();
        }
    }

    // 车辆注册流程：TA处理注册请求
    public static RegistrationResponse processRegistrationRequest(RegistrationRequest request) {
        // TA 生成随机数 u
        Element u = SystemSetup.Zr.newRandomElement().getImmutable();
        Element X_Vi = SystemSetup.P.duplicate().mulZn(u).getImmutable();

        // 计算部分私钥 x_Vi = u + s · h(X_Vi || Y_Vi)
        String hashInput = X_Vi.toString() + request.Y_Vi.toString();
        Element hash = SystemSetup.hashToZr(hashInput);
        Element x_Vi = u.duplicate().add(SystemSetup.s.duplicate().mul(hash)).getImmutable();

        return new RegistrationResponse(x_Vi, X_Vi);
    }

    // 车辆接收 TA 返回消息后进行验证并生成完整私钥、公钥
    public static boolean verifyAndGenerateKeys(Element x_Vi, Element X_Vi, Element y_Vi, String ID_Vi) {
        // Verification: x_Vi · P =? X_Vi + Ppub · h(X_Vi || Y_Vi)
        Element Y_Vi = SystemSetup.P.duplicate().mulZn(y_Vi).getImmutable();
        String hashInput = X_Vi.toString() + Y_Vi.toString();
        Element hash = SystemSetup.hashToZr(hashInput);

        Element left = SystemSetup.P.duplicate().mulZn(x_Vi).getImmutable();
        Element right = X_Vi.duplicate().add(SystemSetup.Ppub.duplicate().mulZn(hash)).getImmutable();

        if (!left.isEqual(right)) {
            System.out.println("❌ Verification failed, re-registration required!");
            return false;
        }

        // Complete private key d_Vi = x_Vi + y_Vi
        Element d_Vi = x_Vi.duplicate().add(y_Vi).getImmutable();

        // Public key P_Vi = {X_Vi, Y_Vi}
        System.out.println("✅ Verification successful! Vehicle " + ID_Vi + " registered successfully!");
        System.out.println("P_Vi = {" + X_Vi + ", " + Y_Vi + "}");
        System.out.println("d_Vi = " + d_Vi);

        // In a real project, this should be stored in TPD
        return true;
    }

}
