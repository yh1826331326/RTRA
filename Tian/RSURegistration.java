package Tian;

import it.unisa.dia.gas.jpbc.Element;

public class RSURegistration {

    // RSU注册请求消息结构
    public static class RSURequest {
        public String ID_RSUj;
        public Element Y_RSUj;

        public RSURequest(String ID, Element Y) {
            this.ID_RSUj = ID;
            this.Y_RSUj = Y.getImmutable();
        }
    }

    // RSU注册响应消息结构
    public static class RSUResponse {
        public Element x_RSUj, X_RSUj;

        public RSUResponse(Element x, Element X) {
            this.x_RSUj = x.getImmutable();
            this.X_RSUj = X.getImmutable();
        }
    }

    // TA 处理 RSU 的注册请求
    public static RSUResponse processRSURegistration(RSURequest request) {
        // 生成随机数 v
        Element v = SystemSetup.Zr.newRandomElement().getImmutable();
        Element X_RSUj = SystemSetup.P.duplicate().mulZn(v).getImmutable();

        // 计算部分私钥 x_RSUj = v + s · h(ID || X || Y)
        String hashInput = request.ID_RSUj + X_RSUj.toString() + request.Y_RSUj.toString();
        Element hash = SystemSetup.hashToZr(hashInput);
        Element x_RSUj = v.duplicate().add(SystemSetup.s.duplicate().mul(hash)).getImmutable();

        return new RSUResponse(x_RSUj, X_RSUj);
    }

    // RSU 端验证并生成密钥、广播信息
    public static boolean verifyAndGenerateRSUKeys(RSUResponse res, Element y_RSUj, String ID_RSUj) {
        Element X_RSUj = res.X_RSUj;
        Element x_RSUj = res.x_RSUj;

        // 计算 Y = y · P
        Element Y_RSUj = SystemSetup.P.duplicate().mulZn(y_RSUj).getImmutable();

        // 验证：x · P =? X + Ppub · h(ID || X || Y)
        String hashInput = ID_RSUj + X_RSUj.toString() + Y_RSUj.toString();
        Element hash = SystemSetup.hashToZr(hashInput);
        Element left = SystemSetup.P.duplicate().mulZn(x_RSUj);
        Element right = X_RSUj.duplicate().add(SystemSetup.Ppub.duplicate().mulZn(hash));

        if (!left.isEqual(right)) {
            System.out.println("❌ RSU registration verification failed！");
            return false;
        }

        // 完整私钥 d = x + y
        Element d_RSUj = x_RSUj.duplicate().add(y_RSUj).getImmutable();
        Element P_RSUj_X = X_RSUj;
        Element P_RSUj_Y = Y_RSUj;

        // 域内主密钥 & 公钥
        Element m_j = SystemSetup.Zr.newRandomElement().getImmutable();
        Element Pub_v2v = SystemSetup.P.duplicate().mulZn(m_j).getImmutable();

        // 模拟广播
        System.out.println("✅ RSU registration is successful！");
        System.out.println("RSU Public Key: {" + P_RSUj_X + ", " + P_RSUj_Y + "}");
        System.out.println("The primary public key within the domain Pub_v2v = " + Pub_v2v);

        // 真实系统中应将 {d_RSUj, P_RSUj, m_j} 存入本地安全模块
        return true;
    }
}

