package Wang;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class BatchVerifier {
    // 批量验证签名有效性
    public static boolean verifyBatch(List<BroadcastMessage> messages) throws Exception {
        Element leftProduct = SystemSetup.pairing.getGT().newOneElement().getImmutable();
        Element rightProduct = SystemSetup.pairing.getGT().newOneElement().getImmutable();

        for (BroadcastMessage msg : messages) {
            // 时间戳校验
            long now = System.currentTimeMillis();
            if (Math.abs(now - msg.timestamp) > 10000) {
                System.out.println("Message timeout, skip" + msg.pseudo);
                continue;
            }

            // 验证证书
            if (!msg.cert.verifyCA()) {
                System.out.println("Invalid certificate: " + msg.pseudo);
                continue;
            }

            // 构造消息串
            String M3 = msg.pseudo + msg.encryptedMsg + msg.timestamp;
            Element h = SystemSetup.HtoG1(M3);

            // 左右累乘
            Element e1 = SystemSetup.pairing.pairing(msg.signature, SystemSetup.P);
            Element e2 = SystemSetup.pairing.pairing(h, msg.cert.pubKey);
            leftProduct = leftProduct.mul(e1).getImmutable();
            rightProduct = rightProduct.mul(e2).getImmutable();
        }

        return leftProduct.isEqual(rightProduct);
    }
}

