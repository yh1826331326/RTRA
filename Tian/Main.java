package Tian;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        // === A. 系统初始化 ===
        System.out.println("🔧 [Setup]");
        SystemSetup.initialize("a.properties"); // 使用你本地 JPBC 的 pairing 参数文件路径

        // === B. 车辆 Vi 注册 ===
        System.out.println("\n🚗 [Vehicle registration stage]");
        String ID_Vi = "vehicle001";
        Element y_Vi = SystemSetup.Zr.newRandomElement().getImmutable();
        Element Y_Vi = SystemSetup.P.duplicate().mulZn(y_Vi).getImmutable();
        var vReq = new VehicleRegistration.RegistrationRequest(ID_Vi, Y_Vi);
        var vRes = VehicleRegistration.processRegistrationRequest(vReq);
        boolean vOk = VehicleRegistration.verifyAndGenerateKeys(vRes.x_Vi, vRes.X_Vi, y_Vi, ID_Vi);
        if (!vOk) return;

        // === C. RSU 注册 ===
        System.out.println("\n📡 [RSU registration stage]");
        String ID_RSU = "RSU001";
        Element y_RSU = SystemSetup.Zr.newRandomElement().getImmutable();
        Element Y_RSU = SystemSetup.P.duplicate().mulZn(y_RSU).getImmutable();
        var rsuReq = new RSURegistration.RSURequest(ID_RSU, Y_RSU);
        var rsuRes = RSURegistration.processRSURegistration(rsuReq);
        boolean rOk = RSURegistration.verifyAndGenerateRSUKeys(rsuRes, y_RSU, ID_RSU);
        if (!rOk) return;

        // 模拟 RSU 的状态信息
        Element d_RSUj = rsuRes.x_RSUj.duplicate().add(y_RSU).getImmutable();
        Element m_j = SystemSetup.Zr.newRandomElement().getImmutable(); // 模拟域内主密钥
        Element Pub_v2v = SystemSetup.P.duplicate().mulZn(m_j).getImmutable();

        // 模拟 Vi 的状态
        Element d_Vi = vRes.x_Vi.duplicate().add(y_Vi).getImmutable();

        // === D. V2I 双向认证 + 密钥生成 ===
        System.out.println("\n🔐 [V2I two-way authentication stage]");
        long time=System.currentTimeMillis();
        var authReq = V2IAuthentication.vehicleInitiate(ID_Vi, d_Vi, rsuRes.X_RSUj, Y_RSU, ID_RSU);
        System.out.println("The generation time of vehicle signatures： "+(System.currentTimeMillis()-time)+" ms");

        var authResp = V2IAuthentication.rsuRespond(authReq, d_RSUj, ID_RSU, vRes.X_Vi, Y_Vi, m_j, ID_Vi);
        if (authResp == null) return;
        long time1=System.currentTimeMillis();
        String hashR = ID_RSU + rsuRes.X_RSUj.toString() + Y_RSU.toString();
        Element D_r = rsuRes.X_RSUj.duplicate().add(Y_RSU)
                .add(SystemSetup.Ppub.duplicate().mulZn(SystemSetup.hashToZr(hashR))).getImmutable();

        boolean success = V2IAuthentication.vehicleVerify(authResp, d_Vi, D_r, authReq.PID_i, ID_Vi, ID_RSU);
        System.out.println("The vehicle verifies the RSU signature time： "+(System.currentTimeMillis()-time1)+" ms");
        if (success) {
            System.out.println("\n🎉 The protocol process simulation has been completed and the communication has been successfully established！");
        } else {
            System.out.println("\n❌ V2I authentication failed！");
        }

        // === E. 域内 V2V 通信 ===
        System.out.println("\n📨 [In-domain V2V communication simulation]");

// 明文消息
        String plaintextMsg = "Alert123";
        Element M_vi = SystemSetup.hashToZr(plaintextMsg);

// 构造 Z_i 并发送消息（这里用 Vi 模拟 Vj）
        var v2vMsg = IntraDomainV2V.send(
                ID_Vi,
                vRes.x_Vi, // ✅ 正确！部分私钥 x_i
                Pub_v2v,
                M_vi,
                vRes.X_Vi,
                Y_Vi,
                ID_RSU
        );


// 接收方（简化为自己）
        boolean received = IntraDomainV2V.receive(
                v2vMsg,
                d_Vi,
                Pub_v2v,
                ID_RSU
        );

        if (received) {
            System.out.println("🎯 The V2V communication within the domain was successful！");
        } else {
            System.out.println("❌ The V2V communication within the domain failed！");
        }

        // 构造多个消息模拟批量验证
        List<IntraDomainV2V.V2VMessage> msgList = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            Element msg_i = SystemSetup.hashToZr("Alert" + i);
            var m = IntraDomainV2V.send(ID_Vi, vRes.x_Vi, Pub_v2v, msg_i, vRes.X_Vi, Y_Vi, ID_RSU);
            msgList.add(m);
        }

// 批量验证
        long time3=System.currentTimeMillis();
        boolean allValid = IntraDomainV2V.batchVerify(msgList, Pub_v2v, ID_RSU);
        System.out.println("Batch verification time cost： "+(System.currentTimeMillis()-time3));
        if (allValid) {
            System.out.println("🎯 All messages have been batch verified successfully！");
        } else {
            System.out.println("❌ Batch verification failed！");
        }


        // === F. 跨域 V2V 通信模拟 ===
        System.out.println("\n🌐 [Cross-domain V2V communication simulation]");

// 🚗 Vi 构造消息（使用 Vi 的 x_i）
        Element M_vi_cross = SystemSetup.hashToZr("InterZone-Alert");

// Vi 构造跨域消息发往 RSU_j
        var crossMsg = CrossDomainV2V.sendInterDomainMessage(
                ID_Vi,
                vRes.x_Vi,
                M_vi_cross,
                "RSU_A",
                "RSU_B",
                "PID_Vj",
                vRes.X_Vi,       // Vi 的公钥 X_Vi
                Pub_v2v          // 当前域内公钥
        );


// 💡 构造 Z_i = X_i - Pub_v2v * h(ID_RSU_i)
        Element h_rsu_i = SystemSetup.hashToZr("RSU_A");
        crossMsg.Z_i = vRes.X_Vi.duplicate().sub(Pub_v2v.duplicate().mulZn(h_rsu_i)).getImmutable();

// 🛰️ RSU_i 解密并转发
        var fwdMsg = CrossDomainV2V.forwardToTargetRSU(
                crossMsg,
                d_RSUj,     // 临时模拟 RSU_i 用 RSU_j 的私钥（实际应为 RSU_i 的）
                "RSU_A",
                rsuRes.X_RSUj, rsuRes.X_RSUj // 用 RSU_j 的公钥模拟目标 RSU_j 的 X/Y
        );
        if (fwdMsg == null) return;

// 📡 RSU_j 验签并解密
        var rsuResponse = CrossDomainV2V.receiveCrossDomainMessageByRSU(
                fwdMsg,
                "RSU_A",
                rsuRes.X_RSUj, rsuRes.X_RSUj,  // 模拟 RSU_i 的公钥
                d_RSUj
        );
        if (rsuResponse == null) return;

// 🚘 Vj 验证消息签名 & 解密
        boolean finalOK = CrossDomainV2V.finalVerifyByVehicle(
                rsuResponse,
                crossMsg,
                Pub_v2v,
                "RSU_A"
        );

        System.out.println("🎯 Cross-domain V2V communication was successful！");



    }
}


