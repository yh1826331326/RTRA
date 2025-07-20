package WangJing;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

/*
 * VANET 双向认证与消息通信协议 - JPBC 实现工程结构
 * Author: ChatGPT (based on user specification)
 */

// 省略其余类定义，同上 ...

public class Main {
    public static void main(String[] args) throws Exception {
        SystemSetup.setup("a.properties");

        Entity vehicle = new Entity("VID123");
        Entity rsu1 = new Entity("RSU001");
        Entity rsu2 = new Entity("RSU002");

        vehicle.registerWithKGC();
        rsu1.registerWithKGC();
        rsu2.registerWithKGC();

        System.out.println("Registration verification: ");
        System.out.println("Vehicle: " + vehicle.verify());
        System.out.println("RSU1: " + rsu1.verify());
        System.out.println("RSU2: " + rsu2.verify());

        List<Entity> rsuList = List.of(rsu1, rsu2);

        // Vehicle initiates authentication request
        AuthRequest authReq = AuthProtocol.vehicleAuthRequest(vehicle, rsuList);
        System.out.println("Vehicle authentication request sent: T, sigma, k");

        // RSU1 verifies vehicle identity
        boolean rsuVerified = AuthProtocol.verifyVehicle(rsu1, vehicle, authReq.T, authReq.sigma, authReq.coeffs);
        System.out.println("RSU1 vehicle verification result: " + rsuVerified);

        // RSU1 generates response
        RSUResponse rsuResp = AuthProtocol.generateRSUResponse(rsu1, vehicle, authReq.k);

        // Vehicle verifies RSU1 response
        boolean vehicleVerified = AuthProtocol.verifyRSUResponse(vehicle, rsu1, rsuResp, authReq.k);
        System.out.println("Vehicle verifies RSU1 response: " + vehicleVerified);

        // Message encryption communication test
        List<String> msgs = List.of("temperature=36.5"); // Only sending one
        Element h1 = SystemSetup.HtoZr(1, rsu1.PID.toString(), rsu1.PK_X.toString(), rsu1.PK_R.toString(), SystemSetup.Ppub.toString());
        Element base = rsu1.PK_X.duplicate().add(rsu1.PK_R).add(SystemSetup.Ppub.duplicate().mulZn(h1));
        Element scalar = vehicle.x.duplicate().add(vehicle.y).add(SystemSetup.Zr.newElementFromHash(authReq.T.toBytes(), 0, authReq.T.toBytes().length));
        Element Q = base.duplicate().mulZn(scalar).getImmutable();
        Element gamma1 = SystemSetup.HtoZr(2, Q.toString());

        String ciphertext = MessageEncryptor.encryptMessages(msgs, List.of(gamma1), authReq.k);

        List<String> recovered = MessageEncryptor.decryptMessages(ciphertext, gamma1, authReq.k);
        System.out.println("Decryption result: " + recovered);
    }

}

