package Wang;

import it.unisa.dia.gas.jpbc.Element;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {
    public static void main(String[] args) throws Exception {
        SystemSetup.initialize();

        // Create RSU and vehicle
        RSU rsu = new RSU("RSU001");
        rsu.requestCertificate();

        Vehicle car = new Vehicle("CAR007");
        car.requestCertificate();

        System.out.println("Performance metrics:");
        // Bi-directional authentication
        long time1 = System.currentTimeMillis();
        AuthRequest authReq = car.generateAuthRequest("PSEUDO_ABC123");
        System.out.println("Vehicle signature generation time: " + (System.currentTimeMillis() - time1) + " ms");

        AuthResponse authResp = AuthProtocol.RSURespond(rsu, authReq);

        Element SK_car = AuthProtocol.VehicleVerifyAndDeriveSK(car, authReq, authResp);

        System.out.println();
        // Compare the two SKs
        System.out.println("Vehicle session key: " + SK_car);
        System.out.println("RSU session key: " + authResp.SK);
        System.out.println("Are they equal? " + SK_car.isEqual(authResp.SK));

        // Assuming GK group key is shared (in practice should be distributed by the server)
        byte[] GK = "1234567890abcdef".getBytes(StandardCharsets.UTF_8); // 16-byte AES key

        // Vehicle broadcasts message
        BroadcastMessage bm = Broadcaster.generateBroadcast(car, "PSEUDO123", "POS=(128,88), SPD=60km/h", GK);
        System.out.println("Broadcast content (ciphertext): " + bm.encryptedMsg);

        // Other vehicles or RSU receive and verify
        String plaintext = Receiver.receiveAndVerify(bm, GK);
        System.out.println("Decrypted broadcast message: " + plaintext);

        List<BroadcastMessage> msgs = new ArrayList<>();

        for (int i = 1; i <= 30; i++) {
            Vehicle Car = new Vehicle("CAR" + i);
            Car.requestCertificate();

            String pseudo = "PSEUDO_" + i;
            String content = "POS=(10" + i + ",88), SPD=6" + i + "km/h";

            BroadcastMessage Bm = Broadcaster.generateBroadcast(car, pseudo, content, GK);
            msgs.add(Bm);
        }

        // Batch verification
        long time3 = System.currentTimeMillis();
        boolean result = BatchVerifier.verifyBatch(msgs);
        System.out.println();

        System.out.println("Batch verification result: " + result);
        System.out.println("Batch verification time for five warning messages: " + (System.currentTimeMillis() - time3) + " ms");

        System.out.println();
        String serverID = "TA_SERVER";

        // Vehicle generates pseudonym request
        PseudoRequest req = PseudoManager.requestNewPseudos(car.ID, serverID);

        // Server processes request and responds with ElGamal encryption
        PseudoResponse resp = Server.respondNewPseudos(req, serverID, car.Y);
        // Vehicle decrypts pseudonyms
        String[] pseudos = VehicleReceiver.decryptResponse(resp, car.x);
        System.out.println("Vehicle new pseudonym set: " + Arrays.toString(pseudos));
    }
}
