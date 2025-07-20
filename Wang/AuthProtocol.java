
package Wang;

import it.unisa.dia.gas.jpbc.Element;

class AuthResponse {
    public String rsuID;
    public Element B;
    public long timestamp;
    public Element sigma2;
    public Cert cert;
    public Element SK; // Session key (for local storage only)
}

public class AuthProtocol {
    // RSU verifies the vehicle and responds
    public static AuthResponse RSURespond(RSU rsu, AuthRequest req) throws Exception {
        long now = System.currentTimeMillis();
        if (Math.abs(now - req.timestamp) > 10000) throw new RuntimeException("Authentication request timeout");

        long time2 = System.currentTimeMillis();
        // Verify the vehicle's certificate
        if (!req.cert.verifyCA()) throw new RuntimeException("Vehicle certificate is invalid");
        // Verify signature sigma1
        String M1 = req.pseudo + req.A.toString() + req.timestamp;
        Element hM1 = SystemSetup.HtoG1(M1);
        Element left = SystemSetup.pairing.pairing(req.sigma1, SystemSetup.P);
        Element right = SystemSetup.pairing.pairing(hM1, req.cert.pubKey);
        if (!left.isEqual(right)) throw new RuntimeException("Signature verification failed");
        System.out.println("RSU signature verification time: " + (System.currentTimeMillis() - time2) + " ms");

        long time3 = System.currentTimeMillis();
        // Generate RSU response
        Element b = SystemSetup.Zq.newRandomElement().getImmutable();
        Element B = SystemSetup.P.duplicate().mulZn(b).getImmutable();
        long T2 = System.currentTimeMillis();
        String M2 = rsu.ID + B.toString() + T2;
        Element hM2 = SystemSetup.HtoG1(M2);
        Element sigma2 = hM2.duplicate().mulZn(rsu.sk).getImmutable();
        System.out.println("RSU signature generation time: " + (System.currentTimeMillis() - time3) + " ms");

        long time1 = System.currentTimeMillis();
        Element SK = SystemSetup.H1(SystemSetup.pairing.pairing(req.A, B)).getImmutable();
        System.out.println("Session key calculation time: " + (System.currentTimeMillis() - time1) + " ms");

        AuthResponse resp = new AuthResponse();
        resp.rsuID = rsu.ID;
        resp.B = B;
        resp.timestamp = T2;
        resp.sigma2 = sigma2;
        resp.cert = rsu.cert;
        resp.SK = SK;
        return resp;
    }

    // Vehicle verifies RSU and derives shared key
    public static Element VehicleVerifyAndDeriveSK(Vehicle vehicle, AuthRequest req, AuthResponse resp) throws Exception {
        long now = System.currentTimeMillis();
        if (Math.abs(now - resp.timestamp) > 10000) throw new RuntimeException("RSU response timeout");

        long time2 = System.currentTimeMillis();
        // Verify RSU certificate
        if (!resp.cert.verifyCA()) throw new RuntimeException("RSU certificate is invalid");
        // Verify signature sigma2
        String M2 = resp.rsuID + resp.B.toString() + resp.timestamp;
        Element hM2 = SystemSetup.HtoG1(M2);
        Element left = SystemSetup.pairing.pairing(resp.sigma2, SystemSetup.P);
        Element right = SystemSetup.pairing.pairing(hM2, resp.cert.pubKey);
        if (!left.isEqual(right)) throw new RuntimeException("RSU signature verification failed");
        System.out.println("Vehicle signature verification time: " + (System.currentTimeMillis() - time2) + " ms");

        long time1 = System.currentTimeMillis();
        SystemSetup.H1(SystemSetup.pairing.pairing(resp.B, req.A)).getImmutable();
        System.out.println("Session key calculation time: " + (System.currentTimeMillis() - time1) + " ms");
        // Generate shared session key
        return SystemSetup.H1(SystemSetup.pairing.pairing(resp.B, req.A)).getImmutable();
    }
}

