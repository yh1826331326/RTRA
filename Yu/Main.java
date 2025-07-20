package Yu;

import com.github.davidmoten.geo.GeoHash;
import com.github.davidmoten.geo.LatLong;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Main {

    public static String XOREncrypt(String plaintext, Element sk) {
        byte[] key = sk.toBytes();  // 从 JPBC 元素获取原始字节
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }

        return Base64.getEncoder().encodeToString(result);  // 编码方便传输
    }

    public static Element hashToZr(String input, Field<Element> Zr) {
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        return Zr.newElement().setFromHash(bytes, 0, bytes.length).getImmutable();
    }

    public static void main(String[] args) {
        SystemParam params = new SystemParam();
        TA ta = new TA(params);
        V2VProtocol V2V = new V2VProtocol(params, ta);
        CrossDomainProtocol cdp = new CrossDomainProtocol(params, ta);

        System.out.println("=== Register RSU₁ 与 RSU₂ ===");
        // === 2. 注册 RSU₁ 与 RSU₂ ===
        RSU rsu1 = new RSU(params, "RSU_001");
        var rsu1Record = ta.registerRSU(rsu1.RID, rsu1.getPublicKey());
        boolean rsu1Valid = rsu1.verifyRSUSignature(rsu1Record);
        System.out.println("[RSU₁] Local verification of TA returns the registration signature: " + rsu1Valid);

        RSU rsu2 = new RSU(params, "RSU_002");
        var rsu2Record = ta.registerRSU(rsu2.RID, rsu2.getPublicKey());
        boolean rsu2Valid = rsu2.verifyRSUSignature(rsu2Record);
        System.out.println("[RSU₂] Local verification of TA returns the registration signatur: " + rsu2Valid);

        System.out.println();

        System.out.println("=== Registered vehicles: witness, accident, neighbor ===");
        // === 3. 注册车辆：目击 witness、事故 accident、邻域 neighbor ===
        Vehicle witness = new Vehicle(params, "VID_Witness");
        var witnessRecord = ta.registerVehicle(witness.getVID(), witness.getPublicKey());
        boolean witnessValid = witness.verifyRegistration(witnessRecord, params); // ❌ 由 TA 验证
        System.out.println("Witness Registration verification: " + witnessValid);

        Vehicle accident = new Vehicle(params, "VID_Accident");
        var accidentRecord = ta.registerVehicle(accident.getVID(), accident.getPublicKey());
        boolean accidentValid = accident.verifyRegistration(accidentRecord, params); // ❌ 由 TA 验证
        System.out.println("Accident Registration verification: " + accidentValid);

        Vehicle neighbor = new Vehicle(params, "VID_Neighbor");
        var neighborRecord = ta.registerVehicle(neighbor.getVID(), neighbor.getPublicKey());
        boolean neighborValid = neighbor.verifyRegistration(neighborRecord, params);
        System.out.println("Neighbor Registration verification: " + neighborValid);
        System.out.println();

        System.out.println("=== In-domain V2V two-way authentication: Witness vehicles generate accident reports ===");

        LatLong location1 = new LatLong(40.712776, -74.005974); // New York (Location 1)
        String GH_i = GeoHash.encodeHash(location1.getLat(), location1.getLon(), 8);
        WitnessReport WitReport = V2V.generateReport(witness, witnessRecord, GH_i, 8);
        //System.out.println("[V2V] 目击车辆发起认证请求："+WitReport);
        if (V2V.verifyReport(WitReport, params,GH_i, 8)) {
          //  System.out.println("[事故车辆] 事故车辆验证签名成功");

            // 构造反馈
            LatLong location2 = new LatLong(40.712800, -74.005950);
            String GH_j = GeoHash.encodeHash(location2.getLat(), location2.getLon(), 8);

            WitnessReport AccReport = V2V.generateReport(accident, accidentRecord, GH_j, 8);
            long time=System.currentTimeMillis();
            Element SK_ji=hashToZr(witness.PID+accident.PID+GH_i+witness.U.duplicate().mulZn(accident.u).toString(),params.Zr);
            System.out.println("Calculate the time cost of the negotiation key for the accident vehicle: "+(System.currentTimeMillis()-time)+" ms");
            accident.SK=SK_ji;

            //System.out.println("事故车辆计算的协商密钥为："+SK_ji);

            if(V2V.verifyReport(AccReport, params,GH_j, 8)){
               // System.out.println("[目击车辆] 目击车辆验证签名成功");
                long time1=System.currentTimeMillis();
                Element SK_ij=hashToZr(witness.PID+accident.PID+GH_i+accident.U.duplicate().mulZn(witness.u).toString(),params.Zr);
                System.out.println("Witness the calculation of the time cost for negotiating the key: "+(System.currentTimeMillis()-time1)+" ms");
                //System.out.println("目击车辆计算的协商密钥为："+SK_ij);
                witness.SK=SK_ij;
                String ar_i = "Information related to accident sightings";
                witness.ar=ar_i;
                String AR_i=XOREncrypt(ar_i, SK_ij);
                WitnessReport FeedbackReport= V2V.generateFeedbackd(witness, accident);
                FeedbackReport.AR=AR_i;
                FeedBack fd=V2V.verifyFeedReport(witness, FeedbackReport, accident, params);
                ta.veryfyFeedBack(fd, params);
            }
        }

        System.out.println();
        System.out.println();
        System.out.println("=== Cross-domain V2V: Witness vehicles and generate cross-domain accident warnings ===");

        String AM_i = "The road is blocked due to an accident. It is recommended to take a detour";
        LatLong location3 = new LatLong(40.748817, -73.985428);
        String GH_k = GeoHash.encodeHash(location3.getLat(), location3.getLon(), 5);// 更低精度 GeoHash
        AlertMessage alert = cdp.generateAlert(witness, witnessRecord, AM_i, GH_k,5);
        System.out.println("[Warning] A warning message is generated when a vehicle is witnessed");

        // === 7. RSU₁ 转发预警
        RSUBroadCast fwd = cdp.rsuSign(rsu1, alert);
        System.out.println("[RSU₁] Forward the warning and sign");

        if (cdp.verifyRSUSignature(fwd, rsu1.getPublicKey())) {
            System.out.println("[RSU₂] 验证 Verify that the RSU₁ signature is successful and broadcast a warning");

            if (cdp.verifyAlertReport(fwd.msg, params,GH_k,5)) {
                System.out.println("The early warning signature verification for [Neighborhood Vehicles] was successful");
            }
        }

        System.out.println();

        List<AlertMessage> ams = new ArrayList<>();

        for (int i = 1; i <= 5; i++) {
            Vehicle Car = new Vehicle(params,"CAR" + i);
            var carRecord = ta.registerVehicle(Car.getVID(), Car.getPublicKey());
            boolean carValid = Car.verifyRegistration(carRecord, params); // ❌ 由 TA 验证
           // System.out.println("car 注册验证：" + carValid);

            AlertMessage am= cdp.generateAlert(Car, carRecord, AM_i, GH_k,5);
            ams.add(am);
        }
        long time3=System.currentTimeMillis();
        boolean result = cdp.batchVerify(ams,params,GH_k,5);
        System.out.println("Batch verification result: " + result);
        System.out.println("The batch verification time for early warning messages："+(System.currentTimeMillis()-time3)+" ms");

    }
}
