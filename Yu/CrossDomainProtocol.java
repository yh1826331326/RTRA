package Yu;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class CrossDomainProtocol {

    private final SystemParam params;
    private final TA ta;

    public CrossDomainProtocol(SystemParam params, TA ta){
        this.params = params;
        this.ta = ta;
    }


    private Element hashToZr(String input) {
        return params.Zr.newElement().setFromHash(input.getBytes(), 0, input.length()).getImmutable();
    }
    public static byte[] extendMask(byte[] mask, int targetLength) {
        byte[] extended = new byte[targetLength];
        for (int i = 0; i < targetLength; i++) {
            extended[i] = mask[i % mask.length]; // 重复掩码填满
        }
        return extended;
    }

    public static byte[] xor(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }

    public AlertMessage generateAlert(Vehicle witness, TA.VehicleRecord record,
                                          String AM_i, String GH, int p2) {
        long Tsp3 = System.currentTimeMillis();
        Element zi = params.Zr.newRandomElement().getImmutable();
       // System.out.println("zi: "+zi);
        Element Zi = params.P.duplicate().mulZn(zi).getImmutable();
       // System.out.println("Zi: "+Zi);

        Element h5 = hashToZr(witness.PID+ AM_i + Zi.toString() +witness.V+ Tsp3);
      //  System.out.println("h5: "+h5);
        Element h6 = hashToZr(h5+ Arrays.toString(witness.Bi.toBytes())+GH+p2);
      //  System.out.println("h6: "+h6);

        Element sigma =witness.v.duplicate().mul(h5).add(witness.xi.duplicate().mul(h6)).add(zi).getImmutable();
        System.out.println("Generation time of cross-domain signature information: "+(System.currentTimeMillis()-Tsp3)+ " ms");
        //System.out.println("sigma: "+sigma);

        Element ti=Zi.duplicate().mulZn(hashToZr(witness.PID+GH+witness.V.toString()).invert());
       // System.out.println("ti: "+ti);

       // System.out.println("V: "+witness.V);
        byte[] V_bytes = witness.V.toBytes();
        Element hash = hashToZr(witness.PID + GH + ti);
        byte[] mask = extendMask(hash.toBytes(), V_bytes.length); // ✅ 补齐掩码长度
        byte[] wi_bytes = xor(V_bytes, mask);
        String wi = Base64.getEncoder().encodeToString(wi_bytes);
     //   System.out.println("wi: "+wi);

        AlertMessage alert = new AlertMessage();
        alert.PID = record.PID;
        alert.AM_i = AM_i;
        alert.GH_i = GH;
        alert.Bi=record.Bi;
        alert.ti=ti;
        alert.wi=wi;
        alert.Z_i = Zi;
        alert.sigma = sigma;
        alert.timestamp = Tsp3;
        return alert;
    }

    public boolean verifyAlertReport(AlertMessage am,SystemParam params,String GH,int p1) {//TA.VehicleRecord Record

        long time=System.currentTimeMillis();
        byte[] wi_bytes = Base64.getDecoder().decode(am.wi);
        Element hash = hashToZr(am.PID + GH + am.ti);
        byte[] mask = extendMask(hash.toBytes(), wi_bytes.length); // ✅ 同样补齐
        byte[] V_bytes = xor(wi_bytes, mask);
        Element V = params.G1.newElementFromBytes(V_bytes).getImmutable(); // ✅ 可正确还原
        Element Ei = am.ti.duplicate().mulZn(hashToZr(am.PID+GH+V.toString()));
        Element h5 = hashToZr(am.PID + am.AM_i+Ei + V +  am.timestamp);
          // System.out.println("h5: "+h5);
        Element h6 = hashToZr(h5.toString() + Arrays.toString(am.Bi.toBytes())+GH+p1);
       //   System.out.println("h6: "+h6);
        Element left = params.P.duplicate().mulZn(am.sigma);
     //     System.out.println("left: "+left);
        Element right = V.duplicate().mulZn(h5).add(params.Ppub.duplicate().mulZn(hashToZr(am.PID+V+am.Bi)).duplicate().mulZn(h6)).add(am.Bi.duplicate().mulZn(h6)).add(Ei);
        System.out.println("Vehicle verification time: "+(System.currentTimeMillis()-time)+" ms");
  //      System.out.println("right: "+right);
        return left.isEqual(right);
    }

    public RSUBroadCast rsuSign(RSU rsu, AlertMessage alert) {
        long Tsp4 = System.currentTimeMillis();
        Element ei = params.Zr.newRandomElement().getImmutable();
        Element Ei = params.P.duplicate().mulZn(ei).getImmutable();

        String concat = rsu.RID + alert.PID + alert.AM_i + alert.sigma + alert.Z_i +alert.ti+alert.wi+ alert.timestamp + Ei+Tsp4;
        Element h = hashToZr(concat);
        Element sigmaR = rsu.getPrivateKey().duplicate().mulZn(h).add(ei).getImmutable();
        System.out.println("RSU forwarding time: "+(System.currentTimeMillis()-Tsp4)+" ms");

        RSUBroadCast fwd = new RSUBroadCast();
        fwd.RID_i = rsu.RID;
        fwd.E_i = Ei;
        fwd.sigma_R = sigmaR;
        fwd.msg = alert;
        return fwd;
    }

    public boolean verifyRSUSignature(RSUBroadCast fwd, Element D_i) {
        long time=System.currentTimeMillis();
        String concat = fwd.RID_i + fwd.msg.PID + fwd.msg.AM_i  + fwd.msg.sigma+fwd.msg.Z_i + fwd.msg.ti+fwd.msg.wi+fwd.msg.timestamp + fwd.E_i;
        Element h = hashToZr(concat);
        Element left = params.P.duplicate().mulZn(fwd.sigma_R);
        Element right = D_i.duplicate().mulZn(h).add(fwd.E_i);
        System.out.println("RSU verification time: "+(System.currentTimeMillis()-time)+" ms");
        return left.isEqual(right);
    }

    public boolean batchVerify(List<AlertMessage> ams, SystemParam params, String GH, int p1) {
        Element left = params.G1.newZeroElement().getImmutable();
        Element right = params.G1.newZeroElement().getImmutable();

        for (AlertMessage am : ams) {
            // 还原 V_i
            byte[] wi_bytes = Base64.getDecoder().decode(am.wi);
            Element hash = hashToZr(am.PID + GH + am.ti);
            byte[] mask = extendMask(hash.toBytes(), wi_bytes.length);
            byte[] V_bytes = xor(wi_bytes, mask);
            Element V = params.G1.newElementFromBytes(V_bytes).getImmutable();

            // 计算 Ei（Z_i）
            Element Ei = am.ti.duplicate().mulZn(hashToZr(am.PID + GH + V.toString()));

            // 计算 h5' 和 h6'
            Element h5 = hashToZr(am.PID + am.AM_i + Ei + V + am.timestamp);
            Element h6 = hashToZr(h5.toString() + Arrays.toString(am.Bi.toBytes()) + GH + p1);

            // 聚合左边：sum σ_i * P
            left = left.duplicate().add(params.P.duplicate().mulZn(am.sigma));

            // 聚合右边：
            Element term1 = V.duplicate().mulZn(h5);
            Element term2 = params.Ppub.duplicate()
                    .mulZn(hashToZr(am.PID + V + am.Bi)) // H1
                    .mulZn(h6);
            Element term3 = am.Bi.duplicate().mulZn(h6);
            Element term4 = Ei.duplicate();

            Element partialRight = term1.add(term2).add(term3).add(term4);
            right = right.duplicate().add(partialRight);
        }

        return left.isEqual(right);
    }


}
