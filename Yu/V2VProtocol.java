package Yu;


import it.unisa.dia.gas.jpbc.Element;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class V2VProtocol {

    private final SystemParam params;
    private final TA ta;

    public Element hashToZr(String input) {
        return params.Zr.newElement().setFromHash(input.getBytes(), 0, input.getBytes().length).getImmutable();
    }

    public static String XORDecrypt(String base64Cipher, Element sk) {
        byte[] key = sk.toBytes();
        byte[] data = Base64.getDecoder().decode(base64Cipher);
        byte[] result = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }

        return new String(result, StandardCharsets.UTF_8);
    }

    public String hashToStr(String input) {
        return hashToZr(input).toString(); // 简化为字符串输出
    }


    public static byte[] xor(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }
    public V2VProtocol(SystemParam params, TA ta) {
        this.params = params;
        this.ta = ta;
    }

    public static byte[] extendMask(byte[] mask, int targetLength) {
        byte[] extended = new byte[targetLength];
        for (int i = 0; i < targetLength; i++) {
            extended[i] = mask[i % mask.length]; // 重复掩码填满
        }
        return extended;
    }

    // 目击车辆生成事故报告
    public WitnessReport generateReport(Vehicle witness, TA.VehicleRecord record, String GH,int p1) {
        long Tsp1 = System.currentTimeMillis();
        //System.out.println("V: "+witness.V);
        Element u = params.Zr.newRandomElement().getImmutable();
        Element U = params.P.duplicate().mulZn(u).getImmutable();
      //  System.out.println("U: "+U);

        long time=System.nanoTime();
        Element h1 = hashToZr(witness.PID + U + witness.V +  Tsp1);
       // System.out.println("Hash "+h1.toBytes().length);
        //System.out.println("哈希时间: "+(System.nanoTime()-time)+" ms");
       // System.out.println("h1: "+h1);
        Element h2 = hashToZr(h1.toString() + Arrays.toString(record.Bi.toBytes())+GH+p1);
       // System.out.println("h2: "+h2);
        Element sigma =witness.v.duplicate().mul(h1).add(witness.xi.duplicate().mul(h2)).add(u).getImmutable();
        System.out.println("The generation time of vehicle signatures: "+(System.currentTimeMillis()-Tsp1)+" ms");
      //  System.out.println("sigma: "+sigma);

        Element ti=U.duplicate().mulZn(hashToZr(witness.PID+GH+witness.V.toString()).invert());

        byte[] V_bytes = witness.V.toBytes();
        Element hash = hashToZr(witness.PID + GH + ti);
        byte[] mask = extendMask(hash.toBytes(), V_bytes.length); // ✅ 补齐掩码长度
        byte[] wi_bytes = xor(V_bytes, mask);
        String wi = Base64.getEncoder().encodeToString(wi_bytes);


        witness.u=u;
        witness.U=U;
        WitnessReport wr = new WitnessReport();
        wr.PID = record.PID;
        wr.sigma = sigma;
        wr.Bi= witness.Bi;
        wr.ti=ti;
        wr.wi=wi;
        wr.p1=p1;
        wr.Tsp1=Tsp1;
        return wr;
    }

    // 事故车辆验证事故报告
    public boolean verifyReport(WitnessReport wr,SystemParam params,String GH,int p1) {//TA.VehicleRecord Record


        byte[] wi_bytes = Base64.getDecoder().decode(wr.wi);
        Element hash = hashToZr(wr.PID + GH + wr.ti);
        byte[] mask = extendMask(hash.toBytes(), wi_bytes.length); // ✅ 同样补齐
        byte[] V_bytes = xor(wi_bytes, mask);
        Element V = params.G1.newElementFromBytes(V_bytes).getImmutable(); // ✅ 可正确还原
       //System.out.println("V: "+V);
        Element U = wr.ti.duplicate().mulZn(hashToZr(wr.PID+GH+V.toString()));
       //System.out.println("U: "+U);

        Element h1 = hashToZr(wr.PID + U + V +  wr.Tsp1);
     //   System.out.println("h1: "+h1);
        Element h2 = hashToZr(h1.toString() + Arrays.toString(wr.Bi.toBytes())+GH+p1);

        Element h3=hashToZr(wr.PID+V+wr.Bi);
     //   System.out.println("h2: "+h2);
        long time=System.currentTimeMillis();
        Element left = params.P.duplicate().mulZn(wr.sigma);
    //    System.out.println("left: "+left);
        Element right = V.duplicate().mulZn(h1).add(params.Ppub.duplicate().mulZn(h3).duplicate().mulZn(h2)).add(wr.Bi.duplicate().mulZn(h2)).add(U);

        if(left.isEqual(right)){
            System.out.println("Vehicle verification signature time: "+(System.currentTimeMillis()-time)+" ms");
        }
    //    System.out.println("right: "+right);
        return left.isEqual(right);
    }

    public WitnessReport generateFeedbackd(Vehicle witness,Vehicle accident){
        Element sigmaAR=witness.v.duplicate().mulZn(hashToZr(witness.PID+accident.PID+hashToZr(witness.ar))).add(witness.u);
        WitnessReport wr = new WitnessReport();
        wr.sigmaAR=sigmaAR;
        wr.H_ar=hashToZr(witness.ar);
        return wr;
    }

    public FeedBack verifyFeedReport(Vehicle witness, WitnessReport feedback,Vehicle accdient,SystemParam params){
        Element left=params.P.duplicate().mulZn(feedback.sigmaAR);
        String ar_i=XORDecrypt(feedback.AR, accdient.SK);
        Element right= witness.V.duplicate().mulZn(hashToZr(witness.PID+accdient.PID+hashToZr(ar_i))).add(witness.U);

        FeedBack fd= new FeedBack();
        fd.PID_i= witness.PID;
        fd.PID_j=accdient.PID;
        fd.Bi=witness.Bi;
        fd.Vi=witness.V;
        fd.Vj=accdient.V;
        fd.Ui=witness.U;
        fd.sigmaAR=feedback.sigmaAR;
        fd.ar=ar_i;
        fd.RF=hashToZr(witness.PID+accdient.PID+ params.Ppub.duplicate().mulZn(accdient.v));
       if(left.isEqual(right)&& feedback.H_ar.isEqual(hashToZr(ar_i))){
           System.out.println("[Witnessed Vehicle] The verification feedback signature of the witnessed vehicle was successful");
       }else{
           System.out.println("[Witnessed Vehicle] The signature is invalid. The signature is discarded");
       }
       return fd;
    }
}
