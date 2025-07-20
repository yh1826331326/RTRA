package Yu;



import it.unisa.dia.gas.jpbc.Element;

import java.util.HashMap;
import java.util.Map;

public class TA {

    private final SystemParam params;

    private final Map<String, TA.RSURecord> rsuDatabase = new HashMap<>();

    public TA(SystemParam params) {
        this.params = params;
    }
    public static class RSURecord {
        public String RID;
        public Element R;      // RSU 公钥
        public Element A;      // TA 随机生成
        public Element sigmaR;
    }

    public static class VehicleRecord {
        public String VID;
        public String PID;
        public Element V;          // 注册公钥
        public Element Bi;          // 随机数对应点
        public Element sigmaV;     // 签名
        public int reputation;
        public Object state;

        public int RF;
    }

    public Element hashToZr(String input) {
        return params.Zr.newElement().setFromHash(input.getBytes(), 0, input.getBytes().length).getImmutable();
    }

    public String hashToStr(String input) {
        return hashToZr(input).toString(); // 简化为字符串输出
    }

    private String xor(String a, String b) {
        char[] r = new char[a.length()];
        for (int i = 0; i < a.length(); i++) {
            r[i] = (char) (a.charAt(i) ^ b.charAt(i % b.length()));
        }
        return new String(r);
    }
    public RSURecord registerRSU(String RID, Element R) {
        Element ai = params.Zr.newRandomElement().getImmutable();
        Element Ai = params.P.duplicate().mulZn(ai).getImmutable();
        Element hashInput = hashToZr(RID + R.toString() + Ai.toString());
        Element sigmaR = params.s.duplicate().mulZn(hashInput).add(ai).getImmutable();
        TA.RSURecord record = new TA.RSURecord();
        record.RID = RID;
        record.R = R;
        record.A = Ai;
        record.sigmaR = sigmaR;
        rsuDatabase.put(RID, record);

        return record;
    }

    public VehicleRecord registerVehicle(String VID, Element V) {
        Element bi = params.Zr.newRandomElement().getImmutable();
        Element Bi = params.P.duplicate().mulZn(bi).getImmutable();

        String PID = xor(VID,hashToStr(Bi + V.mulZn(params.s).toString()));

        Element sigmaV = params.s.duplicate().mulZn(
                hashToZr(PID + V + Bi)).add(bi).getImmutable();

       VehicleRecord record = new VehicleRecord();
        record.VID = VID;
        record.PID = PID;
        record.V = V;
        record.Bi = Bi;
        record.sigmaV = sigmaV;
        record.reputation = 10;

        //pl.put(PID, record);  // PL：伪名信誉映射表
        return record;
    }

    public int veryfyFeedBack(FeedBack fd,SystemParam params){

        Element RF1=hashToZr(fd.PID_i+fd.PID_j+fd.Vj.duplicate().mulZn(params.s));
        Element RF2=hashToZr(fd.PID_i+fd.PID_j+fd.Vj.duplicate().mulZn(params.s).negate());
        Element RF3=hashToZr(fd.PID_i+fd.PID_j);
        if(fd.RF.isEqual(RF1)){
            System.out.println("[TA] The verification of reputation feedback was successful");
            System.out.print("Feedback result RF: 1");
            return 1;
        }else if(fd.RF.isEqual(RF2)){
            System.out.println("[TA] The verification of reputation feedback was successful");
            System.out.print("Feedback result RF: -1");
            return -1;
        }else if(fd.RF.isEqual(RF3)){
            System.out.println("[TA] The verification of reputation feedback was successful");
            System.out.print("Feedback result RF: 0");
            return 0;
        }else{
            System.out.println("The feedback is invalid");
            return -2;
        }
    }

}
