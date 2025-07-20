package WangJing;


import it.unisa.dia.gas.jpbc.Element;
//import it.unisa.dia.gas.jpbc.Polynomial;

import java.util.ArrayList;
import java.util.List;

class AuthProtocol {
    public static AuthRequest vehicleAuthRequest(Entity vehicle, List<Entity> rsuList) {
        long time=System.currentTimeMillis();
        Element t = SystemSetup.Zr.newRandomElement().getImmutable();
        Element T = SystemSetup.P.duplicate().mulZn(t).getImmutable();

        List<Element> gammas = new ArrayList<>();
        for (Entity rsu : rsuList) {
            Element h1 = SystemSetup.HtoZr(1, rsu.PID.toString(), rsu.PK_X.toString(), rsu.PK_R.toString(), SystemSetup.Ppub.toString());
            Element base = rsu.PK_X.duplicate().add(rsu.PK_R).add(SystemSetup.Ppub.duplicate().mulZn(h1));
            Element scalar = vehicle.x.duplicate().add(vehicle.y).add(t);
            Element Q = base.duplicate().mulZn(scalar).getImmutable();
            Element gamma = SystemSetup.HtoZr(2, Q.toString());
            gammas.add(gamma);
        }

        Element k = SystemSetup.Zr.newRandomElement().getImmutable();
        Polynomial poly = Polynomial.fromRoots(gammas, k);
        List<Element> coeffs = poly.getCoefficients();

        String pid = vehicle.PID.toString();
        String tStr = T.toString();
        String kStr = k.toString();
        String aStr = coeffs.toString();

        Element h3 = SystemSetup.HtoZr(3, pid, tStr, kStr, aStr);
        Element h4 = SystemSetup.HtoZr(4, pid, tStr, kStr, aStr);
        Element h5 = SystemSetup.HtoZr(5, pid, tStr, kStr, aStr);

        Element sigma = h3.duplicate().mul(t.add(k))
                .add(h4.duplicate().mul(vehicle.x))
                .add(h5.duplicate().mul(vehicle.y)).getImmutable();
        System.out.println("The time for calculating the signed vehicle name： "+(System.currentTimeMillis()-time)+" ms");

        return new AuthRequest(T, sigma, k, coeffs);
    }

    public static RSUResponse generateRSUResponse(Entity rsu, Entity vehicle, Element k_prime) {
        long time =System.currentTimeMillis();
        Element t_i = SystemSetup.Zr.newRandomElement();
        Element T_i = SystemSetup.P.duplicate().mulZn(t_i).getImmutable();

        String pid = rsu.PID.toString();
        String TiStr = T_i.toString();
        String kStr = k_prime.toString();

        Element h6 = SystemSetup.HtoZr(6, pid, TiStr, kStr);
        Element h7 = SystemSetup.HtoZr(7, pid, TiStr, kStr);
        Element h8 = SystemSetup.HtoZr(8, pid, TiStr, kStr);

        Element sigma_i = h6.duplicate().mul(t_i.add(k_prime))
                .add(h7.duplicate().mul(rsu.x))
                .add(h8.duplicate().mul(rsu.y)).getImmutable();
        System.out.println("The signature generation time of RSU: "+(System.currentTimeMillis()-time)+" ms");

        return new RSUResponse(sigma_i, T_i);
    }

    public static boolean verifyRSUResponse(Entity vehicle, Entity rsu, RSUResponse response, Element k) {

        long time=System.currentTimeMillis();
        String pid = rsu.PID.toString();
        String TiStr = response.T_i.toString();
        String kStr = k.toString();

        Element h6 = SystemSetup.HtoZr(6, pid, TiStr, kStr);
        Element h7 = SystemSetup.HtoZr(7, pid, TiStr, kStr);
        Element h8 = SystemSetup.HtoZr(8, pid, TiStr, kStr);

        Element left = SystemSetup.P.duplicate().mulZn(response.sigma_i);
        Element right = response.T_i.duplicate().add(SystemSetup.P.duplicate().mulZn(k)).mulZn(h6)
                .add(rsu.PK_X.duplicate().mulZn(h7))
                .add(rsu.PK_R.duplicate().add(SystemSetup.Ppub.duplicate()
                                .mulZn(SystemSetup.HtoZr(1, rsu.PID.toString(), rsu.PK_X.toString(), rsu.PK_R.toString(), SystemSetup.Ppub.toString())))
                        .mulZn(h8));

        System.out.println("Vehicle verification signature time： "+(System.currentTimeMillis()-time)+" ms");
        return left.isEqual(right);
    }

    public static List<Element> generateGammaList(Entity vehicle, List<Entity> rsus, Element t) {
        List<Element> gammas = new ArrayList<>();
        for (Entity rsu : rsus) {
            Element h1 = SystemSetup.HtoZr(1,
                    rsu.PID.toString(), rsu.PK_X.toString(), rsu.PK_R.toString(), SystemSetup.Ppub.toString());

            Element base = rsu.PK_X.duplicate()
                    .add(rsu.PK_R)
                    .add(SystemSetup.Ppub.duplicate().mulZn(h1));

            Element scalar = vehicle.x.duplicate().add(vehicle.y).add(t);
            Element Q = base.duplicate().mulZn(scalar).getImmutable();
            Element gamma = SystemSetup.HtoZr(2, Q.toString());

            gammas.add(gamma);
        }
        return gammas;
    }

    public static boolean verifyVehicle(Entity rsu, Entity vehicle, Element T, Element sigma, List<Element> coeffs) {

        long time=System.currentTimeMillis();
        // Step 1: h_v = H1(PID_v, X_v, R_v, Ppub)
        Element h_v = SystemSetup.HtoZr(1,
                vehicle.PID.toString(),
                vehicle.PK_X.toString(),
                vehicle.PK_R.toString(),
                SystemSetup.Ppub.toString());

        // Step 2: Q' = (x_i + y_i)(X_v + R_v + h_v·Ppub + T)
        Element base = vehicle.PK_X.duplicate()
                .add(vehicle.PK_R)
                .add(SystemSetup.Ppub.duplicate().mulZn(h_v))
                .add(T);
        Element Q_prime = base.duplicate().mulZn(rsu.x.duplicate().add(rsu.y)).getImmutable();

        // Step 3: γ' = H2(Q')
        Element gamma_prime = SystemSetup.HtoZr(2, Q_prime.toString());

        // Step 4: 计算 k' = f(γ') using coeffs
        Element k_prime = evaluatePolynomial(coeffs, gamma_prime);

        // Step 5: 重构 h3, h4, h5
        String pid = vehicle.PID.toString();
        String tStr = T.toString();
        String kStr = k_prime.toString();
        String aStr = coeffs.toString();

        Element h3 = SystemSetup.HtoZr(3, pid, tStr, kStr, aStr);
        Element h4 = SystemSetup.HtoZr(4, pid, tStr, kStr, aStr);
        Element h5 = SystemSetup.HtoZr(5, pid, tStr, kStr, aStr);

        // Step 6: 验证等式
        Element left = SystemSetup.P.duplicate().mulZn(sigma);

        Element right = T.duplicate().add(SystemSetup.P.duplicate().mulZn(k_prime)).mulZn(h3)
                .add(vehicle.PK_X.duplicate().mulZn(h4))
                .add(vehicle.PK_R.duplicate()
                        .add(SystemSetup.Ppub.duplicate().mulZn(h_v))
                        .mulZn(h5));
        System.out.println("RSU verification signature： "+(System.currentTimeMillis()-time)+" ms");

        return left.isEqual(right);
    }

    private static Element evaluatePolynomial(List<Element> coeffs, Element x) {
        Element result = SystemSetup.Zr.newZeroElement();
        Element power = SystemSetup.Zr.newOneElement();
        for (Element a : coeffs) {
            result = result.add(a.duplicate().mul(power));
            power = power.mul(x);
        }
        return result.getImmutable();
    }

}


