package WangJing;


import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class RSUAuthVerifier {

    public static boolean verifyVehicle(
            Entity rsu,
            Entity vehicle,
            Element T,
            Element sigma,
            List<Element> A // 多项式系数
    ) {
        // Step 1: h_v = H1(PID_v, X_v, R_v, Ppub)
        Element h_v = SystemSetup.HtoZr(1,
                vehicle.PID.toString(),
                vehicle.PK_X.toString(),
                vehicle.PK_R.toString(),
                SystemSetup.Ppub.toString());

        // Step 2: Q_i' = (x_i + y_i)(X_v + R_v + h_v * Ppub + T)
        Element sumXY = rsu.x.duplicate().add(rsu.y).getImmutable();
        Element base = vehicle.PK_X.duplicate()
                .add(vehicle.PK_R)
                .add(SystemSetup.Ppub.duplicate().mulZn(h_v))
                .add(T);
        Element Q_prime = base.duplicate().mulZn(sumXY).getImmutable();

        // Step 3: γ_i' = H2(Q_i')
        Element gamma_prime = SystemSetup.HtoZr(2, Q_prime.toString());

        // Step 4: 计算 k' = f(γ_i')，使用多项式 A
        Element k_prime = evaluatePoly(A, gamma_prime);

        // Step 5: 计算左边 σP
        Element left = sigma.duplicate().mul(SystemSetup.P);

        // Step 6: 计算右边：h3(T + k'P) + h4*X_v + h5*(R_v + h_v*Ppub)
        Element h3 = SystemSetup.HtoZr(3, vehicle.PID.toString(), T.toString(), k_prime.toString(), A.toString());
        Element h4 = SystemSetup.HtoZr(4, vehicle.PID.toString(), T.toString(), k_prime.toString(), A.toString());
        Element h5 = SystemSetup.HtoZr(5, vehicle.PID.toString(), T.toString(), k_prime.toString(), A.toString());

        Element right = T.duplicate().add(SystemSetup.P.duplicate().mulZn(k_prime)).mulZn(h3)
                .add(vehicle.PK_X.duplicate().mulZn(h4))
                .add(vehicle.PK_R.duplicate().add(SystemSetup.Ppub.duplicate().mulZn(h_v)).mulZn(h5));

        return left.isEqual(right);
    }

    // 多项式求值：k = a0 + a1*γ + a2*γ^2 + ...
    public static Element evaluatePoly(List<Element> coeffs, Element x) {
        Element result = SystemSetup.Zr.newZeroElement();
        Element pow = SystemSetup.Zr.newOneElement();
        for (Element a : coeffs) {
            result = result.add(a.duplicate().mul(pow));
            pow = pow.mul(x);
        }
        return result.getImmutable();
    }
}

