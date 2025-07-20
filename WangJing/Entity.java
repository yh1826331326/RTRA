package WangJing;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

class Entity {
    public String ID;
    public Element x, y, X, R, PID;
    public Element PK_X, PK_R;

    public Entity(String ID) {
        this.ID = ID;
    }

    public void registerWithKGC() {
        this.x = SystemSetup.Zr.newRandomElement().getImmutable();
        this.X = SystemSetup.P.duplicate().mulZn(x).getImmutable();

        Element r = SystemSetup.Zr.newRandomElement().getImmutable();
        this.R = SystemSetup.P.duplicate().mulZn(r).getImmutable();

        Element h0 = SystemSetup.HtoZr(0, ID, SystemSetup.s.toString());
        this.PID = SystemSetup.P.duplicate().mulZn(h0).add(R).getImmutable();

        Element h1 = SystemSetup.HtoZr(1, PID.toString(), X.toString(), R.toString(), SystemSetup.Ppub.toString());
        this.y = r.duplicate().add(SystemSetup.s.duplicate().mul(h1)).getImmutable();

        this.PK_X = this.X;
        this.PK_R = this.R;
    }

    public boolean verify() {
        Element h1 = SystemSetup.HtoZr(1, PID.toString(), X.toString(), R.toString(), SystemSetup.Ppub.toString());
        Element left = SystemSetup.P.duplicate().mulZn(y).getImmutable();
        Element right = R.duplicate().add(SystemSetup.Ppub.duplicate().mulZn(h1)).getImmutable();
        return left.isEqual(right);
    }
}

class AuthRequest {
    public Element T;
    public Element sigma;
    public Element k;
    public List<Element> coeffs;

    public AuthRequest(Element T, Element sigma, Element k, List<Element> coeffs) {
        this.T = T;
        this.sigma = sigma;
        this.k = k;
        this.coeffs = coeffs;
    }
}
