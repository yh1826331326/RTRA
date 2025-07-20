package WangJing;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class Polynomial {
    private List<Element> coeffs;

    public Polynomial(List<Element> coeffs) {
        this.coeffs = coeffs;
    }

    public List<Element> getCoefficients() {
        return coeffs;
    }

    public static Polynomial fromRoots(List<Element> roots, Element k) {
        List<Element> coeffs = new ArrayList<>();
        coeffs.add(SystemSetup.Zr.newOneElement());
        for (Element root : roots) {
            List<Element> newCoeffs = new ArrayList<>(Collections.nCopies(coeffs.size() + 1, SystemSetup.Zr.newZeroElement()));
            for (int i = 0; i < coeffs.size(); i++) {
                newCoeffs.set(i + 1, newCoeffs.get(i + 1).duplicate().add(coeffs.get(i)));
                newCoeffs.set(i, newCoeffs.get(i).duplicate().sub(coeffs.get(i).duplicate().mul(root)));
            }
            coeffs = newCoeffs;
        }
        coeffs.set(0, coeffs.get(0).duplicate().add(k));
        return new Polynomial(coeffs);
    }
}
