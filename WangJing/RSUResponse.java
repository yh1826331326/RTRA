package WangJing;

import it.unisa.dia.gas.jpbc.Element;

class RSUResponse {
    public Element sigma_i;
    public Element T_i;

    public RSUResponse(Element sigma_i, Element T_i) {
        this.sigma_i = sigma_i;
        this.T_i = T_i;
    }
}
