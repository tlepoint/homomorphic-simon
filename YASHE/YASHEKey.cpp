/*

Copyright or © or Copr. Tancrede Lepoint.

Tancrede.Lepoint@cryptoexperts.com

This software is a computer program whose purpose is to provide to the 
research community a proof-of-concept implementation of the homomorphic 
evaluation of the lightweight block cipher SIMON, describe in the paper
"A Comparison of the Homomorphic Encryption Schemes FV and YASHE", of
Tancrede Lepoint and Michael Naehrig, available at
http://eprint.iacr.org/2014.

This software is governed by the CeCILL license under French law and
abiding by the rules of distribution of free software.  You can  use, 
modify and/ or redistribute the software under the terms of the CeCILL
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info". 

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability. 

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or 
data to be ensured and,  more generally, to use and operate it in the 
same conditions as regards security. 

The fact that you are presently reading this means that you have had
knowledge of the CeCILL license and that you accept its terms.

*/

#include "YASHEKey.h"
#include "Sampler.h"
#include <iostream>
#include "flint/arith.h"
#include "../timing.h"

/* Static values */
fmpzxx W((fmpzxx(1) << WORDLENGTH));
fmpzxx MASKING((fmpzxx(1) << WORDLENGTH)-fmpzxx(1));

/* Print Key */
std::ostream& operator<<(std::ostream& os, const YASHEKey& k) {
    os << "<YASHEKey with ell=" << k.ell << " num_slots=" << k.get_num_slots() << " q=" << k.q 
	<< " t=" << k.t << " sigma_key=" << k.sigmakey << " sigma_err=" << k.sigmaerr 
	<< ">";
    return os;
}

/* Small useful functions */
bool isPowerOfTwo(int n)
{
    return (n) && !(n & (n - 1)); //this checks if the integer n is a power of two or not
}

void binaryGen(fmpz_mod_polyxx& f, unsigned degree)
{
    for (unsigned i=0; i<=degree; i++)
        f.set_coeff(i, fmpzxx((rand()%3)-1));
}

fmpz_mod_polyxx YASHEKey::BitVectorToPoly(BitVector& m)
{
    assert(m.l() == num_slots);
    
    if (!batching || num_slots == 1)
    {
        fmpz_mod_polyxx pf(q);
        for (unsigned i=0; i<m.l(); i++)
            pf.set_coeff(i, m[i]);
        return pf;
    }
    else
    {
           
    fmpz_mod_polyxx pf(t);

    fmpz_mod_polyxx mess(t);
    mess.set_coeff(0, m[0]);

    pf = mess;

    for (unsigned i=1; i<num_slots; i++)
    {
        mess.set_coeff(0, m[i]);
        pf = CRT(pf, mess, i-1);
    }

    fmpz_mod_polyxx result(q);
    result = pf.to<fmpz_polyxx>();

    return result;

    }
}

unsigned noise_from_poly(const fmpz_mod_polyxx& cval, const fmpzxx &q, unsigned ell)
{
    unsigned bitnoise = 0;
    fmpzxx coeff;
    for (unsigned i=0; i<ell; i++)
    {
        coeff = (cval.get_coeff(i).to<fmpzxx>());
        if (2*coeff > q)
            coeff = coeff - q;
        if (coeff.sizeinbase(2)>bitnoise)
            bitnoise = coeff.sizeinbase(2);
    }
    return bitnoise;
}

/* Constructor */
YASHEKey::YASHEKey(const struct YASHEParams& params, bool batch)
{
    n = params.n;
    sigmakey = params.sigmakey;
    sigmaerr = params.sigmaerr;
    q = params.q;
    t = params.t;

    logwq = q.sizeinbase(2)/WORDLENGTH+1;

    assert ( logwq*WORDLENGTH >= q.sizeinbase(2) );

    fmpz_mod_polyxx one(q);
    one.set_coeff(0, 1);

    // Define polynomial modulus
    arith_cyclotomic_polynomial(poly._data().inner, n);
    phi = new fmpz_mod_polyxx(q);
    *phi = poly;
    ell = phi->degree();

    // Factorize the modulus if batching is set
    batching = batch;
    num_slots = 1;

    if (batching)
    {
    std::cout << "Factorize the cyclotomic polynomial modulo " << t << std::endl;

    fmpz_mod_polyxx phimodt(t);
    phimodt = poly;

    timing T;
    T.start();
    factors = new fmpz_mod_poly_factorxx(factor_cantor_zassenhaus(phimodt));
    T.stop("Factorize");

    unsigned degreeFactors = 0;

    for (unsigned i=0; i<factors->size(); i++)
    {
        degreeFactors += factors->p(i).degree();
    }

    
    if (degreeFactors == phimodt.degree() && factors->size()>1)
    {
        num_slots = factors->size();

        invfactors.resize(num_slots-1, fmpz_mod_polyxx(t));
        fmpz_mod_polyxx num(t);
        num.set_coeff(0, 1);
        for (unsigned i=0; i<num_slots-1; i++)
        {
            num = num*factors->p(i);
            invfactors[i] = num.invmod(factors->p(i+1));
        }
    }
    else
    {
        std::cout << "Batching impossible" << std::endl;
    }
    
    }

    fmpz_mod_polyxx finv(q);
    qdivt = q/t;
    qdiv2t = q/(2*t);

    // Creating sk/pk

    f = new fmpz_mod_polyxx(q);
    h = new fmpz_mod_polyxx(q);

    sampler = new Sampler(sigmaerr*0.4, 1., &random); // 1/sqrt(2*pi) ~ 0.4

    if (sigmakey == 1)
    {
        // Sample g, f1 with coefficients in {-1,0,1} 
        fmpz_mod_polyxx g(q);
        fmpz_mod_polyxx f1(q);
        binaryGen(g, ell-1);
        do
        {
            binaryGen(f1, ell-1);
            *f = t*f1+one;
            finv = (*f).invmod(*phi);
        } while (((*f)*finv)%(*phi) != one);
        *h = (t*g*finv)%(*phi);
    }
    else
    {
        exit(0);
    }

    // Create evaluation key
    fmpz_mod_polyxx pe(q);
    fmpz_mod_polyxx ps(q);
    gamma.resize(logwq, fmpz_mod_polyxx(q));
    for (unsigned k=0; k<logwq; k++)
    {

        gamma[k] = *f;
        for (unsigned j=0; j<k; j++)
            gamma[k] = gamma[k]*W;

        for (unsigned i=0; i<ell; i++)
        {
            long value;

            value = sampler->SamplerGaussian();
            if (value>=0)   pe.set_coeff(i, fmpzxx(value));
            else            pe.set_coeff(i, q-fmpzxx(-value));
            value = sampler->SamplerGaussian();
            if (value>=0)   ps.set_coeff(i, fmpzxx(value));
            else            ps.set_coeff(i, q-fmpzxx(-value));
        }

        gamma[k] += pe+((*h)*ps)%(*phi);
    }
}

/* Compute CRT of m0, m1 for factors i, i+1 */
fmpz_mod_polyxx YASHEKey::CRT(const fmpz_mod_polyxx& m0, const fmpz_mod_polyxx& m1, unsigned i)
{
    fmpz_mod_polyxx res(t);
    res = (((m1-m0)*invfactors[i])%(factors->p(i+1)));

    for (unsigned j=0; j<=i; j++)
        res = res * factors->p(j);

    res += m0;

    return res;
}

/* Encrypt a BitVector publicly */
Ciphertext YASHEKey::encrypt(BitVector& m) {
    fmpz_mod_polyxx cval(q);
    fmpz_mod_polyxx ps(q);
    fmpzxx coeff;
    for (unsigned i=0; i<ell; i++)
    {
        cval.set_coeff(i,q+fmpzxx(sampler->SamplerGaussian())) ;
        ps.set_coeff(i,q+fmpzxx(sampler->SamplerGaussian()));
    }
    cval += ((*h)*ps)%(*phi)+qdivt*BitVectorToPoly(m);
    return Ciphertext(*this, cval, 0);
}

/* Encrypt a BitVector with the secret key 
(Here only publicly ;)) */
Ciphertext YASHEKey::encrypt_with_sk(BitVector& m) {
    return YASHEKey::encrypt(m);
}

/* Decrypt */
BitVector YASHEKey::decrypt(const Ciphertext& c) {
    fmpzxx coeff, diff;
    fmpz_polyxx g;
    if (c.aftermult)
    {
        g = t*((((*f)*(*f)*c.cval)%(*phi)).to<fmpz_polyxx>());
    }
    else
    {
        g = t*((((*f)*c.cval)%(*phi)).to<fmpz_polyxx>());
    }

    BitVector m(num_slots);

    if (batching && num_slots > 1)
    {

    for (unsigned i=0; i<g.degree()+1; i++)
    {
        ltupleref(coeff, diff) = fdiv_qr(g.get_coeff(i), q);
        if (2*diff > q)
        {
            g.set_coeff(i, (coeff+fmpzxx(1))%t );
        }
        else
            g.set_coeff(i, coeff);
    }

    fmpz_mod_polyxx gp(t);
    gp = g;

    for (unsigned i=0; i<num_slots; i++)
    {
            m[i] = (gp%factors->p(i)).get_coeff(0).to<slong>();
    }

    }
    else
    {
        for (unsigned i=0; i<num_slots; i++)
        {
            ltupleref(coeff, diff) = fdiv_qr(g.get_coeff(i), q);
            if (2*diff > q)
            {
                if (coeff == t-fmpzxx(1))
                    m[i] = 0;
                else
                    m[i] = coeff.to<slong>()+1;
            }
            else
                m[i] = coeff.to<slong>();
        }
    }

    return m;
}

/* Convert */
void WordDecomp( std::vector<fmpz_mod_polyxx> &P, const fmpz_mod_polyxx &x )
{
    fmpzxx c;
    unsigned i,j;
    for (i=0; i <= x.degree(); i++)
    {
        c = x.get_coeff(i);
        j=0;
        while ( c > 0 )
        {
            P[j].set_coeff(i, c&MASKING);
            c = (c>>WORDLENGTH);
            j++;
        }
    }
}

fmpz_mod_polyxx YASHEKey::convert(const fmpz_mod_polyxx& cval) {
    fmpz_mod_polyxx result(q);

    std::vector<fmpz_mod_polyxx> P(logwq, fmpz_mod_polyxx(q));
    WordDecomp(P, cval);
    
    result = (P[0]*gamma[0]);
    for (unsigned i=1; i<logwq; i++)
    {
        result = result + (P[i]*gamma[i]);
    }
    result = result%(*phi);

    return result;
}

/* Get real noise */
unsigned YASHEKey::noise(const Ciphertext& c)
{
    unsigned bitnoise = 0;
    fmpzxx coeff;
    fmpz_mod_polyxx g(q);
    BitVector m = decrypt(c);

    g = ((*f)*c.get_cval())%(*phi);
    g = g - qdivt*BitVectorToPoly(m);
    for (unsigned i=0; i<ell; i++)
    {
        coeff = (g.get_coeff(i).to<fmpzxx>());
        if (2*coeff > q)
            coeff = coeff - q;
        if (coeff.sizeinbase(2)>bitnoise)
            bitnoise = coeff.sizeinbase(2);
    }
    return bitnoise;
}

