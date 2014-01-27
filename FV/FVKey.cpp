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

#include "FVKey.h"
#include "Sampler.h"
#include <iostream>
#include "flint/arith.h"
#include "../timing.h"

/* Static values */
fmpzxx W((fmpzxx(1) << WORDLENGTH));
fmpzxx MASKING((fmpzxx(1) << WORDLENGTH)-fmpzxx(1));

/* Print Key */
std::ostream& operator<<(std::ostream& os, const FVKey& k) {
    os << "<FVKey with ell=" << k.ell << " num_slots=" << k.get_num_slots() << " q=" << k.q 
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

fmpz_mod_polyxx FVKey::BitVectorToPoly(BitVector& m)
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
FVKey::FVKey(const struct FVParams& params, bool batch)
{
    // Initializations
    n = params.n;
    sigmakey = params.sigmakey;
    sigmaerr = params.sigmaerr;
    q = params.q;
    t = params.t;

    logwq = q.sizeinbase(2)/WORDLENGTH+1;

    qdivt = q/t;
    qdiv2t = q/(2*t);

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
            std::cout << "Batching possible on " << factors->size() << " slots" << std::endl;
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

    // Creating sk/pk
    std::cerr << "Creating sk/pk" << std::endl;

    a = new fmpz_mod_polyxx(q);
    s = new fmpz_mod_polyxx(q);
    b = new fmpz_mod_polyxx(q);

    for (unsigned i=0; i<ell; i++)
    {
        fmpzxx coeff = fmpzxx(random.getRandomLong());
        for (unsigned j=0; j<q.sizeinbase(2)/64; j++)
            coeff = (coeff<<64)+fmpzxx(random.getRandomLong());

        a->set_coeff(i, coeff);
    }

    samplerkey = new Sampler(sigmakey*0.4, 1., &random); // 1/sqrt(2*pi) ~ 0.4

    if (sigmakey == 1) binaryGen(*s, ell-1);
    else 
    {
        for (unsigned i=0; i<ell; i++)
        {
            long value = samplerkey->SamplerGaussian();
            if (value>=0)   s->set_coeff(i, fmpzxx(value));
            else            s->set_coeff(i, q-fmpzxx(-value));
        }
    }
   
    samplererr = new Sampler(sigmaerr*0.4, 1., &random); // 1/sqrt(2*pi) ~ 0.4

    fmpz_mod_polyxx e(q);
    if (sigmaerr == 1) binaryGen(e, ell-1);
    else 
    {
        for (unsigned i=0; i<ell; i++)
        {
            long value = samplererr->SamplerGaussian();
            if (value>=0)   e.set_coeff(i, fmpzxx(value));
            else            e.set_coeff(i, q-fmpzxx(-value));
        }
    } 

    *b = (-((*a)*(*s)%(*phi)))+e;


    // Create evaluation key
    gamma.resize(2);

    gamma[0].resize(logwq, fmpz_mod_polyxx(q));

    for (unsigned i=0; i<logwq; i++)
    {
        for (unsigned j=0; j<ell; j++)
        {
            fmpzxx coeff = fmpzxx(random.getRandomLong());
            for (unsigned k=0; k<q.sizeinbase(2)/64; k++)
                coeff = (coeff<<64)+fmpzxx(random.getRandomLong());

            gamma[0][i].set_coeff(j, coeff);
        }
    }

    gamma[1].resize(logwq, fmpz_mod_polyxx(q));

    for (unsigned i=0; i<logwq; i++)
    {
        
        gamma[1][i] = (*s)*(*s);
        for (unsigned j=0; j<i; j++)
            gamma[1][i] = gamma[1][i]*W;

        fmpz_mod_polyxx e2(q);
        if (sigmaerr == 1) binaryGen(e2, ell-1);
        else 
        {
            for (unsigned i=0; i<ell; i++)
            {
                long value = samplererr->SamplerGaussian();
                if (value>=0)   e2.set_coeff(i, fmpzxx(value));
                else            e2.set_coeff(i, q-fmpzxx(-value));
            }
        } 

        gamma[1][i] += (-(gamma[0][i]*(*s)%(*phi)))+e2;
    }

}

/* Compute CRT of m0, m1 for factors i, i+1 */
fmpz_mod_polyxx FVKey::CRT(const fmpz_mod_polyxx& m0, const fmpz_mod_polyxx& m1, unsigned i)
{
    fmpz_mod_polyxx res(t);
    res = (((m1-m0)*invfactors[i])%(factors->p(i+1)));

    for (unsigned j=0; j<=i; j++)
        res = res * factors->p(j);

    res += m0;

    return res;
}

/* Encrypt a BitVector publicly */
Ciphertext FVKey::encrypt(BitVector& m) {

    fmpz_mod_polyxx zero(q);
    std::vector<fmpz_mod_polyxx> cval;
    cval.resize(2, fmpz_mod_polyxx(q));

    fmpz_mod_polyxx u(q);
    fmpzxx coeff;
    for (unsigned i=0; i<ell; i++)
    {
        cval[0].set_coeff(i,q+fmpzxx(samplererr->SamplerGaussian())) ;
        cval[1].set_coeff(i,q+fmpzxx(samplererr->SamplerGaussian())) ;
        u.set_coeff(i,q+fmpzxx(samplererr->SamplerGaussian()));
    }

    cval[0] += (*b)*u%(*phi)+qdivt*BitVectorToPoly(m);
    cval[1] += (*a)*u%(*phi);

    return Ciphertext(*this, cval, 2);
}

/* Encrypt a BitVector with the secret key 
(Here only publicly ;)) */
Ciphertext FVKey::encrypt_with_sk(BitVector& m) {
    return FVKey::encrypt(m);
}

/* Decrypt */
BitVector FVKey::decrypt(const Ciphertext& c) {
    std::vector<fmpz_mod_polyxx> tmp;
    tmp.resize(c.len, fmpz_mod_polyxx(q));
    fmpz_mod_polyxx total(q);

    tmp[0] = (c.cval)[0];
    total = tmp[0];
    for (unsigned i=1; i<c.len; i++)
    {
        tmp[i] = *s;
        for (unsigned j=1; j<i; j++)
            tmp[i] = (tmp[i]*(*s))%(*phi);
        tmp[i] = (tmp[i]*(c.cval)[i])%(*phi);
        total = total + tmp[i];
    }

    fmpz_polyxx g;
    fmpzxx coeff, diff;
    g = t*(total.to<fmpz_polyxx>());

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

std::vector<fmpz_mod_polyxx> FVKey::convert(const std::vector<fmpz_mod_polyxx>& cval) {

    std::vector<fmpz_mod_polyxx> result;
    result.resize(2, fmpz_mod_polyxx(q));

    std::vector<fmpz_mod_polyxx> P(logwq, fmpz_mod_polyxx(q));
    WordDecomp(P, cval[2]);

    result[0] = cval[0]+(P[0]*gamma[1][0]);
    result[1] = cval[1]+(P[0]*gamma[0][0]);
    for (unsigned i=1; i<logwq; i++)
    {
        result[0] = result[0] + (P[i]*gamma[1][i]);
        result[1] = result[1] + (P[i]*gamma[0][i]);
    }
    result[0] = result[0]%(*phi);
    result[1] = result[1]%(*phi);

    return result;
}

/* Get real noise */
unsigned FVKey::noise(const Ciphertext& c)
{
    unsigned bitnoise = 0;
    fmpzxx coeff;
    fmpz_mod_polyxx g(q);
    BitVector m = decrypt(c);

    g = c.cval[0] + (c.cval[1]*(*s))%(*phi) - qdivt*BitVectorToPoly(m);
    
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

