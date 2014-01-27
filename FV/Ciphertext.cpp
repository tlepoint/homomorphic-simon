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

#include "Ciphertext.h"
#include "FVKey.h"
#include <iostream>
#include <assert.h>

/* Constructors */
Ciphertext::Ciphertext(FVKey& pk, std::vector<fmpz_mod_polyxx> poly, 
        unsigned length, bool am) : 
    pk(pk), cval(poly), len(length), aftermult(am)
{
}

Ciphertext::Ciphertext(const Ciphertext& c) : 
    pk(c.pk), cval(c.cval), len(c.len), aftermult(c.aftermult) {
}

/* Operators */
Ciphertext& Ciphertext::operator=(const Ciphertext& c) {
    assert(&pk == &c.pk);
    len = c.len;
    cval = c.cval;
    aftermult = c.aftermult;
    return *this;
}

std::ostream& operator<<(std::ostream& os, const Ciphertext& c) {
    os << "<Ciphertext of length "
        << std::dec << c.len;

    os << " with aftermult=" << c.aftermult;
    
    if (!c.aftermult)
        os << " with max(noise)="  << std::dec << c.real_noise() << " bits";
    else
        os << " of type II";
        
    //#ifdef VERBOSE
    os << " of m=" << c.pk.decrypt(c);
    //#endif
    os << ">";
    return os;
}

/* Addition */
Ciphertext& Ciphertext::operator+=(const Ciphertext& c) {

    if (aftermult != c.aftermult)
    {
        if (aftermult)
            convert_self();
        else
            c.convert_self();
    }
    
    if (len >= c.len)
    {
        for (unsigned i=0; i<c.len; i++)
        {
            cval[i] += c.cval[i];
        }
    }
    else
    {
        cval.resize(c.len, cval[0]);

        for (unsigned i=0; i<len; i++)
        {
            cval[i] += c.cval[i];
        }
        for (unsigned i=len; i<c.len; i++)
        {
            cval[i] = c.cval[i];
        }

        len = c.len;
    }

    return *this;
}

/* Multiply */
Ciphertext& Ciphertext::operator*=(const Ciphertext& c) {
    
    std::vector<fmpz_polyxx> c1b;
    c1b.resize(len, fmpz_polyxx(0));
    for (unsigned i=0; i<len; i++)
    {
        c1b[i] = cval[i].to<fmpz_polyxx>();
    }

    std::vector<fmpz_polyxx> c2b;
    c2b.resize(len, fmpz_polyxx(0));
    for (unsigned i=0; i<c.len; i++)
    {
        c2b[i] = c.cval[i].to<fmpz_polyxx>();
    }

    fmpzxx coeff, diff;
    
    fmpz_polyxx g;
    cval.resize(len+c.len-1, fmpz_mod_polyxx(pk.q));
    for (long k=0; k<len+c.len-1; k++)
    {
        g = 0;
        for (long i=0; i<=k; i++)
        {
            long j = k-i;
            if (j < c.len && i<len)
            {
                g += (c1b[i]*c2b[j]);
            }
        }

        g = c.pk.t*g%(c.pk.poly);

        for (unsigned i=0; i<g.degree()+1; i++)
        {
            ltupleref(coeff, diff) = fdiv_qr(g.get_coeff(i), c.pk.q);
            if (2*diff > c.pk.q)
            {
                cval[k].set_coeff(i, coeff+fmpzxx(1));
            }
            else
                cval[k].set_coeff(i, coeff);
        }
    }

    len = len+c.len-1;
    aftermult = true;

    return *this;
}

/* Convert */
void Ciphertext::convert_self(void) const {
    if (!aftermult) return;

    Ciphertext *that = const_cast<Ciphertext*>(this);
    that->cval = pk.convert(cval);
    that->aftermult = false;
    that->len = 2;
}

/* Get real noise */
unsigned Ciphertext::real_noise(void) const {
    if (!aftermult) return pk.noise(*this);
    else return 0;
}

