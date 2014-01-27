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

#include "BitVector.h"
#include <iostream>

/* Constructor BitVector or size l, with basis b (should be called WordVector ;))
The vector is either set to 0 or randomized according to the boolean rnd */
BitVector::BitVector(size_t l, int b, bool rnd) {
    len = l;
    base = b;
    bits = new int[len];
    for (size_t i=0; i<len; i++)
    	bits[i]=0;
    if(rnd)
	for(size_t i = 0; i < len; i++)
	    bits[i] = rand() % base;
}

/* Constructor BitVector */
BitVector::BitVector(const BitVector& b) {
    len = b.len;
    base = b.base;
    bits = new int[len];
    for(size_t i = 0; i < len; i ++) {
	bits[i] = b.bits[i];
    }
}

/* Rerandomize the vector */
BitVector& BitVector::rerand() {
	for (size_t i= 0; i<len; i++)
		bits[i]=rand()%base;
	return *this;
}

/* Operators */
bool BitVector::operator==(const BitVector& b) {
    assert(len == b.len);
    for(size_t i = 0; i < len; i ++) {
	if (bits[i] != b.bits[i]) return false;
    }
    return true;
}

BitVector& BitVector::operator+=(const BitVector& b) {
    assert(len == b.len);
    for(size_t i = 0; i < len; i ++) {
	bits[i] = (bits[i]+b.bits[i])%base;
    }

    return *this;
}

BitVector& BitVector::operator*=(const BitVector& b) {
    assert(len == b.len);
    for(size_t i = 0; i < len; i ++) {
        bits[i] = (bits[i]*b.bits[i])%base;
    }
    return *this;
}

BitVector& BitVector::operator+=(const int& a) {
    if(a & 1)
	for(size_t i = 0; i < len; i++)
	    bits[i] = (bits[i]+a)%base;
    return *this;
}

BitVector& operator+(const int& a, const BitVector& b) {
    return b+a;
}

std::ostream& operator<<(std::ostream& os, const BitVector& b) {
    os << "(";
    for(size_t i = 0; i < b.len; i++) {
    		os << b.bits[i];
    		if(i+1 < b.len) os << ",";
    }
    os << ")";
    return os;
}

/* Multiplication modulo x^n+1 */
BitVector BitVector::mul(const BitVector& b)
{
    assert(len == b.len);
    BitVector a(b.len);
    for(size_t i = 0; i < b.len; i ++) {
       for(size_t j = 0; j < b.len; j ++) {
            if (i+j>=b.len)
                a[(i+j)%b.len] = (b.base+(a[(i+j)%len]-bits[i]*b.bits[j])%b.base)%b.base;
            else
                a[(i+j)%b.len] = (b.base+(a[(i+j)%len]+bits[i]*b.bits[j])%b.base)%b.base;
        }
    }
    return a;
}

/* Hamming weight when basis = 2 */
int BitVector::HW(const BitVector& b)
{
    assert(len == b.len);
    if (base!=2)
        return 0;

    int hw=0;
    for (unsigned i=0; i<len; i++)
    {
        hw += bits[i]*b.bits[i];
    }
    return hw;
}
