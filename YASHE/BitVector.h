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

#ifndef __YASHE__BITVECTOR
#define __YASHE__BITVECTOR

#include <ostream>
#include <cstdlib>
#include <cassert>
#include <cstring>

class BitVector {
    private:
	size_t	len;
    
    public:
    int	*bits;
    int base;
	BitVector(size_t l, int b = 2, bool rnd = false);
        BitVector(const BitVector&);

	~BitVector() { delete[] bits; bits = NULL; }

	inline int& operator[](size_t i) { return bits[i]; }
	inline size_t l() const { return len; }

	friend std::ostream& operator<<(std::ostream&, const BitVector&);

	BitVector& rerand();
	int HW(const BitVector&);
	BitVector mul(const BitVector&);

	bool operator==(const BitVector&);
	BitVector& operator+=(const BitVector&);
	BitVector& operator+=(const int&);
	BitVector& operator*=(const BitVector&);

	BitVector& operator+(const BitVector& b) const {
	    BitVector* b2 = new BitVector(*this);
	    return (*b2 += b);
	}
	BitVector& operator+(const int& a) const {
	    BitVector* b2 = new BitVector(*this);
	    return (*b2 += a);
	}
	friend BitVector& operator+(const int&, const BitVector&);

	BitVector& operator*(const BitVector& b) const {
	    BitVector* b2 = new BitVector(*this);
	    return (*b2 *= b);
	}
};	

#endif
