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

#ifndef __FV__FVKEY
#define __FV__FVKEY

#include <ostream>
#include <vector>
#include <map>
#include "Ciphertext.h"
#include "BitVector.h"
#include "Sampler.h"

#include "gmpxx.h"

#include <iostream>
#include <sstream>
#include <string>
#include "flint/fmpz_mod_polyxx.h"
#include "flint/fmpz_mod_poly_factorxx.h"

using namespace flint;

/**********************************************************************
 * FV Parameters.
 **********************************************************************/
struct FVParams {
    unsigned long n, sigmakey, sigmaerr;
    fmpzxx q;
    fmpzxx t;
};
#define WORDLENGTH 72

class Ciphertext;

class FVKey {
    protected:
    public:
	unsigned long	n, ell, sigmakey, sigmaerr, logwq;
	fmpzxx q, t, qdivt, qdiv2t;

	fmpz_polyxx poly;
	fmpz_mod_polyxx * phi;
	fmpz_mod_polyxx * b, * s, *a;

	fmpz_mod_poly_factorxx * factors;
	std::vector<fmpz_mod_polyxx> invfactors;
	std::vector< std::vector<fmpz_mod_polyxx> > gamma;
	bool batching;
	unsigned num_slots;

	Entropy random;
	Sampler *samplererr;
	Sampler *samplerkey;

	FVKey(const struct FVParams& params, bool batch = false);
	
	inline size_t	get_ell() const { return ell; }
	inline fmpz_mod_polyxx	get_phi() const { return *phi; }
	inline unsigned long get_logwq() const { return logwq; }
	inline fmpzxx get_q() const { return q; }
	inline fmpzxx get_t() const { return t; }

	inline size_t	get_num_slots() const { return num_slots; }

	friend std::ostream& operator<<(std::ostream&, const FVKey&);

	Ciphertext	encrypt(BitVector&);
	Ciphertext	encrypt_with_sk(BitVector&);
	BitVector	decrypt(const Ciphertext&);

	std::vector<fmpz_mod_polyxx>	convert(const std::vector<fmpz_mod_polyxx>&);
	unsigned 		noise(const Ciphertext&);
	fmpz_mod_polyxx BitVectorToPoly(BitVector&);
	fmpz_mod_polyxx CRT(const fmpz_mod_polyxx& m0, const fmpz_mod_polyxx& m1, unsigned i);
};	
#endif

