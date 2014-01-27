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

#include "main.h"

#ifdef SIMON

/*
* Homomorphic evaluation of Simon
* possible values: SIMON=32 or SIMON=64
*/

int main(int argc, char *argv[])
{

	timing t;
	gmp_randclass rng(gmp_randinit_default);

	assert(params.t == fmpzxx("2"));

	/* KEYGEN */
	t.start();
	KEY *sqkey;
	sqkey = new KEY(params, BATCH);
	t.stop( "KEYGEN" );
	std::cout << *sqkey << std::endl;

	/* Define plaintext vector */
	unsigned *plain = new unsigned[2*sqkey->get_num_slots()];
	plain[0] = initialPlaintext[0];
	plain[1] = initialPlaintext[1];

	for (unsigned i=2; i<2*sqkey->get_num_slots(); i++)
		plain[i] = (BATCH) ? plain[i%2] : 0;

	/* Encrypt the key */
	t.start();
	std::vector< std::vector<Ciphertext> > encryptedKeys(ROUNDS);

/*
	// Old method (key expansion not done homomorphically)
	unsigned *expandedKey = new unsigned[ROUNDS];
	keyExpand(expandedKey, key);
	#pragma omp parallel for schedule(static, 1)
	for (unsigned r=0; r<ROUNDS; r++)
	{
		encryptState(encryptedKeys[r], expandedKey+r, 1, sqkey);
	}

//*/
	homomorphicKeyExpand(encryptedKeys, key, sqkey);
	t.stop( "Encrypt Key" );
/*	
	// Print the expanded key
	for (unsigned r=0; r<ROUNDS; r++)
	{
		printState(encryptedKeys[r],1,sqkey);
	}
//*/

	/* Encrypt the State */
	std::vector<Ciphertext> state;
    t.start();
    encryptState(state, plain, 2, sqkey);
	t.stop( "Encrypt State" );

	/* Simon Encrypt */
	t.start();
	SimonEncrypt(state, encryptedKeys,sqkey);
	t.stop( "Simon Encrypt" );

	/* Simon Result */
	t.start();
	std::cout << "-----------------------------------------------------------------------------------------" << std::endl;
	std::cout << "Real state:" << std::endl;
	printState(state, 2, sqkey);
	std::cout << "Expected state:" << std::endl;
	std::cout << "0x" << expectedCiphertext[0] << ", 0x" << expectedCiphertext[1] << std::endl;
	std::cout << "-----------------------------------------------------------------------------------------" << std::endl;
	t.stop( "Print State" );
	std::cout << state[0] << std::endl;

	/* Timings */
	t.show();

	return EXIT_SUCCESS;
}

#else

int main(int argc, char *argv[])
{
	timing t;
	gmp_randclass rng(gmp_randinit_default);
	int basis = params.t.to<slong>();
	srand(111222);

	/* Keygen */
	t.start();
	KEY *sqkey;
	sqkey = new KEY(params, BATCH);
	t.stop(" KeyGen ");
	std::cout << *sqkey << std::endl;


	/* Define some random vectors */
	BitVector m1(sqkey->get_num_slots(), basis, true);
	BitVector m09876(sqkey->get_num_slots(), basis, true);
	BitVector m2(sqkey->get_num_slots(), basis, true);

	/* Encrypt */
	t.start();
	Ciphertext c1 = sqkey->encrypt_with_sk(m1);
	Ciphertext c2 = sqkey->encrypt_with_sk(m2);
	Ciphertext c12 = sqkey->encrypt_with_sk(m09876);
	Ciphertext c22 = sqkey->encrypt_with_sk(m2);
	Ciphertext c13 = sqkey->encrypt_with_sk(m1);
	Ciphertext c23 = sqkey->encrypt_with_sk(m2);
	Ciphertext c14 = sqkey->encrypt_with_sk(m1);
	Ciphertext c24 = sqkey->encrypt_with_sk(m2);
	Ciphertext c15 = sqkey->encrypt_with_sk(m1);
	Ciphertext c25 = sqkey->encrypt_with_sk(m2);
	t.stop(" 10 Encrypt ");

	/* Add */
	t.start();
	Ciphertext c3 = c1+c2;
	t.stop(" Add ");

	/* Multiply */
	t.start();
	Ciphertext c4 = c1*c2;
	t.stop(" Mult ");

	/* Convert */
	t.start();
	c4.convert_self();
	t.stop(" Convert ");

	/* Decrypt */
	t.start();
	BitVector m3 = sqkey->decrypt(c3);
	BitVector m4 = sqkey->decrypt(c4);
	BitVector m32 = sqkey->decrypt(c12);
	BitVector m42 = sqkey->decrypt(c22);
	BitVector m33 = sqkey->decrypt(c13);
	BitVector m43 = sqkey->decrypt(c23);
	BitVector m34 = sqkey->decrypt(c14);
	BitVector m44 = sqkey->decrypt(c24);
	BitVector m35 = sqkey->decrypt(c15);
	BitVector m45 = sqkey->decrypt(c25);
	t.stop(" 10 Decrypt ");

	/* Verifications */
	std::cout << "Hom. Addition: " << ((m3 == (m1+m2)) ? "OK" : "NOT OK") << std::endl; 
	std::cout << "Hom. Multiply: " << ((m4 == (m1*m2)) ? "OK" : "NOT OK") << std::endl; 
	
	std::cout << "m2:" << m2 << std::endl;
	std::cout << "c2:" << c2 << std::endl;
	
	std::cout << "m1:" << m1 << std::endl;
	std::cout << "c1:" << c1 << std::endl;
	
	std::cout << "c3:" << c3 << std::endl;
	std::cout << "m4:" << m4 << std::endl;
	std::cout << "c4:" << c4 << std::endl;

	return EXIT_SUCCESS;
}

#endif