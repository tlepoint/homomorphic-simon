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

#include "Simon.h"

#ifdef SIMON

/* Some Simon specific values, dependent on the chosen version of SIMON */
#if SIMON == 32

unsigned z[28] = {	1,1,1,1,
					1,0,1,0,
					0,0,1,0,
					0,1,0,1,
					0,1,1,0,
					0,0,0,1,
					1,1,0,0};
unsigned maskKey = 0xffff;

unsigned key[] = {0x0100, 0x0908, 0x1110, 0x1918};
unsigned initialPlaintext[] = {0x6565, 0x6877};
unsigned expectedCiphertext[] = {0xc69b, 0xe9bb};

#elif SIMON == 64

unsigned z[40] = {	1,1,0,1,
					1,0,1,1,
					1,0,1,0,
					1,1,0,0,
					0,1,1,0,
					0,1,0,1,
					1,1,1,0,
					0,0,0,0,
					0,1,0,0,
					1,0,0,0};
unsigned maskKey = 0xffffffff;

unsigned key[] = {0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918};
unsigned initialPlaintext[] = {0x656b696c, 0x20646e75};
unsigned expectedCiphertext[] = {0x44c8fc20, 0xb9dfa07a};

#endif

/* Shift */
inline unsigned S(unsigned v, unsigned l)
{
	return ((v<<l) ^ (v>>(SIMON/2-l))) & maskKey;
}

/* (Non) homomorphic key expansion */
void keyExpand(unsigned *expandedKey, unsigned* key)
{
	unsigned tmp;
	for (unsigned i=0; i<4; i++)
	{
		expandedKey[i] = key[i];
	}
	for (unsigned i=4; i<ROUNDS; i++)
	{
		tmp = S(expandedKey[i-1],SIMON/2-3) ^ expandedKey[i-3];
		tmp ^= S(tmp,SIMON/2-1);
		expandedKey[i] = maskKey ^ 3 ^ z[i-4] ^ tmp ^ expandedKey[i-4];
	}
}

/* Homomorphic key expansion */
void homomorphicKeyExpand(std::vector< std::vector<Ciphertext> >& encryptedKeys, unsigned* key, KEY *sqkey)
{
	// Encrypt the initial key
	#pragma omp parallel for schedule(static, 1)
	for (unsigned j=0; j<4; j++)
	{
		std::vector<BitVector> b(SIMON/2, BitVector(sqkey->get_num_slots()));
		for (unsigned i=0; i<SIMON/2; i++)
		{
			for (unsigned l=0; l<sqkey->get_num_slots(); l++)
				b[i][l] = (key[j]>>i)&1;
		}
	
		for (unsigned i=0; i<SIMON/2; i++)
    		encryptedKeys[j].push_back(sqkey->encrypt_with_sk(b[i]));
    }

    // Homomorphic KeyExpand
    std::vector<Ciphertext> tmp(SIMON/2, encryptedKeys[0][0]);
    std::vector< std::vector<Ciphertext> > tmpc(2, tmp);

    std::vector<BitVector> b(SIMON/2, BitVector(sqkey->get_num_slots()));
    for (unsigned i=0; i<SIMON/2; i++)
	{
		for (unsigned l=0; l<sqkey->get_num_slots(); l++)
			b[i][l] = 1;
	}
	for (unsigned l=0; l<sqkey->get_num_slots(); l++)
		b[1][l] = 0;

	for (unsigned l=0; l<sqkey->get_num_slots(); l++)
		b[0][l] = 0;
	for (unsigned i=0; i<SIMON/2; i++)
		tmpc[0][i] = sqkey->encrypt_with_sk(b[i]);
	
	for (unsigned l=0; l<sqkey->get_num_slots(); l++)
		b[0][l] = 1;
	for (unsigned i=0; i<SIMON/2; i++)
		tmpc[1][i] = sqkey->encrypt_with_sk(b[i]);

    for (unsigned j=4; j<ROUNDS; j++)
    {
    	for (unsigned i=0; i<SIMON/2; i++)
    	{
    		encryptedKeys[j].push_back(encryptedKeys[j-1][(i+3)%(SIMON/2)]+encryptedKeys[j-3][i]+encryptedKeys[j-1][(i+4)%(SIMON/2)]+encryptedKeys[j-3][(i+1)%(SIMON/2)]+encryptedKeys[j-4][i]+tmpc[z[j-4]][i]);
    	}
    }
}

/* Encrypt the state */
void encryptState(std::vector<Ciphertext> &state, unsigned *plain, unsigned size, KEY *sqkey)
{
	BitVector B(sqkey->get_num_slots());
	state.resize(SIMON/2*size, sqkey->encrypt_with_sk(B));

	std::vector<BitVector> b(SIMON/2*size, BitVector(sqkey->get_num_slots()));
	for (unsigned l=0; l<1; l++)
    {
		for (unsigned i=0; i<SIMON/2; i++)
	    {
	    	for (unsigned s=0; s<size; s++)
	    	{
	    		b[i+s*SIMON/2][l] = (plain[size*l+s]>>i)&1;
	    	}
	    }
    }
    
    #pragma omp parallel for
    for (unsigned i=0; i<SIMON/2*size; i++)
    	state[i] = sqkey->encrypt_with_sk(b[i]);
	
	b.clear();
}

/* Print the state */
void printState(std::vector<Ciphertext> &st, unsigned size, KEY *sqkey, bool printOnlyFirst)
{
    unsigned *vecplain = new unsigned[sqkey->get_num_slots()*size];
	for (unsigned l=0; l<sqkey->get_num_slots(); l++)
		for (unsigned s=0; s<size; s++)
			vecplain[size*l+s] = 0;

	for (unsigned i = 0; i<SIMON/2; i++)
	{
		for (unsigned s=0; s<size; s++)
		{
			BitVector b = sqkey->decrypt(st[i+(SIMON/2)*s]);
			for (unsigned l=0; l<sqkey->get_num_slots(); l++)
			{
				vecplain[size*l+s] = vecplain[size*l+s]^(((unsigned) b[l])<<(i));//-32*s));
			}
		}		
	}
	if (printOnlyFirst)
	{
		for (unsigned s=0; s<size; s++)
				std::cout << "0x" << hex << vecplain[s] << ((s==size-1)? " " : ", ");
			std::cout << std::endl;
	}
	else
	{
		for (unsigned l=0; l < sqkey->get_num_slots(); l++)
		{
			std::cout << "#" << l << ": "; 
			for (unsigned s=0; s<size; s++)
				std::cout << "0x" << hex << vecplain[size*l+s] << ((s==size-1)? " " : ", ");
			std::cout << std::endl;
		}
	}
}

/* Simon homomorphic encryption */
void SimonEncrypt(std::vector<Ciphertext> &state, std::vector< std::vector<Ciphertext> > &expandedKey, KEY *sqkey)
{
	#ifdef VERBOSE
	timing t;
	std::cout << "Initial state: " << state[0] <<  std::endl;
	#endif

	for (unsigned j=0; j<ROUNDS/2; j++)
	{	
		std::cout << "Round "<< std::dec  << 2*j+1 << std::endl;
		
		#ifdef VERBOSE
		t.start();
		#endif
		
		#pragma omp parallel for schedule(static, 1)
		for (unsigned i=0; i<(SIMON/2); i++)
		{
			state[i+(SIMON/2)] += expandedKey[j*2][i]+state[(i-2)%(SIMON/2)];
			state[i+(SIMON/2)] += state[(i-8)%(SIMON/2)]*state[(i-1)%(SIMON/2)];
		}

		#ifdef VERBOSE
		t.stop( "#" );
		std::cout << "state: " << state[(SIMON/2)] << std::endl;
		printState(state, 2, sqkey);
		#endif

		std::cout << "Round "<< std::dec  << 2*j+2 << std::endl;
		
		#ifdef VERBOSE
		t.start();
		#endif

		#pragma omp parallel for schedule(static, 1)
		for (unsigned i=0; i<(SIMON/2); i++)
		{
			state[i] += expandedKey[j*2+1][i]+state[(i-2)%(SIMON/2)+(SIMON/2)];
			state[i] += state[(i-8)%(SIMON/2)+(SIMON/2)]*state[(i-1)%(SIMON/2)+(SIMON/2)];
		}

		#ifdef VERBOSE
		t.stop( "#" );
		std::cout << "state: " << state[0] << std::endl;
		printState(state, 2, sqkey);
		#endif
	}
}

#endif
