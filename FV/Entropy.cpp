/*

File downloaded from http://bliss.di.ens.fr

*/

/*

Copyright or © or Copr. Leo Ducas and Tancrede Lepoint.

Leo.Ducas@ens.fr and Tancrede.Lepoint@ens.fr

This software is a computer program whose purpose is to provide to the 
research community a proof-of-concept implementation of the BLISS 
digital signature scheme of Ducas, Durmus, Lepoint and Lyubashevsky 
appeared at Crypto 2013.

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

#include "Entropy.h"
#include <iostream>
#include <stdlib.h>
#include <openssl/sha.h>

/*
	Entropy class constructor
*/
Entropy::Entropy()
{
	entropyCharPool = new unsigned char[SHA512_DIGEST_LENGTH*ENTROPYPOOL_SIZE];
	entropyLongPool = new unsigned long[(SHA512_DIGEST_LENGTH>>3)*ENTROPYPOOL_SIZE];

	current_seed = new unsigned char[SHA512_DIGEST_LENGTH];
	fp = fopen("/dev/urandom", "r");
	size_t r = fread(current_seed,sizeof(unsigned char),SHA512_DIGEST_LENGTH,fp);
	if (!r){
		std::cerr << "Cannot read /dev/urandom" << std::endl;
		exit(1);
	}
	//	for (long i=0; i<SHA512_DIGEST_LENGTH; i++)
	//	current_seed[i]=0;
	populateCharPool();
	populateLongPool();
	populateBitPool();
}

/*
	Sha512 computation (CTR mode)
*/
void Entropy::sha512(unsigned char* hash)
{
	long i, j;
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, current_seed, SHA512_DIGEST_LENGTH);
    SHA512_Final(hash, &sha512);
    for (i=0; i<SHA512_DIGEST_LENGTH; i++)
    {
    	if (current_seed[i]!=255)
    	{
    		for (j=0; j<i; j++) current_seed[j] = 0;
    		current_seed[i]++;
    		break;
    	}
    }
}

/*
	Populate Char Pool
*/
void Entropy::populateCharPool()
{
	long i;
	unsigned char* hash = entropyCharPool;
	
	for (i=0; i<ENTROPYPOOL_SIZE; i++){
	  sha512(hash);
	  hash +=64;
	}
	posEntropyCharPool = 0;
}


/*
	Populate Long Pool
*/
void Entropy::populateLongPool()
{
	long i;
	unsigned char* hash = (unsigned char*) ((void*) entropyLongPool);
	
	for (i=0; i<ENTROPYPOOL_SIZE; i++){
	  sha512(hash);
	  hash +=64;
	}

	posEntropyLongPool = 0;
}

/*
	Populate Bit Pool
*/
void Entropy::populateBitPool()
{
	entropyBitPool = getRandomLong();
	posEntropyBitPool = 0;
}

/*
	Get random char
*/
unsigned char Entropy::getRandomChar()
{
	if (posEntropyCharPool>=ENTROPYPOOL_SIZE*64) populateCharPool();
	unsigned char result = entropyCharPool[posEntropyCharPool];
	posEntropyCharPool++;
	return result;
}

/*
	Get random long
*/
unsigned long Entropy::getRandomLong()
{
	if (posEntropyLongPool>=ENTROPYPOOL_SIZE*8) populateLongPool();
	unsigned long result = entropyLongPool[posEntropyLongPool];
	posEntropyLongPool++;
	return result;
}

/*
	Get random char from /dev/urandom
*/
unsigned char Entropy::getURandomChar()
{
	unsigned char result;
	size_t r = fread (&result,sizeof(unsigned char),1,fp);
	if (!r){
		std::cerr << "Cannot read /dev/urandom" << std::endl;
		exit(1);
	}
	return result;
}

/*
	Get random long from /dev/urandom
*/
unsigned long Entropy::getURandomLong()
{
	unsigned long result;
	size_t r = fread (&result,sizeof(unsigned long),1,fp);
	if (!r){
		std::cerr << "Cannot read /dev/urandom" << std::endl;
		exit(1);
	}
	return result;
}

/*
	Get random bit
*/
bool Entropy::getRandomBit()
{
	if (posEntropyBitPool>=64) populateBitPool();
	bool result = entropyBitPool&1;
	entropyBitPool >>= 1;
	posEntropyBitPool++;
	return result;
  // return (getRandomChar() & 1);
}

/*
	Entropy class destructor
*/
Entropy::~Entropy()
{
	fclose(fp);
	delete[] current_seed;
	delete[] entropyCharPool;
	delete[] entropyLongPool;
}
