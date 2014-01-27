#ifndef __SIMON_H
#define __SIMON_H

#include "main.h"

#if SIMON == 32
#define ROUNDS 32
#elif SIMON == 64
#define ROUNDS 44
#endif

extern unsigned key[];
extern unsigned initialPlaintext[];
extern unsigned expectedCiphertext[];

void keyExpand(unsigned *expandedKey, unsigned* key);
void printState(std::vector<Ciphertext> &st, unsigned size, KEY *sqkey, bool printOnlyFirst=true);
void encryptState(std::vector<Ciphertext> &state, unsigned *plain, unsigned size, KEY *sqkey);
void SimonEncrypt(std::vector<Ciphertext> &state, std::vector< std::vector<Ciphertext> > &expandedKey, KEY *sqkey);
void homomorphicKeyExpand(std::vector< std::vector<Ciphertext> >& encryptedKeys, unsigned* key,  KEY *sqkey);

#endif