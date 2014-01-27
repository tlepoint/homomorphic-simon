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

#include "Sampler.h"
#include <iostream>
#include <gmp.h>
#include <mpfr.h>

#include <math.h>

#define _CDT_SAMPLER

/*
	Construction of the sampler

	Should precompute the needed values. The current construction 
	constructs a lot of useless values!!!
*/
Sampler::Sampler(long stddev_input, double alpha, Entropy* randomGen)
{
	random = randomGen;

	stddev = stddev_input;
	k = (unsigned long) (sigma_bin_inv_lowprec*stddev) +1;
	// HACK ! 

		
	// Mask to generate random y
	unsigned long tmpk = k;
	mask = 1;
	while (tmpk>0) {mask <<= 1; tmpk >>= 1;}
	mask = mask-1;

	// Temp variables

	mpfr_t f, y, ff, fM, t, z;
	mpfr_init2(f, 128);
	mpfr_init2(y, 128);
	mpfr_init2(ff, 128);
	mpfr_init2(fM, 128);
	mpfr_init2(t, 128);
	mpfr_init2(z, 128);

	mpfr_set_ui(t, 8, GMP_RNDN);
	mpfr_exp2(t, t, GMP_RNDN); // t^8

	unsigned long B = (unsigned long) (k-1)*(k-1+2*k*sigma_bin_lowprec*tau)+1 , i, j;
	
	ell=0;
	while (B>0) {
		B=B>>1;
		ell++;
	}

//	std::cout << "B=" << B << std::endl;
//	std::cout << "ell=" << ell << std::endl;
	
	// Computation f
	
	mpfr_set_ui(ff, 2, GMP_RNDN);
	mpfr_log(ff, ff, GMP_RNDN); // ff = ln(2)
	mpfr_set_ui(f, k*k, GMP_RNDN); // f = k^2
	mpfr_div(f, f, ff, GMP_RNDN); // f = 2sigma^2 = 2 k^2 1/(2ln(2)) = k^2/ln(2)
	
	// Output sigma to compare with original
	mpfr_div_ui(ff, f, 2, GMP_RNDN);
//	std::cout << "Theoretical stddev^2=" << mpfr_get_d(ff, GMP_RNDN) << std::endl;
	mpfr_sqrt(ff, ff, GMP_RNDN);
//	std::cout << "Theoretical stddev=" << mpfr_get_d(ff, GMP_RNDN) << " instead of " << stddev << std::endl;


	mpfr_mul(ff, ff, ff, GMP_RNDN);
	mpfr_div_d(ff,ff,alpha*alpha,GMP_RNDN);
	
//	std::cout << "M=" << mpfr_get_d(ff,GMP_RNDN) << std::endl;
	M = mpfr_get_ui(ff,GMP_RNDD)+1; // M=exp(m/2sigma^2)
//	std::cout << "M=" << M << std::endl;


	
	// Compute c_i's
	mpfr_set_ui(y, 1, GMP_RNDN);
	c = new unsigned char[ell*16];

	for (i=0; i<ell; i++)
	{
		mpfr_set(z, y, GMP_RNDN); // z=2^i
		mpfr_mul_si(z,z, -1, GMP_RNDN);
		mpfr_div(z,z,f, GMP_RNDN); // z = -2^i/f
		mpfr_exp(z,z, GMP_RNDN); // z = exp(-2^i/f)

		for (j=0; j<16; j++) {
			
			mpfr_mul(z,z,t,GMP_RNDN); // z = exp(-2^i/f)*2^8
			
			c[i*16+j] = (unsigned char) mpfr_get_ui(z, GMP_RNDD);
			mpfr_sub_ui(z,z,(unsigned long) c[i*16+j],GMP_RNDN);
		}

		mpfr_mul_ui(y,y, 2, GMP_RNDN); // y=2*y
	}

	maskPosGau[1] = 1;
	maskPosGau[2] = 14; //0b1110;
	maskPosGau[3] = 496; //0b111110000;
	maskPosGau[4] = 65024; //0b1111111000000000;
	maskPosGau[5] = 33488896; //0b1111111110000000000000000;
	maskPosGau[6] = 68685922304; //0b111111111110000000000000000000000000;
	maskPosGau[7] = 562881233944576; //0b1111111111111000000000000000000000000000000000000;
	valPosGau[1] = 1;
	valPosGau[2] = 8; //0b1000;
	valPosGau[3] = 256; //0b100000000;
	valPosGau[4] = 32768; //0b1000000000000000;
	valPosGau[5] = 16777216; //0b1000000000000000000000000;
	valPosGau[6] = 34359738368; //0b100000000000000000000000000000000000;
	valPosGau[7] = 281474976710656; //0b1000000000000000000000000000000000000000000000000;

	// Precompute CDT

	CDT_length = (unsigned long) (k * sigma_bin_lowprec * tau) +1;
	CDT = new unsigned long[CDT_length *2];

//	std::cerr << "2 * sigma^2 " << mpfr_get_d(f, GMP_RNDN) << std::endl;
	
	// compute normalization constant
	mpfr_set_ui(t, 0, GMP_RNDN);
	for (i=1; i<CDT_length; i++)
	{
	  mpfr_set_ui(z, i-1, GMP_RNDN);
	  mpfr_mul(z,z,z, GMP_RNDN); // z = (i-1^2
	  mpfr_mul_si(z,z,-1,GMP_RNDN); // z=-(i-1)^2
	  mpfr_div(z,z,f, GMP_RNDN); // z = i^2/f
  	  mpfr_exp(z,z, GMP_RNDN); // z = exp(-2^i/f)
	  if (i==1)
	    mpfr_div_ui(z,z,2, GMP_RNDN);
	  mpfr_add(t,t,z,GMP_RNDN);
	}

//	std::cerr << "rho_sigma(ZZ)" << mpfr_get_d(t, GMP_RNDN) << std::endl;


	mpfr_set_ui(ff, 64, GMP_RNDN);
	mpfr_exp2(ff, ff, GMP_RNDN); // t^8

	mpfr_set_ui(y, 0, GMP_RNDN);
	for (i=1; i<CDT_length; i++)
	{
	  mpfr_set_ui(z, i-1, GMP_RNDN);
	  mpfr_mul(z,z,z, GMP_RNDN); // z = (i-1)^2
	  mpfr_mul_si(z,z,-1,GMP_RNDN); // z=-(i-1)^2
	  mpfr_div(z,z,f, GMP_RNDN); // z = (i-1)^2/f
  	  mpfr_exp(z,z, GMP_RNDN); // z = exp(2^(i-1)/f)
	  if (i==1)
	    mpfr_div_ui(z,z,2, GMP_RNDN);

	  mpfr_div(z,z,t,GMP_RNDN); // z = exp(-2^i/f) / (1/2 \rho(ZZ))
	  mpfr_add(y,y,z,GMP_RNDN); // y = \rho([-(i-1),i-1]) / rho(ZZ)


	  mpfr_set(z,y,GMP_RNDN);

	  for (j=0; j<2; j++) {	    	    

	    mpfr_mul(z,z,ff,GMP_RNDN); 

	    CDT[i+j*CDT_length] = (unsigned long) mpfr_get_ui(z, GMP_RNDD);
	    mpfr_sub_ui(z,z,(unsigned long) CDT[i+j*CDT_length],GMP_RNDN);
	    

	  }
	}

	for (j=0; j<2; j++){
	  CDT[j*CDT_length] = (unsigned long) 0;
	}
	
	unsigned long min=0, max = 0,val;
	unsigned long mask =  ((unsigned long) (255U)) << 56;
	
	for(i=0;i<256;i++){
	  val = ((unsigned long) i) << 56;
	  while(CDT[min+1]<val){
	    min++;
	  }
	  
	  while((max+1 < CDT_length) && ( (CDT[max] & mask) <=val))
	    max++;
	  CDT_inv_min[i]=min;
	  CDT_inv_max[i]=max;
	}


	mpfr_clear(t);
	mpfr_clear(ff);
	mpfr_clear(z);
	mpfr_clear(y);
	mpfr_clear(f);


}

/* Sample according to 2^(-x*x) */

/* Should be rewritten if we start using it again ! 
Consume too much entropy ! 
Doesn't handle proba less than 2^{-64}
Boooooh!
*/
unsigned long Sampler::SamplerPosBin() {
	long i;
	unsigned long val;
	std::cerr << "SamplerPosBin Should not be used until rewritten !" << std::endl;
	beg:
	if (random->getRandomBit()==0) return 0;
	
	for (i=1; i>0; i++)
	  {
	    if (i>=8) { std::cout << "erk" << std::endl; break; }
	    val = (random->getRandomLong()&maskPosGau[i]);
	    if (val == valPosGau[i]) return i;
	    else if ( (val&(maskPosGau[i]>>1))>0 ) goto beg;
	  }
	return 0;
}
//*/

/* 
	Sample according to the positive Gaussian of std dev=sigma
*/
unsigned long Sampler::SamplerPosGau() {
	unsigned long x, y;

	begPosGau:

	x = SamplerPosBin();
	do {
	  y = (random->getRandomLong()&mask);
	} while(y>=k);
	
	if (!SamplerBerExp(y*y+2*k*x*y)) goto begPosGau;
	
	return (k*x+y);
}
//*/

/*
	Sampling Ber(p) with p=0.ab
*/
bool Sampler::SamplerBer(unsigned char* p)
{
	long i;
	unsigned char uc;
	for (i=0; i<16; i++)
	{
	  uc = random->getRandomChar();
	  if (uc < *(p)) return 1;
	  else if (uc > *(p)) return 0;
	  p++;
	}
	return 1;
}
//*/

/*
	Sample according to exp(-x/(2*sigma*sigma))
*/
bool Sampler::SamplerBerExp(unsigned long x)
{
	long bit=0;
	while (x>0) {
		if ((x&1) &&!SamplerBer((c+(bit*16)))) return 0;
		x >>= 1;
		bit++;
	}
	return 1;
}

/*
	Sample according to 1/(M*exp(-x/(2*sigma*sigma)))
*/
bool Sampler::SamplerBerExpM(unsigned long x)
{
	return SamplerBerExp(M-x);
}

/*
	Sample according to 1/cosh(x/(sigma*sigma)
*/
bool Sampler::SamplerBerCosh(long x)
{
	if (x<0) x=-x;
	while(1) {
		if (SamplerBerExp(x<<1)) return 1;
		if ( random->getRandomBit())
		  if (!SamplerBerExp(x<<1)) return 0;
	}
}
//*/

#ifdef _CDT_SAMPLER

const unsigned long long_255 = ((unsigned long) (255U));
const unsigned long mask_init = long_255 << (64-8);

/*
	Gaussian Sampler
*/
long Sampler::SamplerGaussian(){

  unsigned char r0;
  unsigned long min, max;
  
  r0 = ((unsigned char) random->getRandomChar());
  min = CDT_inv_min[r0];
  max = CDT_inv_max[r0];
  //  min = 0;
  //max = CDT_length;
  if (max-min <2){
    //std::cerr << "WTF ?" << std::endl;
    return (random->getRandomBit()) ? min : -min;

  }
  //std::cerr << "blaaaaaa" << std::endl;
  unsigned long r1; 
  unsigned long cur;
  unsigned long mask_index;
  unsigned long r2;

  mask_index = 56;
  r1 = ((unsigned long) r0) <<  mask_index;
  r2 = mask_init;
  cur = (min+max)/2;

  while (1){
    if (r1 > CDT[cur])
      min = cur;
    else if (r1 < (CDT[cur] & r2))
      max = cur;
    else{
      if (!mask_index)
	break;
      mask_index-= 8;
      r2 |= long_255 << mask_index;
      r1 |= ((unsigned long) random->getRandomChar()) << mask_index;
    }
    if (max-min <2){
      return (random->getRandomBit()) ? min : -min;
    }
    cur = (min+max)/2;
  }
 
  r2 = random->getRandomLong(); 
  while (1){
    if (r1 < CDT[cur] || ((r1 == CDT[cur]) && (r2 < CDT[cur+CDT_length])))
      max = cur;
    else
      max = cur;
    cur = (min+max)/2;   
    if (max-min <2)
      return (random->getRandomBit()) ? min : -min;
  }
}
  
//*/
#endif

#ifndef _CDT_SAMPLER
/*
	Gaussian Sampler
*/
long Sampler::SamplerGaussian()
{
	unsigned long z;
	bool sign = random->getRandomBit();
	bool bit;
	
	begSam:
	z = SamplerPosGau();
	bit = random->getRandomBit();
	if ((z==0) && (bit==0))
		goto begSam;
	return (sign) ? z : -z;
}

#endif

/*
	Sampler destruction
*/
Sampler::~Sampler()
{
	delete[] c;
	delete[] CDT;
}
