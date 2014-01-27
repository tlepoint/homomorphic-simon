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

#ifndef __SAMPLER_H
#define __SAMPLER_H

#include "Entropy.h"
//#include <vector>

struct precise {
    unsigned long a, b;
};
const int tau = 12;
const double sigma_bin_inv_lowprec = 1.17741002251547469101156932645969963; // sqrt(2 ln 2)
const  double sigma_bin_lowprec = 0.8493218002880190427215028341028896; //  sqrt(1/(2 ln 2))
// WARNING: Not High precision (because not needed)!!!


class Sampler {
	private:
		long stddev;
		unsigned long k;
		unsigned long mask;
		unsigned M;
		unsigned long maskPosGau[8];
		unsigned long valPosGau[8];
		unsigned ell;

		unsigned char* c;
		unsigned long CDT_length;
		unsigned long* CDT;
		unsigned long CDT_inv_min[256];
		unsigned long CDT_inv_max[256];
		Entropy* random;
		
	public:
		Sampler(long stddev_input, double alpha, Entropy* randomGen);		
		unsigned long SamplerPosBin();
		unsigned long SamplerPosGau();
		bool SamplerBer(unsigned char* p);
		bool SamplerBerExp(unsigned long x);
		bool SamplerBerExpM(unsigned long x);
		bool SamplerBerCosh(long x);
		long SamplerGaussian();
		~Sampler();
};


#endif
