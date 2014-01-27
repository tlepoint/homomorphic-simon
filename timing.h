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


#ifndef __TIMING_H__
#define __TIMING_H__
#include <iostream>
#include <map>
#include <ctime>
using namespace std;

#ifdef __MACH__
#include <sys/time.h>
//clock_gettime is not implemented on OSX
#define CLOCK_MONOTONIC 0
int clock_gettime(int clk_id, struct timespec* t);
#endif

class tm_entry {
  public:
    double		total_cpu_time;
    double		total_wall_time;
    unsigned long	iterations;

    tm_entry() : total_cpu_time(0.), total_wall_time(0.), iterations(0) {}
    tm_entry(double cpu, double wall, unsigned long its = 1) :
	total_cpu_time(cpu), total_wall_time(wall), iterations(its) {}

    void update(const tm_entry& other) {
	total_cpu_time  += other.total_cpu_time;
	total_wall_time += other.total_wall_time;
	iterations      += other.iterations;
    }
};

class timing {
    bool		  recording;
    clock_t		  last_clock;
    timespec		  last_wall;
    map<string, tm_entry> results;

  public:
    timing() : recording(false) {}
    
    void start( void ) {
	if( recording )
	    return;

	recording = true;
	last_clock = clock();
	clock_gettime(CLOCK_MONOTONIC, &last_wall);
    }

    void stop( const string& s, bool verbose = true ) {
	if( !recording )
	    return;

	double cpu_secs, wall_secs;
	timespec now;

	cpu_secs  = static_cast<double>(clock() - last_clock) / 
	    ((double)CLOCKS_PER_SEC);

	clock_gettime(CLOCK_MONOTONIC, &now);
	wall_secs = (now.tv_sec - last_wall.tv_sec)/1.0 +
	    (now.tv_nsec - last_wall.tv_nsec) / 1000000000.0;

	if( verbose )
	    cerr << s << ": " << cpu_secs << " s (CPU) / "
		              << wall_secs<< " s (wall)." << endl;

	tm_entry newentry(cpu_secs, wall_secs);

	map<string, tm_entry>::iterator it = results.find(s);
	if( it != results.end() ) {
	    newentry.update(it->second);
	    results.erase(it);
	}

	results.insert( pair<string, tm_entry>(s, newentry) );
	recording = false;
    }

    void show( void ) {
	double total_cpu = 0., total_wall = 0.;
	map<string, tm_entry>::iterator it;

	cerr << "Function\t#\tCPU avg\tWall avg\n";
	for( it = results.begin(); it != results.end(); it++ ) {
	    tm_entry e = it->second;
	    cerr << it->first << '\t' << e.iterations << '\t' 
		 << e.total_cpu_time   / e.iterations << '\t' 
		 << e.total_wall_time  / e.iterations << endl;
	    
	    total_cpu  += e.total_cpu_time;
	    total_wall += e.total_wall_time;
	}
	cerr << "\nOverall time: " << total_cpu << " s (CPU) / "
	                           << total_wall<< " s (wall)." << endl;
    }
};

#endif /* __TIMING_H__ */
