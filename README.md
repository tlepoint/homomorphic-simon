A proof-of-concept implementation of the homomorphic evaluation of SIMON
Using FV and YASHE leveled homomorphic cryptosystems
========================================================================

This is a proof-of-concept implementation of a homomorphic Simon encryption
using YASHE and FV leveled homomorphic cryptosystems. This implementation is
described in the following article:

[1] T. Lepoint and M. Naehrig, "A Comparison of the Homomorphic Encryption
Schemes FV and YASHE". Available at http://eprint.iacr.org/2014.

This proof-of-concept implementation is done in C++ using the FLINT library
http://www.flintlib.org/ 
The C++ wrappers are used, so our implementation requires the use of FLINT
versions >= 2.4. We only tested for FLINT compiles with GMP and not MPIR.


WARNING
=======

This academic implementation is NOT to be used, not to be considered secured
nor pretty code. However we publish it under license CeCILL as a way to
support code-sharing and to allow the community to verify easily both the
correctness and the efficiency of this homomorphic evaluation.


HOW TO USE
==========

Modify the Makefile accordingly and type:

```
$ make
$ ./Simon
```

The underlying homomorphic encryption scheme can be chosen in Makefile.

Parameters can be set in the file main.h.

Note that the wordsize are set in files YASHE/YASHEKey.h and FV/FVKey.h.

To run the TEST mode, uncomment the corresponding line in main.h;
To run the homomorphic evaluation of SIMON, uncomment the corresponding line in main.h.
