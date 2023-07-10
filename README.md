# PQC-MPSI

An implementation of the first multiparty private set intersection protocol with
linear complexity, available at \[[https:://eprint.iacr.org/2021/172](https://ia.cr/2021/172)\]. Also contains the first implementations of multiparty
circuit and quorum private set intersection protocols.

Code based on the implementation of 2-party private set intersection available at \[[encryptogroup/OPPRF-PSI](https://github.com/encryptogroup/OPPRF-PSI)\]
and on the implementation of multiparty arithmetic circuits available at \[[cryptobiu/MPC-Benchmark/MPCHonestMajority](https://github.com/cryptobiu/MPC-Benchmark/tree/master/MPCHonestMajority)\]

For mPSI protocols, this repository has implementation using polynomial-OPPRF and relaxed-OPPRF. See \[[mPSI-TableOPPRF](https://github.com/shahakash28/mPSI-TableOPPRF)\] for implementation using table-OPPRF.

## Required packages:
 - g++ (version >=8) 
 - libboost-all-dev (version >=1.69) 
 - libgmp-dev 
 - libssl-dev 
 - libntl-dev
 - libscapi

## Compilation

After cloning project from Git:
1. Copy aux\_hash/cuckoo\_hashing.cpp and aux\_hash/cuckoo\_hashing.h into extern/HashingTables/cuckoo\_hashing
2. Copy aux\_hash/iknp.h into extern/EzPC/SCI/src/OT/

To compile as library.

```
mkdir build
cd build
cmake ..
make
// or make -j for faster compilation

```

## Applications & Running the Code

This implementation can execute protocols for multiparty circuit-based private set intersection, multiparty circuit private set intersection, 
and multiparty quorum private set intersection, referred to in the code as "Threshold". (For further details on the protocols, see the paper.)

To run the program, there are two methods that can be used:
 - individually run each process as:
   ```
   ./build/bin/pqc_mpsi_example -F files/addresses -R 4
   ```
   with the requisite arguments, or
 - call ./run\_protocol.sh with the arguments

The arguments are:
 - r: Role / party ID (indexed from 0 i.e leader party must be 0)
 - N: Total number of parties
 - n: Set size (e.g 4096, 65536, 262144)
 - t: Number of threads
 - o: Type of OPPRF (Poly/Relaxed)
 - y: PSI variant (PSI/Circuit/Threshold)
 - c: Threshold/quorum in case of Quorum PSI

E.g for Quorum PSI with Relaxed Batch OPPRF over 15 parties on the same terminal, threshold 7, set size 2^18 (=262144), run:
```
./run_protocol.sh 0 14 15 262144 14 Relaxed Threshold 7
```

For further details, run 
```
./build/bin/pqc_mpsi_example --help
```

To run over multiple servers, edit the IP addresses in Parties.txt and files/addresses.

Change the input sets in main() method of mpsi\_src/mpsi\_analytics\_example.cpp.

## Field Modulus

This branch implements the second phase of Quorum and Circuit PSI variants in the field with prime modulus 31. 
This prime modulus can be changed to any other Mersenne prime under 1 byte in length such that the prime is greater than N.

To change this the following files need to be edited:
-  mpsi\_src/mpsi\_analytics\_example.cpp: 160 
-  extern/MPCHonestMajority/ZpMersenneByteElement.cpp: 4, 5

## Contact

For any queries, contact Akash Shah (akashshah08 at outlook.com) or Nishka Dasgupta (nishka.dasgupta at yahoo.com).
