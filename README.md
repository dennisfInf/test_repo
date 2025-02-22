## Important Notes
We have 3 seperate projects (one for GigaDORAM, one for semi-honest and one for malicious), which made developing easier. This project now is the first step to merge all three projects, but is a prerelease version that is not fully tested. Currently, only semi-honest and malicious are merged and GigaDORAM will probabily be included too next week. Also, we will do additional bug-testing until next week.
This project version was (currently) only tested with n=3 t=1 and only locally (but should work with arbitrary parameters)

Tested Parameters:
add_shares_vec_mal 3 1 1 100
oram_2 3 10 10 2


## How to run the code for malicious

First, we have to compile the MPC's in MP-SPDZ to do that, issue ([MP-SPDZ has some requirements for that to work](https://mp-spdz.readthedocs.io/en/latest/readme.html) ):
./lib/MP-SPDZ/compile.py -P 5541245505022739011583672869577435255026888277144126952450651294188487038640194767986566260919128250811286032482323 add_shares_vec_mal n t 1 batch_size

where n is equal to the total amount of operators and t the threshold, batch_size is the size of the input batch. In this version, batch_size is hard-coded to 100 inside the c++ project.

./lib/MP-SPDZ/compile.py oram_2 n logbook_size bits t

logbook_size is equal to the amount of entries inside a logbook per user
bits is equal to 2^{bits} logbook addresses.

Now to build the docker files use:

./scripts/build_docker.zsh

which will build the docker files for you.

After that, you are able to run the project with:


 ./scripts/local_start_mal_2.zsh -n 3 -t 1 10 10 100


## semi-honest will follow shortly


## Bugs
Currently, the input check for MPC2 in the malicious setting does not work correctly. 
