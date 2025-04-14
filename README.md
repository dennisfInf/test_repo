## Important Notes
This code tries to use all threads of the underlying system. In doing so (since we are no pros)
it sometimes does no progress, since some threads are occupied. Restarting the container helps then.
This project version was (currently) only tested with n=3 t=1 and only locally (but should work with arbitrary parameters).
In the release version, we will extend the read me to fully recreate our experiments. 

Tested Parameters:
add_shares_vec_mal 3 1 1 100
oram_2 3 10 10 2


## How to run the code for malicious
For this project version malicious currently only works for n=3 and t=1. When publishing the Code, this will work for arbitrary parametrs with a better documentation.
First, we have to compile the MPC's in MP-SPDZ to do that, issue ([MP-SPDZ has some requirements for that to work](https://mp-spdz.readthedocs.io/en/latest/readme.html) ):
./lib/MP-SPDZ/compile.py -P 5541245505022739011583672869577435255026888277144126952450651294188487038640194767986566260919128250811286032482323 add_shares_vec_mal n t 1 batch_size

where n is equal to the total amount of operators and t the threshold, batch_size is the size of the input batch. In this version, batch_size is hard-coded to 100 inside the c++ project.

./lib/MP-SPDZ/compile.py oram_2 n logbook_size bits t

logbook_size is equal to the amount of entries inside a logbook per user
bits is equal to 2^{bits} logbook addresses.
If you plan to also try out semi-honest and Gigadoram, compile their mpc's first by using the ../compile.py .... commands. 
With this, you are able to use the same containers accross the different attacker models.

In the root folder of the repository create a benchmarks folder:

mkdir -p ./benchmarks

Now to build the docker files use (this will take a while):

chmod 777 ./scripts/

./scripts/build_docker.zsh

which will build the docker files for you.

After that, you are able to run the project with:


 ./scripts/local_start_mal_2.zsh -n 3 -t 1 10 10 100

## Bugs
Currently, the input check for MPC2 in the malicious setting does not work correctly and will be fixed on publishing the code.


## semi-honest 

Similiarly compile the mpc's:

./lib/MP-SPDZ/compile.py -P 5541245505022739011583672869577435255026888277144126952450651294188487038640194767986566260919128250811286032482323 add_shares_vec n t 1 batch_size
and
./lib/MP-SPDZ/compile.py oram_honest n logbook_size bits 

In the root folder of the repository create a benchmarks folder:

mkdir -p ./benchmarks

Now to build the docker files use:

./scripts/build_docker_honest.zsh

After that, you are able to run the project with:


 ./scripts/local_start_honest.zsh -n 3 -t 1 {logbook_size} {bits} {batch_size}
 


 This code works fine and you can choose every parameter to your liking.


## semi-honest gigadoram
Almost the same as above. Here are the differences in the commands:
Use the --gigadoram flag while building

./scripts/build_docker_honest.zsh --gigadoram

Also some additional arguments need to be provied to run it:

 ./scripts/local_start_giga.zsh {batch_size} {bits} {num_levels}  {amp_factor}

 Num levels and amp factor are parameteres specific to gigadoram. See: https://github.com/jacob14916/GigaDORAM-USENIX23-Artifact 