#!/bin/zsh
#After building the container
#
#
if [[ $1 =~ ^(-n) && $3 =~ ^(-t) ]]
then
    if [[ $2 =~ ^[0-9]+$ && $4 =~ ^[0-9]+$ ]]
    then
        n="$2"
        t="$4"
        echo "starting bookkeeping implementation with parameters n: $n t: $t"
    else echo "either -n or -t is not a number"
        exit 1
    fi
else echo "Usage: $0 -n <number of parties> -t <threshold> <loogbook size> <log of oram addresses> <batch size>"
    exit 1
fi
script_path=$(realpath "$0")

script_dir=$(dirname "$script_path")

for id in {0..$(($n- 1))}; do
    docker run  --rm  --network host --entrypoint /bin/bash  --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc2.txt,target=/usr/src/MP-SPDZ/hostsmpc.txt --mount type=bind,source=$script_dir/../benchmarks,target=/app/benchmarks mpspdz -c "sleep 2 && exec ./shamir-party.x $id oram_2-$n-$5-$6-1 -pn 19500 --ip-file-name hostsmpc.txt -N $n -B 5 --batch-size 100 > /app/benchmarks/mpspdz-$n-$id-$t-mpc2.log 2>&1" &
done
sleep 8
for id in {0..$(($n- 1))}; do
    docker run --rm  --network host --entrypoint /bin/bash --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc1.txt,target=/usr/src/MP-SPDZ/hostsmpc.txt --mount type=bind,source=$script_dir/../benchmarks,target=/app/benchmarks mpspdz -c "sleep 2 && exec ./shamir-party.x $id add_shares_vec-$n-$t-1-$7 -pn 18500 --ip-file-name hostsmpc.txt -N $n -B 5 --batch-size 100 > /app/benchmarks/mpspdz-$n-$id-$t-mpc1.log 2>&1" & 
done

wait
