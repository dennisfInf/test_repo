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
    docker run  --rm  --network host --entrypoint /bin/bash  --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc2.txt,target=/usr/src/MP-SPDZ/hostsmpc.txt --mount type=bind,source=$script_dir/../benchmarks,target=/app/benchmarks mpspdz -c "sleep 2 && exec ./malicious-shamir-party.x $id oram_2-$n-$5-$6-$t-1 -pn 19500 --ip-file-name hostsmpc.txt -N $n -B 5 --batch-size 100 > /app/benchmarks/mpspdz-$n-$id-$t-mpc2.log 2>&1" &
done
sleep 8
for id in {0..$(($n- 1))}; do
    docker run --rm  --network host --entrypoint /bin/bash --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc1.txt,target=/usr/src/MP-SPDZ/hostsmpc.txt --mount type=bind,source=$script_dir/../benchmarks,target=/app/benchmarks mpspdz -c "sleep 2 && exec ./malicious-shamir-party.x $id add_shares_vec_mal-$n-$t-1-$7 -pn 18500 --ip-file-name hostsmpc.txt -N $n -B 5 --batch-size 100 > /app/benchmarks/mpspdz-$n-$id-$t-mpc1.log 2>&1" & 
done
sleep 4

app_port=50050
docker run --rm --network host --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc1.txt,target=/app/hostnames_mpc1.txt  --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc2.txt,target=/app/hostnames_mpc2.txt -v $script_dir/../benchmarks:/app/benchmarks poba $n 1 $t $app_port 14000 127.0.0.1 127.0.0.1:50050 1 &

for id in {1..$(($n- 1))};do
    app_port=$((50050+ $id))
    docker run --rm  --network host --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc1.txt,target=/app/hostnames_mpc1.txt  --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc2.txt,target=/app/hostnames_mpc2.txt -v $script_dir/../benchmarks:/app/benchmarks poba $n 0 $t $app_port 14000 127.0.0.1 127.0.0.1:50050 1 &
done

wait
