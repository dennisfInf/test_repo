#!/bin/zsh
#After building the container
#
#

script_path=$(realpath "$0")

script_dir=$(dirname "$script_path")

sleep 3
for id in {0..2}; do
    docker run --rm  --network host --entrypoint /bin/bash --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc1.txt,target=/usr/src/MP-SPDZ/hostsmpc.txt --mount type=bind,source=$script_dir/../benchmarks,target=/app/benchmarks mpspdz -c "sleep 2 && exec ./shamir-party.x $id add_shares_vec-3-1-1-$1 -pn 18500 --ip-file-name hostsmpc.txt -N 3 -B 5 --batch-size 100" & 
done
sleep 4

app_port=50050
docker run --rm --network host --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc1.txt,target=/app/hostnames_mpc1.txt  --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc2.txt,target=/app/hostnames_mpc2.txt -v $script_dir/../benchmarks:/app/benchmarks poba 3 1 1 $app_port 14000 127.0.0.1 127.0.0.1:50050 0 $2 $3 $4 &

for id in {1..2};do
    app_port=$((50050+ $id))
    docker run --rm  --network host --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc1.txt,target=/app/hostnames_mpc1.txt  --mount type=bind,source=$script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc2.txt,target=/app/hostnames_mpc2.txt -v $script_dir/../benchmarks:/app/benchmarks poba 3 0 1 $app_port 14000 127.0.0.1 127.0.0.1:50050 0 $2 $3 $4 &
done

wait
