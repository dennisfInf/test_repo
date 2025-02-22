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
cp $script_dir/../mp-spdz-files/HostFiles/local/* $script_dir/../build
cp -r $script_dir/Player-Data $script_dir/../lib/MP-SPDZ/
cp -r $script_dir/Player-Data $script_dir/../build/
cd $script_dir/../lib/MP-SPDZ/

./Scripts/shamir.sh oram_2-$n-$5-$6-1 --ip-file-name $script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc2.txt -N $n -B 5 --batch-size 100 &

sleep 2
./Scripts/shamir.sh add_shares_vec-mal-$n-$t-1-$7 --ip-file-name $script_dir/../mp-spdz-files/HostFiles/local/hostnames_mpc1.txt -N $n -B 5 --batch-size 100 & 


app_port=50050


$script_dir/../build/ippa $n 1 $t $app_port 14000 127.0.0.1 127.0.0.1:50050 0 &

for id in {1..$(($n- 1))};do
    app_port=$((50050+ $id))
    $script_dir/../build/ippa $n 0 $t $app_port 14000 127.0.0.1 127.0.0.1:50050 0 &
done

wait
