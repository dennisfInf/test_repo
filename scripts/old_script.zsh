#!/bin/zsh
#
# DO NOT USE THIS FILE, just for me to know some used variables
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
else echo "Usage: $0 -n <number of parties> -t <threshold>"
    exit 1
fi
mydir=${0:a:h}
relic_prime_q=149505334124813
relic_prime=5541245505022739011583672869577435255026888277144126952450651294188487038640194767986566260919128250811286032482323
cd $mydir/lib/MP-SPDZ-0.3.7
./compile.py -P $relic_prime add_shares 1
./compile.py -P $relic_prime_q oram 1
Scripts/shamir.sh add_shares-1 -N $n -B 5 --batch-size 100 &
Scripts/shamir.sh oram-1 -N $n -B 5 --batch-size 100 &
port=50050
bootstrap_port=$(($port + $t -1))
for i in {0..$(($t - 2))}
do
    $mydir/build/ippa $n "0" $t $(($port + i)) "14000" "$q" "localhost" "localhost:$bootstrap_port" &
done
$mydir/build/ippa $n "1" $t $bootstrap_port "14000" "$q" "localhost" "" &


wait