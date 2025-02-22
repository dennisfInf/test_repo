    #!/bin/zsh
#After building the container
#
#
# Ensure the correct number of arguments are provided
if [[ "$#" -ne 8 ]]; then
    echo "Usage: $0 -n <number of parties> -t <threshold> -l <logbooks per users> -a <log(#oram addr)>"
    exit 1
fi

# Parse the arguments
if [[ "$1" == "-n" && "$3" == "-t" && "$5" == "-l" && "$7" == "-a" ]]; then
    if [[ "$2" =~ ^[0-9]+$ && "$4" =~ ^[0-9]+$ && "$6" =~ ^[0-9]+$ && "$8" =~ ^[0-9]+$ ]]; then
        n="$2"
        t="$4"
        logsize="$6"
        addr="$8"
        echo "Compiling MPC circuits with parameters:"
        echo "n: $n, t: $t, logbooks per user: $logsize, log(#ORAM addr): $addr"
    else
        echo "Error: Arguments for -n, -t, -l, or -a must be numbers."
        exit 1
    fi
else
    echo "Usage: $0 -n <number of parties> -t <threshold> -l <logbooks per users> -a <log(#oram addr)>"
    exit 1
fi
docker run --entrypoint /bin/bash mpspdz -c "./compile.py add_shares_vec $n $t 1 25 && ./compile.py oram_2 $n $logsize $addr 1"