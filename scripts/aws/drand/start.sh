#!/bin/bash

cd drand || exit 1

LeaderAddr=$1
N=${2:-"4"}
T=$(( "$N"/2 + 1 ))
isLeader=${3:-"no"}

killall drand
rm -rf datadir

IP=$(ip address show | \
    grep "inet .* brd" | \
    sed 's/ brd.*//g' | \
    sed 's/inet //' | \
    sed 's;/.*;;g' | \
    sed 's/.* //g')

./drand generate-keypair --tls-disable --folder datadir "$IP":8080

echo "mysecret901234567890123456789012" > secret-file.log

./drand start --folder datadir \
                --tls-disable \
                --public-listen 0.0.0.0:9090 \
                --verbose &

sleep 2

if [ "$isLeader" == "no" ] ; then
    sleep 75
    echo "Client: Connecting to $LeaderAddr"
    ./drand --folder datadir share \
                                --tls-disable \
                                --connect "$LeaderAddr" \
                                --nodes "$N" \
                                --threshold $T \
                                --secret-file secret-file.log \
                                --timeout "90s" \
                                --period "90s" \
                                --control 0.0.0.0:8888
else 
    echo "Leader: Starting..."
    ./drand --folder datadir share \
                                --tls-disable \
                                --leader \
                                --nodes "$N" \
                                --threshold $T \
                                --secret-file secret-file.log \
                                --timeout "90s" \
                                --period "90s" \
                                --control 0.0.0.0:8888
fi

# sleep 300
# killall drand