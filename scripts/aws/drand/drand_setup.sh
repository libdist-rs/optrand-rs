#!/bin/bash
# Script that must run on AWS

# Update packages
sudo pacman -Syu --noconfirm

# Install go
sudo pacman -S go git --noconfirm

rm -rf drand
if [ ! -d drand ]; then
    git clone https://github.com/drand/drand && \
        cd drand && \
        git checkout fix/log && \
        cd ..
else
    cd drand && \
        git pull origin fix/log && \
        cd ..
fi
cd drand || exit 1
make build

IP=$(ip address show | \
    grep "inet .* brd" | \
    sed 's/ brd.*//g' | \
    sed 's/inet //' | \
    sed 's;/.*;;g' | \
    sed 's/.* //g')

echo "Got IP: $IP"

if [ ! -d datadir ] ; then
    mkdir -p datadir
else
    rm -rf datadir
    mkdir -p datadir
fi

./drand generate-keypair --tls-disable --folder datadir "$IP":8080