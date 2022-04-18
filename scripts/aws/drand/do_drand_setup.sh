#!/bin/bash
# Do the setup on the AWS Server

FILE="${1:-/dev/stdin}"
IPS=()

while IFS= read -r line; do
  IPS+=("$line")
done < "$FILE"

for ip in "${IPS[@]}"
do
    ssh -oStrictHostKeyChecking=accept-new \
        -t arch@"$ip" 'bash -ls' < scripts/aws/drand/drand_setup.sh &
done

wait