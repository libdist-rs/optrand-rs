killall -9 node-optrand
timeout 600 ./optrand-rs/target/release/node-optrand -c ./optrand-rs/testdata/n33-f16/nodes-$1.dat -d 5000 -i ./optrand-rs/ips_file > output.log
