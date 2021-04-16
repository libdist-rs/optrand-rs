killall -9 node-optrand
timeout 600 ./optrand-rs/target/release/node-optrand -c ./optrand-rs/testdata/n3-f1/nodes-$1.dat -d 5000 -i ./optrand-rs/ips_file > output.log
