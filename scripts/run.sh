set -e
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

TYPE=${TYPE:-"release"}
TESTDIR=${TESTDIR:-"./testdata/test-local"}

cargo build --package=node-optrand --release
./target/$TYPE/node-optrand -c $TESTDIR/nodes-0.dat -d 500 -i ./scripts/ip_file $1 &> 0.log&
./target/$TYPE/node-optrand -c $TESTDIR/nodes-1.dat -d 500 -i ./scripts/ip_file $1 &> 1.log&
./target/$TYPE/node-optrand -c $TESTDIR/nodes-2.dat -d 500 -i ./scripts/ip_file $1 &> 2.log&
./target/$TYPE/node-optrand -c $TESTDIR/nodes-3.dat -d 500 -i ./scripts/ip_file $1 &> 3.log&

wait