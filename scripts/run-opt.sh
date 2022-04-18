set -e
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

TYPE=${TYPE:-"release"}
TESTDIR=${TESTDIR:-"./testdata/test-local"}

cargo build --package=node-optrand-opt --${TYPE}
echo "Starting protocol nodes"

DELTA=${DELTA:-"50"}

./target/$TYPE/node-optrand-opt -c $TESTDIR/nodes-0.dat -d ${DELTA} -i ./scripts/ip_file $1 &> 0.log&
./target/$TYPE/node-optrand-opt -c $TESTDIR/nodes-1.dat -d ${DELTA} -i ./scripts/ip_file $1 &> 1.log&
./target/$TYPE/node-optrand-opt -c $TESTDIR/nodes-2.dat -d ${DELTA} -i ./scripts/ip_file $1 &> 2.log&
./target/$TYPE/node-optrand-opt -c $TESTDIR/nodes-3.dat -d ${DELTA} -i ./scripts/ip_file $1 &> 3.log&

wait