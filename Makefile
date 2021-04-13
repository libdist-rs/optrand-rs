.PHONY: all clean configs

all:
	cargo build --all --release

configs:
	cargo build -p genconfig --release
	mkdir -p testdata/n3-d100
	./target/release/genconfig -n 3 -d 100 -P 10000 -f 1 -o json -t testdata/n3-d100