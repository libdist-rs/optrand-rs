sudo pacman -Syu --noconfirm
# sudo apt-get update

sudo pacman -S git --noconfirm
# sudo apt-get install git build-utils

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > install-rust.sh

bash install-rust.sh -y
source $HOME/.cargo/env

git clone https://github.com/adithyabhatkajake/optrand-rs.git
cd optrand-rs

git pull
make all
