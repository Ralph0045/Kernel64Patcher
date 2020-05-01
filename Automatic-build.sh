#!/bin/bash

brew install automake autoconf libtool pkg-config

git clone --recursive https://github.com/tihmstar/libgeneral
cd libgeneral
bash autogen.sh
make
sudo make install
cd ..
rm -rf libgeneral
git clone --recursive https://github.com/Ralph0045/liboffsetfinder64.git
cd liboffsetfinder64
bash autogen.sh
make
sudo make install
cd ..
rm -rf liboffsetfinder64
bash autogen.sh
make
mkdir Build
mv Kernel64Patcher/Kernel64Patcher Build
