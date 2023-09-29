#!/bin/bash

sudo apt install pkg-config libcapstone-dev cmake

git submodule update --init --recursive

cd syscall_intercept
mkdir build
mkdir install
cd build
cmake -DCMAKE_INSTALL_PREFIX=../install -DCMAKE_BUILD_TYPE=Release ..
make
make install

cd ../../
