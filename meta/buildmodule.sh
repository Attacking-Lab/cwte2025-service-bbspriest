#!/bin/sh

rm -rf build
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && make && cd .. && cp build/cryptoaccelerator.cpython-313-x86_64-linux-musl.so out
