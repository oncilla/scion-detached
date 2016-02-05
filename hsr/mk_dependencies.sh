#!/bin/sh

cd ../lib/libscion
make
cd ../../hsr/lib
./mk_lnx_lib.sh
make
cd ../cJSON
make
cd ..
make

