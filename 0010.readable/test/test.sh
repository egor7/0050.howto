#!/bin/bash

rm ../*.c
cp test0001.c.orig ../"test 0001.c"
cp test0002.c.orig ../"test0002.c"

cd ..
./build.sh
cd test
