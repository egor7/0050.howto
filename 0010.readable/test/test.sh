#!/bin/bash

rm ../*.c
cp test0001.c.orig ../"test 0001.c"

cd ..
./build.sh
cd test
