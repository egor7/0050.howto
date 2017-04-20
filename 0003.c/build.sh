#!/bin/bash

# tcc c9.c -run main.c | tee build.lst
tcc -run srv.c > srv.lst 2>&1 & \
tcc -run clt.c > clt.lst
