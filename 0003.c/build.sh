#!/bin/bash

# tcc c9.c -run main.c | tee build.lst
#tcc -run srv.c
tcc -run clt.c
