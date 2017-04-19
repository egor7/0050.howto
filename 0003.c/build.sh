#!/bin/bash

tcc -run main.c | tee build.lst
#python build.py 2>&1 | grep -v -e "PyX" -e "IPv6" | tee build.lst
