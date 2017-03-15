#!/bin/bash

#python build.py 2>&1 | grep -ve "PyX" -e "IPv6" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" | tee build.lst
python build.py 2>&1 | grep -v -e "PyX" -e "IPv6" | tee build.lst
