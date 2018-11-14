#!/bin/bash

echo -n > build.lst
tcc -run main.c
cat build.lst
