#!/bin/bash

#tcc c9.c -run main.c | tee build.lst

echo -n > build.lst
tcc c9.c -run main.c

#tcc -run srv.c &>srv.lst &
#tcc -run clt.c > clt.lst
