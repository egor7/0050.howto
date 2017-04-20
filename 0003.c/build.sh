#!/bin/bash

echo -n > build.lst

#tcc c9.c -run main.c | tee build.lst
#tcc c9.c -run main.c

echo -n > srv.lst
echo -n > clt.lst
tcc -run srv.c &
sleep 1
tcc -run clt.c
wait
cat srv.lst >> build.lst
cat clt.lst >> build.lst
