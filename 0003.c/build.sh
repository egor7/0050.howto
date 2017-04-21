#!/bin/bash

echo -n > build.lst

#tcc c9.c -run main.c | tee build.lst
#tcc c9.c -run main.c

echo -n > srv.lst
echo -n > clt.lst
echo -n > c9.lst

tcc c9.c -run srv.c &
sleep 1
tcc c9.c -run clt.c
wait
cat srv.lst >> build.lst
cat clt.lst >> build.lst
cat c9.lst >> build.lst

#netstat -pnat | grep 8888
