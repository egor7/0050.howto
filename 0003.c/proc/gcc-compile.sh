#cd ..
gcc -g -o srv c9.c srv.c
gcc -g -o clt c9.c clt.c -lpthread
