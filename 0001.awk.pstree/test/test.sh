#/bin/bash

#awk -f ../build.awk test.data PID PGID CMD > test.lst
cat test.data | awk -f ../build.awk - PID PGID CMD > test.lst
#cat test.data.orig | awk -f ../build.awk - PID PGID CMD > test.lst

if cmp test.lst etalon/test.lst &> /dev/null
then echo Test passed
else tmux neww -n "emacs-diff" 'emacs -diff test.lst etalon/test.lst'
fi
