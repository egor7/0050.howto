#/bin/bash
cp ../build.lst test.lst

if cmp test.lst etalon/test.lst &> /dev/null
then echo Test passed
else tmux neww -n "emacs-diff" 'emacs -diff test.lst etalon/test.lst'
fi
