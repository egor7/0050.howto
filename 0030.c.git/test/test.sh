#/bin/bash
rm -rdf ex
mkdir ex
cd ex

init-db > ../test.lst 2>&1
echo 12345678 > aaaa.txt
update-cache aaaa.txt >> ../test.lst 2>&1
g_tree=$(write-tree)
echo $g_tree >> ../test.lst
echo "initial" | commit-tree $g_tree >> ../test.lst 2>&1

cd ..
if cmp test.lst etalon/test.lst &> /dev/null
then echo Test passed
else tmux neww -n "emacs-diff" "emacs -diff test.lst etalon/test.lst"
fi
