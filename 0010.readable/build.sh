#!/bin/bash

function cut_head {
	echo Cut head: "$1"
	awk -f cut_head.awk "$1" > __tmp
	mv __tmp "$1"
}
function cut_vim {
	echo Cut vim: "$1"
	grep -v "/\* vim.*\*/$" "$1" > __tmp
	mv __tmp "$1"
}

find . -type f -name "*.c" -print0 |
while read -d $'\0' f; do
	echo Processing $f
	cut_head "$f"
	cut_vim "$f"
done
