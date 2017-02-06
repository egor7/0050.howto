# EUSER      PID  PPID  PGID   SID TT       STAT CMD
# root         1     0     1     1 ?        Ss   /sbin/init splash
# root         2     0     0     0 ?        S    [kthreadd]
# root         3     2     0     0 ?        S    [ksoftirqd/0]

BEGIN {
	if (ARGC != 5) {
		print "Please specify CHILD, PARENT and DATA columns"
		exit
	}

	chld = toupper(ARGV[2]); ARGV[2] = "";
	prnt = toupper(ARGV[3]); ARGV[3] = "";
	data = toupper(ARGV[4]); ARGV[4] = "";

	head = 1
	nchld = 0
	nprnt = 0
	ndata = 0
}

{
	if (head == 1) {
		for (i = 0; i <= NF; i++) {
			if (toupper($i) == chld) nchld = i
			if (toupper($i) == prnt) nprnt = i
			if (toupper($i) == data) ndata = i
		}
		if (nchld == 0 || nprnt == 0 || ndata == 0) {
			print "CHILD, PARENT and DATA are nessesary, use the example: ps -eo pid,pgid,cmd"
			exit
		}
		head = 0
		next
	}

	noden[++nn] = $nchld
	node[$nchld, "prnt"] = $nprnt
	for (i = ndata; i <= NF; i++)
		node[$nchld, "data"] = node[$nchld, "data"] " " $i
	node[$nprnt, "chld", ++node[$nprnt, "nchld"]] = $nchld
}

END {
	# reconstruct parent nodes
	for (n in node) {
		split(n, na, SUBSEP)
		nodel[na[1]] = 1
	}

	# print tops
	for (i in nodel)
		if (node[i, "prnt"] == "" || node[i, "prnt"] == i) printt(i)

}

function printt(n,d,   i) {
	# infinit loop protection
	if (inf++ > 1000) exit

	print ((d=="")?(""):(d "\\_ ")) n " " node[n, "data"]
	for (i = 1; i <= node[n, "nchld"]; i++)
		if (n != node[n, "chld", i])
			printt(node[n, "chld", i], d "  ")
}
function printn(n,   i,s) {
	for (i = 1; i <= node[n, "nchld"]; i++) s = s " " node[n, "chld", i]
	print "id: " n,								\
		"prnt: " node[n, "prnt"],				\
		"data: " node[n, "data"],				\
		"n-chs: " node[n, "nchld"],			\
		"chs:" s
}
