BEGIN {
	f_incopy = 0
	f_filled = 0
}

/Copyright \(c\)/ {
	f_incopy = 1
	next
}
/\*\// {
	f_incopy = 0
	next
}

!/^[ 	]*$/ { if (f_incopy == 0)
	f_filled = 1
}

{
	if (f_incopy == 0 && f_filled == 1)
		print $0
}
