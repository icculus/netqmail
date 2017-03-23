# I should be called by qmail-smtpd or anything that calls qmail-queue
#
if [ -f /bin/mktemp ] ; then
	MKTEMP=/bin/mktemp
elif [ -f /usr/bin/mktemp ] ; then
	MKTEMP=/usr/bin/mktemp
else
	MKTEMP=mktemp
fi
out=`$MKTEMP -t surblXXXXXXXXXX`
if [ $? -ne 0 ] ; then
	echo "mktemp: unable to create temp files" 1>&2
	exit 111
fi
#
# Redirect standard error to 4 so that qmail_open() will pick up the error
#
QMAIL/bin/surblfilter > $out 2>&4
status=$?
if [ $status -eq 0 ] ; then
	exec 0<$out
	/bin/rm -f $out
	# use SURBLQUEUE to execute queue program (thanks Roberto Puzzanghera)
	if [ "$SURBLQUEUE" != "" -a -x "$SURBLQUEUE" ]; then
		exec $SURBLQUEUE
	else
		exec QMAIL/bin/qmail-queue
	fi
else
	/bin/rm -f $out
	exit $status
fi
