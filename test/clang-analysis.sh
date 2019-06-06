#!/bin/sh
# clang analysis test script

if test ! -x "`which clang 2>&1`"; then
        echo "No clang in path"
        exit 0
fi

PRE="."
# test if assertions are enabled
if grep "^#define DO_DEBUG" $PRE/config.h >/dev/null; then
        :
else
        echo "DO_DEBUG (--enable-debug) is not enabled, skip test"
        # no debug means no assertions, and clang analyzer uses
        # the assertions to make inferences.
        exit 0
fi

# read value from Makefile
# $1: result variable name
# $2: string on Makefile
# $3: Makefile location
read_value () {
        x=`grep "$2" $3 | sed -e "s/$2//"`
        eval $1="'""$x""'"
        # print what we just read
        #echo $1"="'"'"`eval echo '$'$1`"'"'
}

# read some values from the Makefile
read_value srcdir '^srcdir=' $PRE/Makefile
read_value gui '^gui=' $PRE/Makefile
read_value CPPFLAGS '^CPPFLAGS=' $PRE/Makefile
read_value LIBOBJS '^LIBOBJS= *' $PRE/Makefile
read_value GTK_CFLAGS '^GTK_CFLAGS= *' $PRE/Makefile

# turn libobjs into C files
compatfiles=`echo "$LIBOBJS" | sed -e 's?..LIBOBJDIR.?compat/?g' -e 's/.U.o/.c/g'`

odir=`pwd`
cd $srcdir
# check the files in the srcdir
fail="no"
for x in riggerd/*.c panel/attach.c $compatfiles test/*.c; do
	echo clang --analyze $CPPFLAGS $x
	plist=`basename $x .c`.plist
	rm -rf $plist
	(cd "$odir"; clang --analyze $CPPFLAGS $srcdir/$x 2>&1 ) | tee tmp.$$
	if grep -e warning -e error tmp.$$ >/dev/null; then
		fail="yes"
		fails="$fails $x"
	fi
	rm -rf $plist tmp.$$
done

if test "$gui" = "gtk"; then
	x="panel/panel.c"
	echo clang --analyze $CPPFLAGS $GTK_CFLAGS $x
	plist=`basename $x .c`.plist
	rm -rf $plist
	(cd "$odir"; clang --analyze $CPPFLAGS $GTK_CFLAGS $srcdir/$x 2>&1 ) | tee tmp.$$
	if grep -e warning -e error tmp.$$ >/dev/null; then
		fail="yes"
		fails="$fails $x"
	fi
	rm -rf $plist tmp.$$
fi

echo
if test "$fail" = "yes"; then
        echo "Failures"
        echo "create reports in file.plist dir with     clang --analyze --analyzer-output html $CPPFLAGS""$fails"
        exit 1
fi
echo "OK"
exit 0
